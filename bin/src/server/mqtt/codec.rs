use std::fmt;

use bytes::BytesMut;
use rumqttd::protocol::{self, v4::V4, Packet, Protocol};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::tcp::OwnedWriteHalf,
    sync::mpsc,
    time::{timeout, Duration},
};

const READ_CHUNK: usize = 4096;
const MAX_IDLE_READ_BUFFER: usize = READ_CHUNK * 4;

pub(super) async fn send_packet(
    outbound: &mpsc::Sender<Packet>,
    packet: Packet,
) -> Result<(), String> {
    outbound
        .send(packet)
        .await
        .map_err(|_| "mqtt writer closed".to_owned())
}

pub(super) async fn write_loop(mut writer: OwnedWriteHalf, mut rx: mpsc::Receiver<Packet>) {
    let protocol = V4;
    while let Some(packet) = rx.recv().await {
        let mut bytes = BytesMut::new();
        if protocol.write(packet, &mut bytes).is_err() {
            break;
        }
        if writer.write_all(&bytes).await.is_err() {
            break;
        }
    }
}

pub(super) struct PacketReader<R> {
    reader: R,
    protocol: V4,
    buffer: BytesMut,
    max_packet_bytes: usize,
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    pub(super) fn new(reader: R, max_packet_bytes: usize) -> Self {
        Self {
            reader,
            protocol: V4,
            buffer: BytesMut::with_capacity(READ_CHUNK),
            max_packet_bytes,
        }
    }

    pub(super) async fn read_packet(&mut self) -> Result<Packet, PacketReadError> {
        loop {
            match self
                .protocol
                .read_mut(&mut self.buffer, self.max_packet_bytes)
            {
                Ok(packet) => {
                    if self.buffer.is_empty() && self.buffer.capacity() > MAX_IDLE_READ_BUFFER {
                        self.buffer = BytesMut::with_capacity(READ_CHUNK);
                    }
                    return Ok(packet);
                }
                Err(protocol::Error::InsufficientBytes(_)) => {
                    let read = self.reader.read_buf(&mut self.buffer).await?;
                    if read == 0 {
                        return Err(PacketReadError::Closed);
                    }
                }
                Err(err) => return Err(PacketReadError::Protocol(err)),
            }
        }
    }

    pub(super) async fn read_packet_with_timeout(
        &mut self,
        timeout_after: Option<Duration>,
    ) -> Result<Packet, PacketReadError> {
        match timeout_after {
            Some(timeout_after) => timeout(timeout_after, self.read_packet())
                .await
                .map_err(|_| PacketReadError::KeepAliveTimeout)?,
            None => self.read_packet().await,
        }
    }
}

#[derive(Debug)]
pub(super) enum PacketReadError {
    Closed,
    KeepAliveTimeout,
    Io(std::io::Error),
    Protocol(protocol::Error),
}

impl fmt::Display for PacketReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("connection closed"),
            Self::KeepAliveTimeout => f.write_str("MQTT keep-alive timeout"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Protocol(err) => write!(f, "protocol error: {err}"),
        }
    }
}

impl From<std::io::Error> for PacketReadError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
