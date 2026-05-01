//! Native SCoAP/UDP surface for elastik-core.
//!
//! This is not a general CoAP stack. It is "UDP curl": a deliberately small
//! adapter that parses enough CoAP-shaped wire truth to derive method, path,
//! payload and content type, then calls the same Core storage operations as
//! HTTP. TCP and UDP become two doors into the same world store.
//!
//! In elastik terms, core owns protocol truth, not protocol politics:
//!
//! - Truth we keep here: v1 header, method code, Uri-Path, Content-Format,
//!   payload marker, token echo, response code, CON->ACK / NON->NON.
//! - Politics we intentionally do not keep here: retransmission, dedup cache,
//!   block-wise transfer, DTLS/OSCORE, Observe, .well-known/core, Max-Age,
//!   multicast discovery, congestion knobs, and strict critical-option lawyering.
//!
//! Need reliability or large bodies? Use HTTP or retry at the client. Need
//! crypto/discovery/strict RFC behavior? Put a CoAP runtime gateway at the edge.
//! The core stays a disk-shaped bus: packet in, core op, packet out.

use axum::http::StatusCode;
use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::{auth, canonicalize_path, valid_world_name, Core};

const MAX_DATAGRAM: usize = 1152;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MsgType {
    Con = 0,
    Non = 1,
    Ack = 2,
    Rst = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Post,
    Put,
    Delete,
}

#[derive(Debug)]
struct Packet<'a> {
    typ: MsgType,
    code: u8,
    mid: u16,
    token: &'a [u8],
    path: Vec<String>,
    content_format: Option<u16>,
    payload: &'a [u8],
}

impl Packet<'_> {
    fn method(&self) -> Option<Method> {
        match self.code {
            1 => Some(Method::Get),
            2 => Some(Method::Post),
            3 => Some(Method::Put),
            4 => Some(Method::Delete),
            _ => None,
        }
    }

    fn response_type(&self) -> MsgType {
        match self.typ {
            MsgType::Con => MsgType::Ack,
            MsgType::Non => MsgType::Non,
            _ => MsgType::Non,
        }
    }
}

pub(crate) async fn serve(core: Core, bind: String, mut shutdown: watch::Receiver<bool>) {
    let socket = match UdpSocket::bind(&bind).await {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("scoap: failed to bind coap://{bind}/: {e}");
            return;
        }
    };
    let socket = std::sync::Arc::new(socket);
    eprintln!("scoap: listening on coap://{bind}/");
    eprintln!("scoap: UDP curl surface; CoAP PUT maps to local write tier");
    let mut buf = [0_u8; MAX_DATAGRAM];
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                eprintln!("scoap: shutdown signal received");
                return;
            }
            received = socket.recv_from(&mut buf) => {
                let (n, peer) = match received {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("scoap: recv_from: {e}");
                        continue;
                    }
                };
                let data = Vec::from(&buf[..n]);
                let socket = socket.clone();
                let core = core.clone();
                tokio::spawn(async move {
                    let request = match parse_packet(&data) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("scoap: bad packet from {peer}: {e}");
                            return;
                        }
                    };
                    let response = handle(&core, &request).await;
                    if let Err(e) = socket.send_to(&response, peer).await {
                        eprintln!("scoap: send_to {peer}: {e}");
                    }
                });
            }
        }
    }
}

async fn handle(core: &Core, request: &Packet<'_>) -> Vec<u8> {
    let Some(method) = request.method() else {
        return encode_response(request, 133, None, b"method not allowed\n");
    };
    let path = request_path(request);
    let world_name = canonicalize_path(&path);
    if !valid_world_name(&world_name) {
        return encode_response(request, 128, None, b"bad world name\n");
    }
    match method {
        Method::Get => match core.read_world(&world_name) {
            Some(stage) => encode_response(
                request,
                69,
                media_type_to_cf(&stage.content_type),
                &stage.body,
            ),
            None => encode_response(request, 132, Some(0), b"not found\n"),
        },
        Method::Put => {
            let content_type = cf_to_media_type(request.content_format);
            match core
                .put_bytes(
                    &world_name,
                    request.payload,
                    content_type,
                    &[],
                    auth::Tier::Auth,
                    None,
                )
                .await
            {
                Ok(outcome) => {
                    let code = if outcome.status == StatusCode::CREATED {
                        65
                    } else {
                        68
                    };
                    encode_response(request, code, None, b"")
                }
                Err(resp) => {
                    encode_response(request, status_to_coap(resp.status()), Some(0), b"error\n")
                }
            }
        }
        Method::Post => encode_response(
            request,
            133,
            Some(0),
            b"post not implemented over coap yet\n",
        ),
        Method::Delete => encode_response(
            request,
            133,
            Some(0),
            b"delete not implemented over coap yet\n",
        ),
    }
}

fn request_path(request: &Packet<'_>) -> String {
    let mut path = String::from("/");
    path.push_str(&request.path.join("/"));
    path
}

fn parse_packet(data: &[u8]) -> Result<Packet<'_>, String> {
    if data.len() < 4 {
        return Err("short header".to_owned());
    }
    let ver = data[0] >> 6;
    if ver != 1 {
        return Err(format!("unsupported version {ver}"));
    }
    let typ = match (data[0] >> 4) & 0b11 {
        0 => MsgType::Con,
        1 => MsgType::Non,
        2 => MsgType::Ack,
        _ => MsgType::Rst,
    };
    let tkl = (data[0] & 0x0f) as usize;
    if tkl > 8 {
        return Err("token too long".to_owned());
    }
    if data.len() < 4 + tkl {
        return Err("truncated token".to_owned());
    }
    let code = data[1];
    let mid = u16::from_be_bytes([data[2], data[3]]);
    let token = &data[4..4 + tkl];
    let mut i = 4 + tkl;
    let mut option_number = 0_u16;
    let mut path = Vec::new();
    let mut content_format = None;
    while i < data.len() {
        if data[i] == 0xff {
            i += 1;
            return Ok(Packet {
                typ,
                code,
                mid,
                token,
                path,
                content_format,
                payload: &data[i..],
            });
        }
        let first = data[i];
        i += 1;
        let (delta, used_delta) = read_ext(first >> 4, &data[i..])?;
        i += used_delta;
        let (len, used_len) = read_ext(first & 0x0f, &data[i..])?;
        i += used_len;
        option_number = option_number
            .checked_add(delta)
            .ok_or_else(|| "option number overflow".to_owned())?;
        let len = len as usize;
        if i + len > data.len() {
            return Err("truncated option".to_owned());
        }
        let value = &data[i..i + len];
        i += len;
        match option_number {
            11 => path.push(String::from_utf8_lossy(value).to_string()),
            12 => content_format = Some(parse_uint(value)?),
            _ => {}
        }
    }
    Ok(Packet {
        typ,
        code,
        mid,
        token,
        path,
        content_format,
        payload: b"",
    })
}

fn read_ext(nibble: u8, rest: &[u8]) -> Result<(u16, usize), String> {
    match nibble {
        n @ 0..=12 => Ok((n as u16, 0)),
        13 => rest
            .first()
            .map(|b| ((*b as u16) + 13, 1))
            .ok_or_else(|| "truncated extended option".to_owned()),
        14 => {
            if rest.len() < 2 {
                return Err("truncated extended option".to_owned());
            }
            Ok((u16::from_be_bytes([rest[0], rest[1]]) + 269, 2))
        }
        _ => Err("reserved option nibble".to_owned()),
    }
}

fn parse_uint(value: &[u8]) -> Result<u16, String> {
    if value.len() > 2 {
        return Err("uint option too large".to_owned());
    }
    Ok(value.iter().fold(0_u16, |n, b| (n << 8) | (*b as u16)))
}

fn encode_response(
    request: &Packet<'_>,
    code: u8,
    content_format: Option<u16>,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + request.token.len() + 8 + payload.len());
    out.push((1 << 6) | ((request.response_type() as u8) << 4) | (request.token.len() as u8));
    out.push(code);
    out.extend_from_slice(&request.mid.to_be_bytes());
    out.extend_from_slice(request.token);
    let mut prev = 0_u16;
    if let Some(cf) = content_format {
        write_option(&mut out, &mut prev, 12, &uint_bytes(cf));
    }
    if !payload.is_empty() {
        out.push(0xff);
        out.extend_from_slice(payload);
    }
    out
}

fn write_option(out: &mut Vec<u8>, prev: &mut u16, number: u16, value: &[u8]) {
    let delta = number - *prev;
    let (delta_nibble, mut delta_ext) = option_ext(delta);
    let (len_nibble, mut len_ext) = option_ext(value.len() as u16);
    out.push((delta_nibble << 4) | len_nibble);
    out.append(&mut delta_ext);
    out.append(&mut len_ext);
    out.extend_from_slice(value);
    *prev = number;
}

fn option_ext(value: u16) -> (u8, Vec<u8>) {
    match value {
        0..=12 => (value as u8, Vec::new()),
        13..=268 => (13, vec![(value - 13) as u8]),
        _ => {
            let n = value - 269;
            (14, n.to_be_bytes().to_vec())
        }
    }
}

fn uint_bytes(value: u16) -> Vec<u8> {
    if value == 0 {
        Vec::new()
    } else if value <= 0xff {
        vec![value as u8]
    } else {
        value.to_be_bytes().to_vec()
    }
}

fn cf_to_media_type(cf: Option<u16>) -> &'static str {
    match cf {
        Some(0) | None => "text/plain; charset=utf-8",
        Some(42) => "application/octet-stream",
        Some(50) => "application/json",
        Some(60) => "application/cbor",
        _ => "application/octet-stream",
    }
}

fn media_type_to_cf(value: &str) -> Option<u16> {
    match value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "text/plain" => Some(0),
        "application/octet-stream" => Some(42),
        "application/json" => Some(50),
        "application/cbor" => Some(60),
        _ => None,
    }
}

fn status_to_coap(status: StatusCode) -> u8 {
    match status.as_u16() {
        400 => 128,
        401 => 129,
        403 => 131,
        404 => 132,
        405 => 133,
        409 => 137,
        412 => 140,
        413 => 141,
        415 => 143,
        500..=599 => 160,
        _ => 128,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth, store, Core, DEFAULT_MAX_MEMORY_BYTES, DEFAULT_MAX_WORLD_BYTES, LISTEN_REPLAY_MAX,
    };
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::{atomic::AtomicU64, Arc, Mutex as StdMutex};
    use tokio::sync::{broadcast, watch, Mutex};

    fn packet(bytes: &[u8]) -> Packet<'_> {
        parse_packet(bytes).unwrap()
    }

    fn test_core(label: &str) -> (Core, PathBuf) {
        let mut dir = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!(
            "elastik-coap-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (events, _) = broadcast::channel(16);
        (
            Core {
                data: dir.clone(),
                tokens: auth::Tokens {
                    read: None,
                    auth: None,
                    approve: None,
                },
                hmac_key: b"test-key".to_vec(),
                mem: Arc::new(store::MemoryStore::new()),
                max_world_bytes: DEFAULT_MAX_WORLD_BYTES,
                max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
                events,
                event_log: Arc::new(StdMutex::new(VecDeque::with_capacity(LISTEN_REPLAY_MAX))),
                shutdown: watch::channel(false).1,
                next_event: Arc::new(AtomicU64::new(0)),
                write_lock: Arc::new(Mutex::new(())),
            },
            dir,
        )
    }

    #[test]
    fn parses_get_path() {
        // Ver=1, CON, TKL=1, GET, mid=0x1234, token=0xaa,
        // Uri-Path "home", Uri-Path "x".
        let p = packet(&[
            0x41, 0x01, 0x12, 0x34, 0xaa, 0xb4, b'h', b'o', b'm', b'e', 0x01, b'x',
        ]);
        assert_eq!(p.method(), Some(Method::Get));
        assert_eq!(p.mid, 0x1234);
        assert_eq!(p.token, &[0xaa]);
        assert_eq!(p.path, vec!["home", "x"]);
        assert_eq!(request_path(&p), "/home/x");
    }

    #[test]
    fn encodes_ack_content_response() {
        let p = packet(&[0x41, 0x01, 0x12, 0x34, 0xaa]);
        let out = encode_response(&p, 69, Some(0), b"ok");
        assert_eq!(&out[..5], &[0x61, 69, 0x12, 0x34, 0xaa]);
        assert_eq!(out[5], 0xc0); // delta 12, len 0 -> Content-Format: text/plain
        assert_eq!(out[6], 0xff);
        assert_eq!(&out[7..], b"ok");
    }

    #[tokio::test]
    async fn coap_put_and_get_share_the_core_world_store() {
        let (core, dir) = test_core("dual-transport");
        let put = packet(&[
            0x41, 0x03, 0x12, 0x34, 0xaa, // CON PUT, mid, token
            0xb4, b'h', b'o', b'm', b'e', // Uri-Path: home
            0x06, b's', b'e', b'n', b's', b'o', b'r', // Uri-Path: sensor
            0x07, b'k', b'i', b't', b'c', b'h', b'e', b'n', // Uri-Path: kitchen
            0x04, b't', b'e', b'm', b'p', // Uri-Path: temp
            0x10, // Content-Format: text/plain
            0xff, b'2', b'3', b'.', b'5',
        ]);
        let put_response = handle(&core, &put).await;
        assert_eq!(put_response[1], 65); // 2.01 Created

        let stage = core.read_world("home/sensor/kitchen/temp").unwrap();
        assert_eq!(stage.body, b"23.5");
        assert_eq!(stage.content_type, "text/plain; charset=utf-8");

        let get = packet(&[
            0x41, 0x01, 0x12, 0x35, 0xbb, // CON GET, mid, token
            0xb4, b'h', b'o', b'm', b'e', 0x06, b's', b'e', b'n', b's', b'o', b'r', 0x07, b'k',
            b'i', b't', b'c', b'h', b'e', b'n', 0x04, b't', b'e', b'm', b'p',
        ]);
        let get_response = handle(&core, &get).await;
        assert_eq!(get_response[1], 69); // 2.05 Content
        assert_eq!(get_response[6], 0xff);
        assert_eq!(&get_response[7..], b"23.5");

        let _ = std::fs::remove_dir_all(dir);
    }
}
