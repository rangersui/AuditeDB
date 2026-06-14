//! Native SCoAP/UDP surface for elastik-core.
//!
//! This is not a general CoAP stack. It is "UDP curl": parse method, path,
//! payload, content type, and auth token, then call the protocol-neutral Engine
//! facade. CoAP stays in the server adapter layer because its wire shape has
//! near-zero semantic distance from HTTP; richer protocol politics belong in
//! edge adapters. This adapter currently implements GET and PUT; POST and
//! DELETE deliberately return 4.05 Method Not Allowed stubs.

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

use crate::{
    engine::{Engine, ShutdownToken},
    engine_trace::EngineWriteTraceHooks,
    engine_types::{AccessTier, Preconditions, Representation, ValidatedWorldPath, WriteKind},
    server::{coap_errors, path::canonicalize_path},
};

const MAX_DATAGRAM: usize = 1152;
const RECV_BUF: usize = MAX_DATAGRAM + 1;
/// Experimental critical CoAP option carrying the raw elastik token bytes.
///
/// This is not encryption and not a CoAPS replacement. It is the UDP equivalent
/// of the HTTP bearer-token auth header for the playground adapter: absent means Anon,
/// matching a configured token yields Read/Write/Approve. Use CoAPS/DTLS-PSK at
/// the edge if the token should not be visible on the wire.
const ELASTIK_AUTH_OPTION: u16 = 65001;

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
    auth_token: Option<&'a [u8]>,
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

#[cfg_attr(test, allow(dead_code))]
pub(crate) async fn serve(
    engine: Engine,
    bind: String,
    mut shutdown: ShutdownToken,
    max_in_flight: usize,
) {
    let socket = match UdpSocket::bind(&bind).await {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("scoap: failed to bind coap://{bind}/: {e}");
            return;
        }
    };
    let socket = std::sync::Arc::new(socket);
    let permits = std::sync::Arc::new(Semaphore::new(max_in_flight));
    eprintln!("scoap: listening on coap://{bind}/");
    eprintln!("scoap: UDP curl surface; auth option {ELASTIK_AUTH_OPTION} maps to token tier");
    let mut buf = [0_u8; RECV_BUF];
    loop {
        tokio::select! {
            _ = shutdown.wait() => {
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
                if n > MAX_DATAGRAM {
                    eprintln!("scoap: oversized datagram from {peer}: {n} bytes");
                    let reset = [0x70, 0x00, buf[2], buf[3]];
                    if let Err(e) = socket.send_to(&reset, peer).await {
                        eprintln!("scoap: send_to {peer}: {e}");
                    }
                    continue;
                }
                let data = Vec::from(&buf[..n]);
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        eprintln!("scoap: rejecting datagram from {peer}: in-flight limit reached");
                        if let Ok(request) = parse_packet(&data) {
                            let response = encode_response(
                                &request,
                                163,
                                Some(0),
                                b"too many coap requests\n",
                            );
                            if let Err(e) = socket.send_to(&response, peer).await {
                                eprintln!("scoap: send_to {peer}: {e}");
                            }
                        }
                        continue;
                    }
                };
                let socket = socket.clone();
                let engine = engine.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let request = match parse_packet(&data) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("scoap: bad packet from {peer}: {e}");
                            return;
                        }
                    };
                    let response = handle(&engine, &request).await;
                    if let Err(e) = socket.send_to(&response, peer).await {
                        eprintln!("scoap: send_to {peer}: {e}");
                    }
                });
            }
        }
    }
}

async fn handle(engine: &Engine, request: &Packet<'_>) -> Vec<u8> {
    let Some(method) = request.method() else {
        return encode_response(request, 133, Some(0), b"method not allowed\n");
    };
    let path = request_path(request);
    let world_name = canonicalize_path(&path);
    let Ok(world_name) = ValidatedWorldPath::new(world_name) else {
        return encode_response(request, 128, Some(0), b"bad world name\n");
    };
    let tier = request
        .auth_token
        .map(|token| engine.verify_token(token))
        .unwrap_or(AccessTier::Anon);
    match method {
        Method::Get => match engine.read(&world_name, tier) {
            Ok(Some(result)) => {
                let stage = result.representation;
                if encoded_len(
                    request,
                    media_type_to_cf(&stage.content_type),
                    stage.body.len(),
                ) > MAX_DATAGRAM
                {
                    return encode_response(request, 141, Some(0), b"world too large for coap\n");
                }
                encode_response(
                    request,
                    69,
                    media_type_to_cf(&stage.content_type),
                    &stage.body,
                )
            }
            Ok(None) => encode_response(request, 132, Some(0), b"not found\n"),
            Err(err) => encode_response(
                request,
                coap_errors::read_error_to_coap(&err),
                Some(0),
                coap_errors::read_error_body(&err),
            ),
        },
        Method::Put => {
            let content_type = cf_to_media_type(request.content_format);
            let representation = Representation::new(
                Bytes::copy_from_slice(request.payload),
                content_type,
                Vec::new(),
            );
            match engine
                .replace_traced(
                    &world_name,
                    representation,
                    Preconditions::none(),
                    tier,
                    &CoapNoopWriteTrace,
                )
                .await
            {
                Ok(outcome) => {
                    let code = match outcome.kind {
                        WriteKind::Created => 65,
                        WriteKind::Updated => 68,
                        _ => 68,
                    };
                    encode_response(request, code, None, b"")
                }
                Err(err) => encode_response(
                    request,
                    coap_errors::write_error_to_coap(&err),
                    Some(0),
                    b"error\n",
                ),
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

struct CoapNoopWriteTrace;

impl EngineWriteTraceHooks for CoapNoopWriteTrace {}

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
    let mut auth_token = None;
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
                auth_token,
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
            11 => {
                let segment = std::str::from_utf8(value)
                    .map_err(|_| "invalid utf-8 in Uri-Path option".to_owned())?;
                path.push(segment.to_owned());
            }
            12 => content_format = Some(parse_uint(value)?),
            ELASTIK_AUTH_OPTION => auth_token = Some(value),
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
        auth_token,
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
            let value = u16::from_be_bytes([rest[0], rest[1]]);
            value
                .checked_add(269)
                .map(|v| (v, 2))
                .ok_or_else(|| "extended option overflow".to_owned())
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

fn encoded_len(request: &Packet<'_>, content_format: Option<u16>, payload_len: usize) -> usize {
    let mut len = 4 + request.token.len();
    if let Some(cf) = content_format {
        len += option_len(12, &uint_bytes(cf));
    }
    if payload_len > 0 {
        len += 1 + payload_len;
    }
    len
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

fn option_len(delta: u16, value: &[u8]) -> usize {
    1 + option_ext_len(delta) + option_ext_len(value.len() as u16) + value.len()
}

fn option_ext_len(value: u16) -> usize {
    match value {
        0..=12 => 0,
        13..=268 => 1,
        _ => 2,
    }
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
        Some(0) => "text/plain; charset=utf-8",
        Some(42) => "application/octet-stream",
        Some(50) => "application/octet-stream",
        Some(60) => "application/octet-stream",
        None => "application/octet-stream",
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
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{
        handler,
        test_support::{
            server_state_for_engine_for_tests, test_engine_for_server_with_auth_tokens,
            world_db_path_for_server_tests, write_text_world_for_tests,
        },
        Phase, TraceCtx,
    };
    use axum::body::Bytes;
    use axum::http::{HeaderMap, StatusCode};

    fn packet(bytes: &[u8]) -> Packet<'_> {
        parse_packet(bytes).unwrap()
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
    async fn textual_errors_carry_text_plain_content_format() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("error-format");
        let p = packet(&[0x41, 0x63, 0x12, 0x34, 0xaa]); // unknown method code
        let out = handle(&engine, &p).await;
        assert_eq!(out[1], 133);
        assert_eq!(out[5], 0xc0); // Content-Format: text/plain
        assert_eq!(out[6], 0xff);
        assert_eq!(&out[7..], b"method not allowed\n");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn receive_buffer_can_detect_one_byte_oversize_datagrams() {
        assert_eq!(RECV_BUF, MAX_DATAGRAM + 1);
    }

    #[test]
    fn in_flight_limit_response_is_explicit_service_unavailable() {
        let p = packet(&[0x41, 0x01, 0x12, 0x34, 0xaa]);
        let out = encode_response(&p, 163, Some(0), b"too many coap requests\n");
        assert_eq!(&out[..5], &[0x61, 163, 0x12, 0x34, 0xaa]);
        assert_eq!(out[5], 0xc0); // Content-Format: text/plain
        assert_eq!(out[6], 0xff);
        assert_eq!(&out[7..], b"too many coap requests\n");
    }

    #[test]
    fn write_quota_maps_to_coap_insufficient_storage() {
        assert_eq!(
            coap_errors::write_error_to_coap(&crate::engine::EngineError::QuotaExceeded {
                used: 9,
                quota: 10,
                projected: 11,
            }),
            167
        );
    }

    #[test]
    fn write_payload_too_large_maps_to_coap_request_entity_too_large() {
        assert_eq!(
            coap_errors::write_error_to_coap(&crate::engine::EngineError::PayloadTooLarge {
                max: 1024
            }),
            141
        );
    }

    #[test]
    fn extended_option_overflow_is_rejected() {
        let err = read_ext(14, &[0xff, 0xff]).unwrap_err();
        assert_eq!(err, "extended option overflow");
    }

    #[test]
    fn missing_content_format_defaults_to_octet_stream() {
        assert_eq!(cf_to_media_type(None), "application/octet-stream");
        assert_eq!(cf_to_media_type(Some(0)), "text/plain; charset=utf-8");
    }

    #[test]
    fn structured_content_formats_collapse_to_bytes() {
        assert_eq!(cf_to_media_type(Some(50)), "application/octet-stream");
        assert_eq!(cf_to_media_type(Some(60)), "application/octet-stream");
        assert_eq!(media_type_to_cf(concat!("application/", "json")), None);
        assert_eq!(media_type_to_cf(concat!("application/", "cbor")), None);
    }

    #[test]
    fn invalid_utf8_uri_path_is_rejected() {
        let err = parse_packet(&[0x40, 0x01, 0x12, 0x34, 0xb1, 0xff]).unwrap_err();
        assert_eq!(err, "invalid utf-8 in Uri-Path option");
    }

    fn coap_put_packet(path: &[&[u8]], payload: &[u8], token: Option<&[u8]>) -> Vec<u8> {
        let mut out = vec![0x41, 0x03, 0x12, 0x34, 0xaa];
        let mut prev = 0_u16;
        for segment in path {
            write_option(&mut out, &mut prev, 11, segment);
        }
        write_option(&mut out, &mut prev, 12, &[]);
        if let Some(token) = token {
            write_option(&mut out, &mut prev, ELASTIK_AUTH_OPTION, token);
        }
        out.push(0xff);
        out.extend_from_slice(payload);
        out
    }

    fn coap_get_packet(path: &[&[u8]], token: Option<&[u8]>) -> Vec<u8> {
        let mut out = vec![0x41, 0x01, 0x12, 0x35, 0xbb];
        let mut prev = 0_u16;
        for segment in path {
            write_option(&mut out, &mut prev, 11, segment);
        }
        if let Some(token) = token {
            write_option(&mut out, &mut prev, ELASTIK_AUTH_OPTION, token);
        }
        out
    }

    #[tokio::test]
    async fn coap_put_without_auth_token_is_rejected() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("auth-reject");
        let put_bytes = coap_put_packet(&[b"home", b"sensor", b"kitchen", b"temp"], b"23.5", None);
        let put = packet(&put_bytes);

        let response = handle(&engine, &put).await;

        assert_eq!(response[1], 129); // 4.01 Unauthorized
        let world = ValidatedWorldPath::new("home/sensor/kitchen/temp").unwrap();
        assert!(engine.read(&world, AccessTier::Read).unwrap().is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn coap_get_honors_read_token_when_enabled() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("read-auth");
        write_text_world_for_tests(&engine, "home/secret", "ok").await;

        let denied = handle(
            &engine,
            &packet(&coap_get_packet(&[b"home", b"secret"], None)),
        )
        .await;
        assert_eq!(denied[1], 129); // 4.01 Unauthorized

        let allowed = handle(
            &engine,
            &packet(&coap_get_packet(&[b"home", b"secret"], Some(b"reader"))),
        )
        .await;
        assert_eq!(allowed[1], 69); // 2.05 Content
        assert_eq!(&allowed[7..], b"ok");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn coap_get_rejects_worlds_too_large_for_one_datagram() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("large-get");
        let world = ValidatedWorldPath::new("home/large").unwrap();
        engine
            .replace(
                &world,
                Representation::new(
                    Bytes::from(vec![b'x'; MAX_DATAGRAM]),
                    "application/octet-stream",
                    Vec::new(),
                ),
                Preconditions::none(),
                AccessTier::Write,
            )
            .await
            .unwrap();

        let get_bytes = coap_get_packet(&[b"home", b"large"], Some(b"reader"));
        let response = handle(&engine, &packet(&get_bytes)).await;

        assert_eq!(response[1], 141); // 4.13 Request Entity Too Large
        assert_eq!(response[5], 0xc0); // Content-Format: text/plain
        assert_eq!(response[6], 0xff);
        assert_eq!(&response[7..], b"world too large for coap\n");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn coap_get_storage_busy_maps_to_service_unavailable() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("busy-get");
        write_text_world_for_tests(&engine, "home/busy", "ok").await;
        let db = world_db_path_for_server_tests(&dir, "home/busy");
        let holder = rusqlite::Connection::open(db).unwrap();
        holder
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .unwrap();
        holder.execute_batch("BEGIN EXCLUSIVE").unwrap();

        let response = handle(
            &engine,
            &packet(&coap_get_packet(&[b"home", b"busy"], Some(b"reader"))),
        )
        .await;

        assert_eq!(response[1], 163); // 5.03 Service Unavailable
        assert_eq!(response[5], 0xc0); // Content-Format: text/plain
        assert_eq!(response[6], 0xff);
        assert_eq!(&response[7..], b"storage busy\n");

        drop(holder);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn coap_put_and_get_share_the_core_world_store() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("dual-transport");
        let put_bytes = coap_put_packet(
            &[b"home", b"sensor", b"kitchen", b"temp"],
            b"23.5",
            Some(b"writer"),
        );
        let put = packet(&put_bytes);
        let put_response = handle(&engine, &put).await;
        assert_eq!(put_response[1], 65); // 2.01 Created

        let world = ValidatedWorldPath::new("home/sensor/kitchen/temp").unwrap();
        let stage = engine
            .read(&world, AccessTier::Read)
            .unwrap()
            .unwrap()
            .representation;
        assert_eq!(stage.body, Bytes::from_static(b"23.5"));
        assert_eq!(stage.content_type, "text/plain; charset=utf-8");

        let get_bytes =
            coap_get_packet(&[b"home", b"sensor", b"kitchen", b"temp"], Some(b"reader"));
        let get = packet(&get_bytes);
        let get_response = handle(&engine, &get).await;
        assert_eq!(get_response[1], 69); // 2.05 Content
        assert_eq!(get_response[6], 0xff);
        assert_eq!(&get_response[7..], b"23.5");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn http_put_and_coap_put_share_engine_semantics() {
        let (engine, dir) = test_engine_for_server_with_auth_tokens("cross-protocol");
        let mut events = engine
            .subscribe(
                &crate::engine_types::SubscribePattern::new("home/*"),
                AccessTier::Read,
                crate::engine_types::SubscriptionResume::none(),
            )
            .expect("test subscription should open");
        let http_state = server_state_for_engine_for_tests(engine.clone());

        let mut http_headers = HeaderMap::new();
        http_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8".parse().unwrap(),
        );
        let http_phase = handler::execute_put(
            http_headers,
            Bytes::from_static(b"23.5"),
            AccessTier::Write,
            ValidatedWorldPath::new("home/http-temp").unwrap(),
            &http_state,
            &TraceCtx::disabled(),
        )
        .await;
        let http_response = match http_phase {
            Phase::CommittedWrite(resp) => resp,
            _ => panic!("HTTP PUT did not commit"),
        };
        assert_eq!(http_response.status(), StatusCode::CREATED);
        let http_event = events.recv().await.unwrap();
        assert_eq!(http_event.verb, crate::engine_types::ChangeVerb::Replace);
        assert_eq!(http_event.path.as_str(), "home/http-temp");

        let coap_put_bytes =
            coap_put_packet(&[b"home", b"coap", b"temp"], b"23.5", Some(b"writer"));
        let coap_put = packet(&coap_put_bytes);
        let coap_response = handle(&engine, &coap_put).await;
        assert_eq!(coap_response[1], 65); // 2.01 Created
        let coap_event = events.recv().await.unwrap();
        assert_eq!(coap_event.verb, crate::engine_types::ChangeVerb::Replace);
        assert_eq!(coap_event.path.as_str(), "home/coap/temp");

        let http_world = ValidatedWorldPath::new("home/http-temp").unwrap();
        let coap_world = ValidatedWorldPath::new("home/coap/temp").unwrap();
        let http_read = engine.read(&http_world, AccessTier::Read).unwrap().unwrap();
        let coap_read = engine.read(&coap_world, AccessTier::Read).unwrap().unwrap();
        assert_eq!(http_read.representation.body, coap_read.representation.body);
        assert_eq!(
            http_read.representation.content_type,
            coap_read.representation.content_type
        );
        assert!(http_read.etag.starts_with("hmac-"));
        assert!(coap_read.etag.starts_with("hmac-"));
        assert_eq!(http_event.etag, http_read.etag);
        assert_eq!(coap_event.etag, coap_read.etag);
        assert_eq!(engine.df(AccessTier::Read).unwrap().worlds, 2);
        assert!(matches!(
            engine.verify_audit(&http_world, AccessTier::Read).unwrap(),
            crate::engine_introspection::AuditVerify::Valid(_)
        ));
        assert!(matches!(
            engine.verify_audit(&coap_world, AccessTier::Read).unwrap(),
            crate::engine_introspection::AuditVerify::Valid(_)
        ));

        let _ = std::fs::remove_dir_all(dir);
    }
}
