"""Tiny stdlib-only SCoAP client for elastik-core.

This is UDP's curl-shaped helper: humans say method/path/body, Python
packs the small CoAP envelope, and the core sees the same bytes as HTTP.

It is intentionally not a general CoAP stack. It speaks the subset that
elastik-core accepts: GET, PUT, Uri-Path, text/plain or octet-stream
Content-Format, payload marker, and private auth option 65001.
"""
from __future__ import annotations

import secrets
import socket
from dataclasses import dataclass
from typing import Iterable

from elastik.sdk import (
    ElastikError,
    Forbidden,
    NotFound,
    PayloadTooLarge,
    PreconditionFailed,
    ServerError,
    Unauthorized,
    _canonical_world_name,
    _validate_world_name,
)


ELASTIK_AUTH_OPTION = 65001
MAX_DATAGRAM = 1152
_CONTENT_FORMATS = {
    "text/plain": 0,
    "application/octet-stream": 42,
}
_CODE_TEXT = {
    65: "2.01 Created",
    68: "2.04 Changed",
    69: "2.05 Content",
    128: "4.00 Bad Request",
    129: "4.01 Unauthorized",
    131: "4.03 Forbidden",
    132: "4.04 Not Found",
    133: "4.05 Method Not Allowed",
    137: "4.09 Conflict",
    140: "4.12 Precondition Failed",
    141: "4.13 Request Entity Too Large",
    143: "4.15 Unsupported Content-Format",
    160: "5.00 Internal Server Error",
}


@dataclass(frozen=True)
class CoapResponse:
    code: int
    payload: bytes
    content_format: int | None
    raw: bytes

    @property
    def ok(self) -> bool:
        return 64 <= self.code < 96

    @property
    def status(self) -> str:
        return coap_code_text(self.code)

    def raise_for_status(self, *, method: str = "COAP", path: str = "") -> None:
        """Raise an ElastikError subclass when this CoAP response is not 2.xx."""
        if self.ok:
            return
        _raise_coap_error(self.code, self.payload, method=method, path=path)


class CoapClient:
    """Small stateful CoAP client so host/port/token are not repeated."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int | str = 5683,
        *,
        token: str | bytes | None = None,
        timeout: float = 2.0,
        raise_errors: bool = False,
    ):
        self.host = host
        self.port = int(port)
        self.token = token
        self.timeout = float(timeout)
        self.raise_errors = bool(raise_errors)

    def get(
        self,
        path: str,
        *,
        token: str | bytes | None = None,
        timeout: float | None = None,
        raise_errors: bool | None = None,
    ) -> CoapResponse:
        response = get(
            self.host,
            self.port,
            path,
            token=self.token if token is None else token,
            timeout=self.timeout if timeout is None else timeout,
        )
        if self._should_raise(raise_errors):
            response.raise_for_status(method="COAP GET", path=path)
        return response

    def put(
        self,
        path: str,
        payload: bytes | str,
        *,
        token: str | bytes | None = None,
        content_type: str | None = None,
        timeout: float | None = None,
        raise_errors: bool | None = None,
    ) -> CoapResponse:
        response = put(
            self.host,
            self.port,
            path,
            payload,
            token=self.token if token is None else token,
            content_type=content_type,
            timeout=self.timeout if timeout is None else timeout,
        )
        if self._should_raise(raise_errors):
            response.raise_for_status(method="COAP PUT", path=path)
        return response

    def _should_raise(self, override: bool | None) -> bool:
        return self.raise_errors if override is None else bool(override)


def get(
    host: str,
    port: int | str,
    path: str,
    *,
    token: str | bytes | None = None,
    timeout: float = 2.0,
    raise_errors: bool = False,
) -> CoapResponse:
    """Send one CoAP GET datagram and return the parsed response."""
    response = _roundtrip(
        host,
        int(port),
        _build_packet(1, path, auth_token=_bytes_or_none(token)),
        timeout,
    )
    if raise_errors:
        response.raise_for_status(method="COAP GET", path=path)
    return response


def put(
    host: str,
    port: int | str,
    path: str,
    payload: bytes | str,
    *,
    token: str | bytes | None = None,
    content_type: str | None = None,
    timeout: float = 2.0,
    raise_errors: bool = False,
) -> CoapResponse:
    """Send one CoAP PUT datagram and return the parsed response."""
    body = payload.encode("utf-8") if isinstance(payload, str) else payload
    if content_type is None:
        content_type = (
            "text/plain; charset=utf-8"
            if isinstance(payload, str)
            else "application/octet-stream"
        )
    response = _roundtrip(
        host,
        int(port),
        _build_packet(
            3,
            path,
            payload=body,
            auth_token=_bytes_or_none(token),
            content_format=_content_type_to_format(content_type),
        ),
        timeout,
    )
    if raise_errors:
        response.raise_for_status(method="COAP PUT", path=path)
    return response


def coap_code_text(code: int) -> str:
    if code in _CODE_TEXT:
        return _CODE_TEXT[code]
    return f"{code >> 5}.{code & 0x1f:02d}"


def _roundtrip(host: str, port: int, packet: bytes, timeout: float) -> CoapResponse:
    if len(packet) > MAX_DATAGRAM:
        raise ValueError(
            f"CoAP packet ({len(packet)} bytes) exceeds {MAX_DATAGRAM} byte "
            "datagram limit; use HTTP for large payloads"
        )
    last_error: OSError | None = None
    for family, socktype, proto, _canon, sockaddr in socket.getaddrinfo(
        host, port, type=socket.SOCK_DGRAM
    ):
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, sockaddr)
                data, _peer = sock.recvfrom(MAX_DATAGRAM)
                return _parse_response(data)
        except (socket.timeout, TimeoutError):
            last_error = TimeoutError(
                f"CoAP timeout after {timeout}s waiting for {host}:{port}"
            )
        except (ConnectionResetError, ConnectionRefusedError) as exc:
            last_error = TimeoutError(
                f"CoAP target {host}:{port} did not respond: {exc}"
            )
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise TimeoutError(f"no UDP address resolved for {host}:{port}")


def _build_packet(
    method_code: int,
    path: str,
    *,
    payload: bytes = b"",
    auth_token: bytes | None = None,
    content_format: int | None = None,
) -> bytes:
    message_id = secrets.randbelow(65536)
    message_token = secrets.token_bytes(1)
    out = bytearray()
    out.append(0x40 | len(message_token))  # v1, CON, token length
    out.append(method_code)
    out.extend(message_id.to_bytes(2, "big"))
    out.extend(message_token)

    prev = 0
    for segment in _path_segments(path):
        prev = _write_option(out, prev, 11, segment.encode("utf-8"))
    if content_format is not None:
        prev = _write_option(out, prev, 12, _uint_bytes(content_format))
    if auth_token:
        prev = _write_option(out, prev, ELASTIK_AUTH_OPTION, auth_token)
    if payload:
        out.append(0xFF)
        out.extend(payload)
    return bytes(out)


def _parse_response(data: bytes) -> CoapResponse:
    if len(data) < 4:
        raise ValueError("short CoAP response")
    if data[0] >> 6 != 1:
        raise ValueError("unsupported CoAP response version")
    token_len = data[0] & 0x0F
    if token_len > 8 or len(data) < 4 + token_len:
        raise ValueError("invalid CoAP response token")
    i = 4 + token_len
    option_number = 0
    content_format = None
    while i < len(data):
        if data[i] == 0xFF:
            return CoapResponse(data[1], data[i + 1 :], content_format, data)
        first = data[i]
        i += 1
        delta, i = _read_extended(first >> 4, data, i)
        length, i = _read_extended(first & 0x0F, data, i)
        option_number += delta
        if i + length > len(data):
            raise ValueError("truncated CoAP option")
        value = data[i : i + length]
        i += length
        if option_number == 12:
            content_format = _parse_uint(value)
    return CoapResponse(data[1], b"", content_format, data)


def _path_segments(path: str) -> Iterable[str]:
    world = _canonical_world_name(path)
    _validate_world_name(world)
    return world.split("/")


def _write_option(out: bytearray, prev: int, number: int, value: bytes) -> int:
    if number < prev:
        raise ValueError("CoAP options must be written in numeric order")
    delta_nibble, delta_ext = _extended_parts(number - prev)
    len_nibble, len_ext = _extended_parts(len(value))
    out.append((delta_nibble << 4) | len_nibble)
    out.extend(delta_ext)
    out.extend(len_ext)
    out.extend(value)
    return number


def _extended_parts(value: int) -> tuple[int, bytes]:
    if value < 0:
        raise ValueError("negative CoAP option value")
    if value <= 12:
        return value, b""
    if value <= 268:
        return 13, bytes([value - 13])
    if value <= 65804:
        return 14, (value - 269).to_bytes(2, "big")
    raise ValueError("CoAP option value too large")


def _read_extended(nibble: int, data: bytes, i: int) -> tuple[int, int]:
    if nibble <= 12:
        return nibble, i
    if nibble == 13:
        if i >= len(data):
            raise ValueError("truncated CoAP extended option")
        return data[i] + 13, i + 1
    if nibble == 14:
        if i + 2 > len(data):
            raise ValueError("truncated CoAP extended option")
        return int.from_bytes(data[i : i + 2], "big") + 269, i + 2
    raise ValueError("reserved CoAP option nibble")


def _uint_bytes(value: int) -> bytes:
    if value == 0:
        return b""
    if value <= 0xFF:
        return bytes([value])
    if value <= 0xFFFF:
        return value.to_bytes(2, "big")
    raise ValueError("CoAP uint too large")


def _parse_uint(value: bytes) -> int:
    if len(value) > 2:
        raise ValueError("CoAP uint too large")
    out = 0
    for byte in value:
        out = (out << 8) | byte
    return out


def _content_type_to_format(value: str) -> int | None:
    base = value.split(";", 1)[0].strip().lower()
    try:
        return _CONTENT_FORMATS[base]
    except KeyError:
        supported = ", ".join(sorted(_CONTENT_FORMATS))
        raise ValueError(
            f"unsupported CoAP content_type {value!r}; supported: {supported}"
        ) from None


def _coap_http_status(code: int) -> int:
    return (code >> 5) * 100 + (code & 0x1F)


def _raise_coap_error(
    code: int,
    body: bytes,
    *,
    method: str = "",
    path: str = "",
) -> None:
    status = _coap_http_status(code)
    cls: type[ElastikError]
    if status == 401:
        cls = Unauthorized
    elif status == 403:
        cls = Forbidden
    elif status == 404:
        cls = NotFound
    elif status == 412:
        cls = PreconditionFailed
    elif status == 413:
        cls = PayloadTooLarge
    elif status >= 500:
        cls = ServerError
    else:
        cls = ElastikError
    raise cls(status, body, method=method, path=path)


def _bytes_or_none(value: str | bytes | None) -> bytes | None:
    if value is None:
        return None
    return value.encode("utf-8") if isinstance(value, str) else value
