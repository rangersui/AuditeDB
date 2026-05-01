"""Small Python bindings for elastik-core.

This package is deliberately boring: PUT stores bytes, GET returns bytes,
HEAD returns metadata, and /listen emits change events.

stdlib only: no httpx, no requests. urllib.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterator


_NAMESPACES = {"home", "tmp", "dev", "sys", "proc", "etc", "lib", "boot", "usr", "var"}
_PROC_ENDPOINTS = {"proc/version", "proc/worlds"}
_RESERVED_WORLD_NAMES = {
    "home",
    "tmp",
    "dev",
    "sys",
    "proc",
    "etc",
    "lib",
    "boot",
    "usr",
    "var",
    "var/log",
}


class ElastikError(Exception):
    def __init__(self, status: int, body: bytes):
        self.status = status
        self.body = body
        super().__init__(f"elastik {status}: {body[:200]!r}")


@dataclass(frozen=True)
class Response:
    """Thin HTTP response object returned by Elastik.request()."""

    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def ok(self) -> bool:
        return self.status < 400

    @property
    def etag(self) -> str:
        return self.headers.get("etag", "")

    @property
    def not_modified(self) -> bool:
        return self.status == 304

    @property
    def created(self) -> bool:
        return self.status == 201


class Elastik:
    """Pythonic bindings to elastik-core's HTTP surface.

    >>> e = Elastik("http://localhost:3105", token="t2")
    >>> e.put("note", b"hello")          # PUT /home/note
    >>> e.get("note")                    # GET, returns bytes
    >>> e.get_text("note")               # GET, decode to str
    >>> e.head("note")                   # HEAD, lowercased headers dict
    >>> e.list_paths()                   # GET /proc/worlds
    """

    def __init__(self, url: str | None = None, token: str | None = None):
        if url is None:
            from elastik._spawn import default_url
            url = default_url()
        if token is None:
            token = _best_env_token()
        self.url = url.rstrip("/")
        self.token = token

    def put(
        self,
        path: str,
        data: bytes | str,
        *,
        content_type: str | None = None,
        content_encoding: str | None = None,
        content_language: str | None = None,
        content_disposition: str | None = None,
        cache_control: str | None = None,
        if_match: str | None = None,
        if_none_match: bool | str = False,
        headers: dict[str, str] | None = None,
        **meta: Any,
    ) -> dict:
        """PUT body to path, replacing any existing body.

        `content_type` and standard representation kwargs are stored
        as HTTP representation metadata and returned verbatim by GET
        and HEAD. Extra kwargs become X-Meta-* headers; they are plain
        metadata, not auth or audit fields.

        `if_none_match=True` sends `If-None-Match: *`.
        `if_none_match="etag"` sends a quoted ETag validator.
        """
        body = data.encode("utf-8") if isinstance(data, str) else data
        request_headers = dict(headers or {})
        request_headers.update(
            {f"X-Meta-{k.replace('_', '-')}": str(v) for k, v in meta.items()}
        )
        if content_type is None:
            content_type = (
                "text/plain; charset=utf-8"
                if isinstance(data, str)
                else "application/octet-stream"
            )
        request_headers["Content-Type"] = content_type
        _set_if(request_headers, "Content-Encoding", content_encoding)
        _set_if(request_headers, "Content-Language", content_language)
        _set_if(request_headers, "Content-Disposition", content_disposition)
        _set_if(request_headers, "Cache-Control", cache_control)
        _set_if(request_headers, "If-Match", _etag_value(if_match))
        if if_none_match:
            request_headers["If-None-Match"] = (
                "*" if if_none_match is True else _etag_value(str(if_none_match))
            )
        resp = self.request("PUT", path, body, request_headers)
        if resp.status >= 400:
            raise ElastikError(resp.status, resp.body)
        return {
            "status": resp.status,
            "etag": resp.etag,
        }

    def post(
        self,
        path: str,
        data: bytes | str,
        *,
        if_match: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict:
        """POST byte-append to an existing path without changing metadata."""
        body = data.encode("utf-8") if isinstance(data, str) else data
        request_headers = dict(headers or {})
        _set_if(request_headers, "If-Match", _etag_value(if_match))
        resp = self.request("POST", path, body, request_headers)
        if resp.status >= 400:
            raise ElastikError(resp.status, resp.body)
        return {"status": resp.status, "etag": resp.etag}

    def get(
        self,
        path: str,
        *,
        range: tuple[int, int] | None = None,
        if_none_match: str | None = None,
        if_range: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> bytes | None:
        """GET path. Returns bytes exactly as stored, or None on 304."""
        request_headers = dict(headers or {})
        if range is not None:
            start, end = range
            request_headers["Range"] = f"bytes={start}-{end}"
        _set_if(request_headers, "If-None-Match", _etag_value(if_none_match))
        _set_if(request_headers, "If-Range", _etag_value(if_range))
        resp = self.request("GET", path, headers=request_headers)
        if resp.status == 304:
            return None
        if resp.status == 404:
            raise ElastikError(404, resp.body)
        if resp.status >= 400:
            raise ElastikError(resp.status, resp.body)
        return resp.body

    def get_text(
        self,
        path: str,
        *,
        encoding: str = "utf-8",
        errors: str = "strict",
        range: tuple[int, int] | None = None,
        if_none_match: str | None = None,
        if_range: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> str | None:
        """GET path and decode bytes to text, or return None on 304."""
        body = self.get(
            path,
            range=range,
            if_none_match=if_none_match,
            if_range=if_range,
            headers=headers,
        )
        if body is None:
            return None
        return body.decode(encoding, errors)

    def get_json(
        self,
        path: str,
        *,
        encoding: str = "utf-8",
        range: tuple[int, int] | None = None,
        if_none_match: str | None = None,
        if_range: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any | None:
        """GET path, decode as UTF-8 JSON, or return None on 304."""
        text = self.get_text(
            path,
            encoding=encoding,
            range=range,
            if_none_match=if_none_match,
            if_range=if_range,
            headers=headers,
        )
        if text is None:
            return None
        return json.loads(text)

    def head(self, path: str) -> dict[str, str]:
        """HEAD path. Returns lowercased HTTP headers.

        Stable application headers include: etag, content-type,
        content-length, accept-ranges, link, and any x-meta-* keys you
        stored with put(..., **meta).
        """
        resp = self.request("HEAD", path)
        if resp.status == 404:
            raise ElastikError(404, resp.body)
        if resp.status >= 400:
            raise ElastikError(resp.status, resp.body)
        return resp.headers

    def delete(self, path: str, *, if_match: str | None = None) -> bool:
        """DELETE path. Returns True on 204, False on 404."""
        h = {}
        _set_if(h, "If-Match", _etag_value(if_match))
        resp = self.request("DELETE", path, headers=h)
        if resp.status == 204:
            return True
        if resp.status == 404:
            return False
        raise ElastikError(resp.status, resp.body)

    def list(self) -> list[str]:
        """GET /proc/worlds. Returns one world name per line."""
        resp = self.request("GET", "/proc/worlds")
        if resp.status >= 400:
            raise ElastikError(resp.status, resp.body)
        text = resp.body.decode("utf-8")
        return [line for line in text.splitlines() if line]

    def list_paths(self) -> list[str]:
        """Alias for list(). Returns stored paths/keys."""
        return self.list()

    def list_keys(self) -> list[str]:
        """Alias for list_paths(), for KV-store-shaped code."""
        return self.list()

    def listen(
        self,
        pattern: str = "*",
        *,
        last_event_id: str | int | None = None,
    ) -> Iterator[dict[str, str]]:
        """Yield Server-Sent Events from GET /listen/{pattern}.

        Events are control-plane only:
          event: put
          data: path: /home/task/a
          data: method: PUT
          data: etag: hmac-...

        The body is never embedded in the stream. Consumers that need
        content call GET/HEAD with the path from the event.
        """
        url = self.url + "/listen/" + _quote_listen_pattern(pattern)
        h = {}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if last_event_id is not None:
            h["Last-Event-ID"] = str(last_event_id)
        req = urllib.request.Request(url, method="GET", headers=h)
        try:
            with urllib.request.urlopen(req, timeout=None) as r:
                yield from _iter_sse(r)
        except urllib.error.HTTPError as e:
            raise ElastikError(e.code, e.read() if e.fp else b"") from e

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        """Raw HTTP escape hatch for any header/method the SDK hasn't sugared."""
        url = self.url + _quote_path(path)
        h = dict(headers or {})
        if self.token:
            h.setdefault("Authorization", f"Bearer {self.token}")
        req = urllib.request.Request(url, data=body, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return Response(
                    r.status,
                    {k.lower(): v for k, v in r.headers.items()},
                    r.read(),
                )
        except urllib.error.HTTPError as e:
            return Response(
                e.code,
                {k.lower(): v for k, v in (e.headers or {}).items()},
                e.read() if e.fp else b"",
            )

    def _raw(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """Backward-compatible tuple escape hatch. Prefer request()."""
        resp = self.request(method, path, body, headers)
        return resp.status, resp.headers, resp.body


def _quote_listen_pattern(pattern: str) -> str:
    p = pattern.strip() or "*"
    if p.startswith("/"):
        p = p[1:]
    if p != "*":
        _validate_world_name(_canonical_world_name(p))
    return urllib.parse.quote(p, safe="/-*")


def _best_env_token() -> str:
    return (
        os.getenv("ELASTIK_APPROVE_TOKEN")
        or os.getenv("ELASTIK_TOKEN")
        or os.getenv("ELASTIK_READ_TOKEN", "")
    )


def _quote_path(path: str) -> str:
    world = _canonical_world_name(path)
    if world in _PROC_ENDPOINTS:
        return "/" + urllib.parse.quote(world, safe="/")
    if world == "proc" or world.startswith("proc/"):
        raise ValueError("/proc is reserved; only /proc/version and /proc/worlds exist")
    _validate_world_name(world)
    return "/" + urllib.parse.quote(world, safe="/")


def _canonical_world_name(path: str) -> str:
    stripped = path.lstrip("/")
    first = stripped.split("/", 1)[0]
    if first in _NAMESPACES:
        return stripped
    return "home/" + stripped


def _validate_world_name(world: str) -> None:
    if not world:
        raise ValueError("empty elastik path")
    if world in _RESERVED_WORLD_NAMES or world.startswith("proc/"):
        raise ValueError("namespace roots and /proc internals are reserved")
    if "\\" in world:
        raise ValueError("backslash is not allowed in elastik paths")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in world):
        raise ValueError("control bytes are not allowed in elastik paths")
    for segment in world.split("/"):
        if segment in ("", ".", ".."):
            raise ValueError("empty, dot, and dot-dot path segments are not allowed")


def _set_if(headers: dict[str, str], name: str, value: str | None) -> None:
    if value is not None:
        headers[name] = str(value)


def _etag_value(value: str | None) -> str | None:
    if value is None:
        return None
    v = str(value).strip()
    if v == "*":
        return v
    if v.startswith("W/"):
        return v
    if v.startswith('"') and v.endswith('"'):
        return v
    return f'"{v}"'


def _iter_sse(resp) -> Iterator[dict[str, str]]:
    event = "message"
    event_id = ""
    data_lines: list[str] = []
    for raw in resp:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if line == "":
            if data_lines:
                data = "\n".join(data_lines)
                item = {
                    "event": event,
                    "id": event_id,
                    "data": data,
                }
                item.update(_parse_event_data(data))
                yield item
            event = "message"
            event_id = ""
            data_lines = []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("id:"):
            event_id = line[3:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip(" "))


def _parse_event_data(data: str) -> dict[str, str]:
    out = {}
    for line in data.splitlines():
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip().lower()] = v.lstrip(" ")
    return out
