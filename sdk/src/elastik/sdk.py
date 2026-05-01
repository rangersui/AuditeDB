"""Small Python bindings for elastik-core.

This package is deliberately boring: PUT stores bytes, GET returns bytes,
HEAD returns metadata, and /listen emits change events.

stdlib only: no httpx, no requests. urllib.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import time
import csv
import difflib
import gzip as gzip_mod
import io
import struct
import textwrap
import urllib.error
import urllib.parse
import urllib.request
import warnings
from collections.abc import MutableMapping
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Iterator, TypedDict


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
_REPRESENTATION_KWARGS = {
    "content_type",
    "content_encoding",
    "content_language",
    "content_disposition",
    "cache_control",
}
_log = logging.getLogger("elastik")


WorldMeta = TypedDict(
    "WorldMeta",
    {
        "etag": str,
        "content-type": str,
        "content-length": str,
        "content-encoding": str,
        "content-language": str,
        "content-disposition": str,
        "cache-control": str,
        "accept-ranges": str,
        "link": str,
    },
    total=False,
)


class ElastikError(Exception):
    def __init__(self, status: int, body: bytes, *, method: str = "", path: str = ""):
        self.status = status
        self.body = body
        self.method = method
        self.path = path
        super().__init__(str(self))

    def __str__(self) -> str:
        route = f" {self.method} {self.path}" if self.method or self.path else ""
        return f"elastik {self.status}{route}: {self.body[:200]!r}"


class Unauthorized(ElastikError):
    """401 Unauthorized."""


class Forbidden(ElastikError):
    """403 Forbidden."""


class NotFound(ElastikError):
    """404 Not Found."""


class PreconditionFailed(ElastikError):
    """412 Precondition Failed."""


class PayloadTooLarge(ElastikError):
    """413 Payload Too Large."""


class ServerError(ElastikError):
    """5xx server-side failure."""


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


class Elastik(MutableMapping[str, bytes]):
    """Pythonic bindings to elastik-core's HTTP surface.

    >>> e = Elastik("http://localhost:3105", bearer_token="write-token")
    >>> e.put("note", b"hello")          # PUT /home/note
    >>> e.get("note")                    # GET, returns bytes
    >>> e.get_text("note")               # GET, decode to str
    >>> e.head("note")                   # HEAD, lowercased headers dict
    >>> e.list_paths()                   # GET /proc/worlds
    """

    def __init__(self, url: str | None = None, bearer_token: str | None = None):
        if url is None:
            from elastik._spawn import default_url
            url = default_url()
        if bearer_token is None:
            bearer_token = _best_env_token()
        self.url = url.rstrip("/")
        self.bearer_token = bearer_token
        self._etag_cache: dict[str, tuple[str, bytes]] = {}

    def __repr__(self) -> str:
        status = "external"
        count: str | int = "?"
        try:
            from elastik._spawn import is_running, live_info

            live = live_info()
            if live.get("url") == self.url:
                status = live.get("state") or ("running" if is_running() else "stopped")
                if status == "running":
                    try:
                        count = len(self.list_paths())
                    except Exception:
                        count = "?"
        except Exception:
            pass
        return f"<Elastik {self.url} [{status}] {count} paths>"

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
        if_none_match: str | None = None,
        create_only: bool = False,
        headers: dict[str, str] | None = None,
        **meta: Any,
    ) -> dict:
        """PUT body to path, replacing any existing body.

        `content_type` and standard representation kwargs are stored
        as HTTP representation metadata and returned verbatim by GET
        and HEAD. Extra kwargs become X-Meta-* headers; they are plain
        metadata, not auth or audit fields.

        `create_only=True` sends `If-None-Match: *`.
        `if_none_match="etag"` sends a quoted ETag validator.
        """
        if isinstance(if_none_match, bool):
            raise TypeError("if_none_match must be an ETag string; use create_only=True for If-None-Match: *")
        if create_only and if_none_match is not None:
            raise ValueError("use either create_only=True or if_none_match=etag, not both")
        body = _body_bytes(data, "put")
        request_headers = dict(headers or {})
        _warn_near_representation_kwargs(meta)
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
        if create_only:
            request_headers["If-None-Match"] = "*"
        elif if_none_match:
            request_headers["If-None-Match"] = (
                "*" if if_none_match == "*" else _etag_value(str(if_none_match))
            )
        resp = self.request("PUT", path, body, request_headers)
        if resp.status >= 400:
            _raise_for_response(resp, "PUT", path)
        if resp.etag:
            self._etag_cache[_cache_key(path)] = (resp.etag, body)
        return {
            "status": resp.status,
            "etag": resp.etag,
        }

    def put_text(
        self,
        path: str,
        text: str,
        *,
        encoding: str = "utf-8",
        **kwargs: Any,
    ) -> dict:
        """PUT text with a text/plain Content-Type."""
        return self.put(
            path,
            text.encode(encoding),
            content_type=f"text/plain; charset={encoding}",
            **kwargs,
        )

    def put_json(
        self,
        path: str,
        value: Any,
        *,
        ensure_ascii: bool = False,
        **kwargs: Any,
    ) -> dict:
        """PUT JSON with application/json Content-Type."""
        body = json.dumps(value, ensure_ascii=ensure_ascii).encode("utf-8")
        return self.put(path, body, content_type="application/json", **kwargs)

    def put_gzip(self, path: str, data: bytes | str, **kwargs: Any) -> dict:
        """PUT gzip-compressed bytes with Content-Encoding: gzip."""
        body = _body_bytes(data, "put_gzip")
        kwargs.setdefault(
            "content_type",
            "text/plain; charset=utf-8"
            if isinstance(data, str)
            else "application/octet-stream",
        )
        return self.put(path, gzip_mod.compress(body), content_encoding="gzip", **kwargs)

    def put_csv(self, path: str, rows: Any, **kwargs: Any) -> dict:
        """PUT rows as text/csv using the stdlib csv writer."""
        buf = io.StringIO(newline="")
        csv.writer(buf).writerows(rows)
        kwargs.setdefault("content_type", "text/csv")
        return self.put(path, buf.getvalue(), **kwargs)

    def put_struct(self, path: str, fmt: str, *values: Any, **kwargs: Any) -> dict:
        """PUT struct.pack(fmt, *values) as octet-stream bytes."""
        kwargs.setdefault("content_type", "application/octet-stream")
        return self.put(path, struct.pack(fmt, *values), **kwargs)

    def post(
        self,
        path: str,
        data: bytes | str,
        *,
        if_match: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict:
        """POST byte-append to an existing path without changing metadata."""
        body = _body_bytes(data, "post")
        request_headers = dict(headers or {})
        _set_if(request_headers, "If-Match", _etag_value(if_match))
        resp = self.request("POST", path, body, request_headers)
        if resp.status >= 400:
            _raise_for_response(resp, "POST", path)
        self.clear_cache(path)
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
        """GET path. Returns bytes exactly as stored, or None on 304.

        404 is an ElastikError. None never means "missing"; it only
        means the server returned 304 Not Modified for if_none_match.
        """
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
            _raise_for_response(resp, "GET", path)
        if resp.status >= 400:
            _raise_for_response(resp, "GET", path)
        if range is None and if_range is None and resp.etag:
            self._etag_cache[_cache_key(path)] = (resp.etag, resp.body)
        return resp.body

    def get_cached(self, path: str) -> bytes:
        """GET using a small client-side ETag cache.

        First call downloads the body. Later calls send If-None-Match
        and return the cached body on 304 Not Modified.
        """
        key = _cache_key(path)
        cached = self._etag_cache.get(key)
        if cached:
            etag, old_body = cached
            body = self.get(path, if_none_match=etag)
            if body is None:
                return old_body
        else:
            body = self.get(path)
        if body is None:
            raise KeyError(path)
        etag = self.head(path).get("etag", "")
        if etag:
            self._etag_cache[key] = (etag, body)
        return body

    def clear_cache(self, path: str | None = None) -> None:
        """Clear SDK-side ETag cache entries."""
        if path is None:
            self._etag_cache.clear()
        else:
            self._etag_cache.pop(_cache_key(path), None)

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

    def get_gzip(self, path: str) -> bytes:
        """GET and gzip-decompress the body."""
        body = self.get(path)
        if body is None:
            raise KeyError(path)
        return gzip_mod.decompress(body)

    def get_csv(self, path: str) -> list[list[str]]:
        """GET text/csv and parse rows with the stdlib csv reader."""
        text = self.get_text(path)
        if text is None:
            raise KeyError(path)
        return list(csv.reader(io.StringIO(text)))

    def get_struct(self, path: str, fmt: str) -> tuple[Any, ...]:
        """GET bytes and struct.unpack(fmt, body)."""
        body = self.get(path)
        if body is None:
            raise KeyError(path)
        return struct.unpack(fmt, body)

    def head(self, path: str) -> WorldMeta:
        """HEAD path. Returns lowercased HTTP headers.

        Stable application headers include: etag, content-type,
        content-length, accept-ranges, link, and any x-meta-* keys you
        stored with put(..., **meta).
        """
        resp = self.request("HEAD", path)
        if resp.status == 404:
            _raise_for_response(resp, "HEAD", path)
        if resp.status >= 400:
            _raise_for_response(resp, "HEAD", path)
        return resp.headers  # type: ignore[return-value]

    def delete(self, path: str, *, if_match: str | None = None) -> bool:
        """DELETE path.

        Returns True when the core deleted an existing path, False when
        the path was already missing, and raises ElastikError for 401,
        412, 5xx, and other real failures.
        """
        h = {}
        _set_if(h, "If-Match", _etag_value(if_match))
        resp = self.request("DELETE", path, headers=h)
        if resp.status == 204:
            self.clear_cache(path)
            return True
        if resp.status == 404:
            return False
        _raise_for_response(resp, "DELETE", path)
        return False

    def list(self) -> list[str]:
        """GET /proc/worlds. Returns one world name per line."""
        resp = self.request("GET", "/proc/worlds")
        if resp.status >= 400:
            _raise_for_response(resp, "GET", "/proc/worlds")
        text = resp.body.decode("utf-8")
        return [line for line in text.splitlines() if line]

    def list_paths(self) -> list[str]:
        """Alias for list(). Returns stored paths/keys."""
        return self.list()

    def list_keys(self) -> list[str]:
        """Alias for list_paths(), for KV-store-shaped code."""
        return self.list()

    def exists(self, path: str) -> bool:
        """Return True when HEAD succeeds for path."""
        return path in self

    def sizeof(self, path: str) -> int:
        """Return Content-Length without downloading the body."""
        return int(self.head(path).get("content-length", "0"))

    def checksum(self, path: str) -> str:
        """Return the current ETag via HEAD."""
        return self.head(path).get("etag", "")

    def is_audited(self, path: str) -> bool:
        """Return True when the current ETag is audit-chain backed."""
        return self.checksum(path).strip('"').startswith("hmac-")

    def verify(self, path: str) -> bool:
        """Alias for is_audited(); does not replay the full audit chain."""
        return self.is_audited(path)

    def diff(self, path: str, new_data: str) -> str:
        """Return a unified text diff between current body and new_data."""
        old = (self.get_text(path) or "").splitlines(keepends=True)
        new = new_data.splitlines(keepends=True)
        return "".join(
            difflib.unified_diff(old, new, fromfile=f"{path}@old", tofile=f"{path}@new")
        )

    def preview(
        self,
        path: str,
        *,
        width: int = 80,
        max_lines: int = 10,
        max_bytes: int = 4096,
        encoding: str = "utf-8",
        errors: str = "replace",
    ) -> str:
        """Fetch a small byte range and return a shortened text preview."""
        if max_bytes <= 0 or max_lines <= 0:
            return ""
        body = self.get(path, range=(0, max_bytes - 1))
        if body is None:
            return ""
        text = body.decode(encoding, errors)
        return "\n".join(
            textwrap.shorten(line, width=width, placeholder="...")
            for line in text.splitlines()[:max_lines]
        )

    def copy(self, src: str, dst: str, **meta: Any) -> dict:
        """Copy a path using GET + HEAD + PUT.

        The body is buffered in Python memory. For huge blobs, prefer a
        streaming tool or curl pipeline that fits your memory budget.
        """
        body = self.get(src)
        if body is None:
            raise KeyError(src)
        headers = self.head(src)
        return self.put(
            dst,
            body,
            content_type=headers.get("content-type", "application/octet-stream"),
            content_encoding=headers.get("content-encoding"),
            content_language=headers.get("content-language"),
            content_disposition=headers.get("content-disposition"),
            cache_control=headers.get("cache-control"),
            **meta,
        )

    def put_many(
        self,
        items: dict[str, bytes | str],
        *,
        max_workers: int = 4,
        **kwargs: Any,
    ) -> dict[str, dict]:
        """PUT many paths concurrently; each item is still one HTTP request."""
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                path: pool.submit(self.put, path, data, **kwargs)
                for path, data in items.items()
            }
            return {path: future.result() for path, future in futures.items()}

    def get_many(
        self,
        paths: list[str],
        *,
        max_workers: int = 4,
    ) -> dict[str, bytes | None]:
        """GET many paths concurrently; each path is still one HTTP request."""
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {path: pool.submit(self.get, path) for path in paths}
            return {path: future.result() for path, future in futures.items()}

    def open(self, path: str, mode: str = "rb") -> "WorldReader":
        """Open a read-only file-like object backed by Range GETs."""
        if mode != "rb":
            raise ValueError("only mode='rb' is supported")
        return WorldReader(self, path)

    @contextmanager
    def tmp(self, name: str = "") -> Iterator[str]:
        """Yield a /tmp path and best-effort delete it on exit.

        Cleanup requires whatever delete authority your core enforces.
        If cleanup is forbidden or the path is already gone, tmp()
        silently leaves the core's normal policy in charge.
        """
        safe = name.strip("/") if name else secrets.token_hex(8)
        path = f"tmp/{safe}"
        try:
            yield path
        finally:
            try:
                self.delete(path)
            except ElastikError:
                pass

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
        if self.bearer_token:
            h["Authorization"] = f"Bearer {self.bearer_token}"
        if last_event_id is not None:
            h["Last-Event-ID"] = str(last_event_id)
        req = urllib.request.Request(url, method="GET", headers=h)
        try:
            with urllib.request.urlopen(req, timeout=None) as r:
                yield from _iter_sse(r)
        except urllib.error.HTTPError as e:
            _raise_error(
                e.code,
                e.read() if e.fp else b"",
                method="GET",
                path=f"/listen/{pattern}",
            )

    def __getitem__(self, path: str) -> bytes:
        try:
            body = self.get(path)
        except NotFound:
            raise KeyError(path) from None
        if body is None:
            raise KeyError(path)
        return body

    def __setitem__(self, path: str, data: bytes | str) -> None:
        self.put(path, data)

    def __delitem__(self, path: str) -> None:
        if not self.delete(path):
            raise KeyError(path)

    def __contains__(self, path: object) -> bool:
        if not isinstance(path, str):
            return False
        try:
            self.head(path)
            return True
        except ElastikError:
            return False

    def __iter__(self) -> Iterator[str]:
        return iter(self.list_paths())

    def __len__(self) -> int:
        return len(self.list_paths())

    def __truediv__(self, path: str) -> "WorldRef":
        return WorldRef(self, path.strip("/"))

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
        if self.bearer_token:
            h.setdefault("Authorization", f"Bearer {self.bearer_token}")
        req = urllib.request.Request(url, data=body, method=method, headers=h)
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                response = Response(
                    r.status,
                    {k.lower(): v for k, v in r.headers.items()},
                    r.read(),
                )
                _log.debug(
                    "%s %s -> %d %dB %.1fms",
                    method,
                    path,
                    response.status,
                    len(response.body),
                    (time.perf_counter() - start) * 1000,
                )
                return response
        except urllib.error.HTTPError as e:
            response = Response(
                e.code,
                {k.lower(): v for k, v in (e.headers or {}).items()},
                e.read() if e.fp else b"",
            )
            _log.debug(
                "%s %s -> %d %dB %.1fms",
                method,
                path,
                response.status,
                len(response.body),
                (time.perf_counter() - start) * 1000,
            )
            return response

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


class WorldRef:
    """Pathlib-shaped reference to one elastik path."""

    def __init__(self, e: Elastik, path: str):
        self._e = e
        self._path = path.strip("/")

    @property
    def path(self) -> str:
        return self._path

    def __truediv__(self, child: str) -> "WorldRef":
        return WorldRef(self._e, f"{self._path.rstrip('/')}/{child.strip('/')}")

    def read(self) -> bytes:
        body = self._e.get(self._path)
        if body is None:
            raise KeyError(self._path)
        return body

    def read_text(self, *, encoding: str = "utf-8", errors: str = "strict") -> str:
        return self.read().decode(encoding, errors)

    def write(self, data: bytes | str, **kwargs: Any) -> dict:
        return self._e.put(self._path, data, **kwargs)

    def exists(self) -> bool:
        return self._path in self._e

    def unlink(self) -> bool:
        return self._e.delete(self._path)

    def stat(self) -> WorldMeta:
        return self._e.head(self._path)

    def open(self, mode: str = "rb") -> "WorldReader":
        return self._e.open(self._path, mode)

    def __fspath__(self) -> str:
        return self._path

    def __str__(self) -> str:
        return self._path

    def __repr__(self) -> str:
        return f"WorldRef({self._path!r})"


class WorldReader(io.RawIOBase):
    """Read-only file-like wrapper using HTTP Range requests."""

    def __init__(self, e: Elastik, path: str):
        super().__init__()
        self._e = e
        self._path = path
        self._pos = 0
        self._size = e.sizeof(path)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            new_pos = offset
        elif whence == io.SEEK_CUR:
            new_pos = self._pos + offset
        elif whence == io.SEEK_END:
            new_pos = self._size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        self._pos = max(0, new_pos)
        return self._pos

    def read(self, size: int = -1) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed elastik world")
        if self._pos >= self._size or size == 0:
            return b""
        if size is None or size < 0:
            end = self._size - 1
        else:
            end = min(self._size, self._pos + size) - 1
        body = self._e.get(self._path, range=(self._pos, end))
        if body is None:
            return b""
        self._pos += len(body)
        return body

    def readinto(self, buf: Any) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed elastik world")
        view = memoryview(buf).cast("B")
        if self._pos >= self._size or len(view) == 0:
            return 0
        end = min(self._size, self._pos + len(view)) - 1
        body = self._e.get(self._path, range=(self._pos, end))
        if body is None:
            return 0
        n = len(body)
        view[:n] = body
        self._pos += n
        return n


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
        or os.getenv("ELASTIK_WRITE_TOKEN")
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


def _cache_key(path: str) -> str:
    return _canonical_world_name(path)


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


def _body_bytes(data: bytes | str, method: str) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    raise TypeError(f"{method}() data must be str or bytes, got {type(data).__name__}")


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


def _raise_for_response(resp: Response, method: str, path: str) -> None:
    _raise_error(resp.status, resp.body, method=method, path=path)


def _raise_error(status: int, body: bytes, *, method: str = "", path: str = "") -> None:
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


def _warn_near_representation_kwargs(meta: dict[str, Any]) -> None:
    for key in meta:
        normalized = str(key).replace("-", "_").lower()
        if normalized in _REPRESENTATION_KWARGS:
            continue
        for expected in _REPRESENTATION_KWARGS:
            if _edit_distance_leq(normalized, expected, 2):
                warnings.warn(
                    f"metadata key {key!r} looks like {expected!r}; "
                    f"use {expected}=... if you meant the HTTP header",
                    stacklevel=3,
                )
                break


def _edit_distance_leq(a: str, b: str, limit: int) -> bool:
    if abs(len(a) - len(b)) > limit:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        row_min = cur[0]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
            row_min = min(row_min, cur[-1])
        if row_min > limit:
            return False
        prev = cur
    return prev[-1] <= limit


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
