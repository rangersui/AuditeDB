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
import sys
import threading
import time
import csv
import difflib
import fnmatch
import gzip as gzip_mod
import io
import struct
import textwrap
import urllib.error
import urllib.parse
import urllib.request
import warnings
from collections.abc import Iterable, MutableMapping
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Iterator, TypedDict


_NAMESPACES = {"home", "tmp", "dev", "sys", "proc", "etc", "lib", "boot", "usr", "var"}
_PROC_ENDPOINTS = {"proc/version", "proc/worlds", "proc/du", "proc/df", "proc/pool"}
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
_FORBIDDEN_USER_HEADERS = {
    "content-length",
    "transfer-encoding",
    "host",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "http2-settings",
}
_NON_PERSISTED_RESPONSE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "http2-settings",
    "accept",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "expect",
    "from",
    "max-forwards",
    "origin",
    "prefer",
    "range",
    "referer",
    "referrer",
    "dnt",
    "user-agent",
    "if-match",
    "if-none-match",
    "if-range",
    "if-modified-since",
    "if-unmodified-since",
    "device-memory",
    "downlink",
    "dpr",
    "ect",
    "rtt",
    "save-data",
    "width",
    "viewport-width",
    "accept-ch",
    "alt-used",
    "attribution-reporting-eligible",
    "available-dictionary",
    "dictionary-id",
    "early-data",
    "idempotency-key",
    "service-worker",
    "service-worker-navigation-preload",
    "upgrade-insecure-requests",
    "alt-svc",
    "server-timing",
    "retry-after",
    "x-powered-by",
    "preference-applied",
    "priority",
    "critical-ch",
    "clear-site-data",
    "content-type",
    "content-length",
    "etag",
    "accept-ranges",
    "content-range",
    "link",
    "location",
    "allow",
    "date",
    "server",
    "www-authenticate",
    "age",
    "vary",
    "x-request-id",
    "x-elapsed-us",
    "x-elapsed-ms",
    "x-content-type-options",
    "forwarded",
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    # Other client-IP forwarding headers from load-balancers / CDNs.
    # true-client-ip = Akamai (also Cloudflare Enterprise);
    # client-ip = legacy proxies. Same data class as x-forwarded-for.
    "true-client-ip",
    "client-ip",
    # Distributed tracing context: W3C Trace Context, W3C Baggage,
    # Zipkin single-header b3. Auto-injected by APM / OpenTelemetry
    # SDKs; if persisted, the next reader replays the writer's
    # trace ID and corrupts downstream tracing. The multi-header
    # Zipkin propagation (x-b3-*) and cloud-provider injections
    # (cf-*, x-amzn-*, ":") are handled by the prefix check in
    # _is_never_persisted_header (which _should_persist_response_header
    # delegates to as Layer 1).
    "traceparent",
    "tracestate",
    "baggage",
    "b3",
    # HTTP transport version markers. http2-settings is
    # HTTP/1.1 -> HTTP/2 upgrade negotiation; http3-settings is
    # the QUIC analog. Living-fossil HTTP/1.0 Pragma: no-cache is
    # a per-request directive, not stored representation.
    "http3-settings",
    "pragma",
}
_log = logging.getLogger("elastik")

DebugHook = Callable[[str, str, int, float, str], None]
_DEBUG_LEVELS = {"all", "slow", "errors"}
_DEBUG_SECRET_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
}
_DEBUG_SECRET_SUFFIXES = ("-token", "-key", "-secret")
_DEBUG_PANEL_PATH = "/tmp/debug-panel.html"
_DEFAULT_DEBUG_SINK = object()
_DEBUG_PANEL_HTML = """<!DOCTYPE html>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">
<title>elastik debug</title>
<style>
  :root { color-scheme: dark; }
  body { background: #10130f; color: #7cff70; font: 14px ui-monospace, Consolas, monospace; margin: 20px; }
  h1 { color: #d8ffd2; font-size: 18px; font-weight: 600; margin: 0 0 12px; }
  #stats, #hint { color: #7f987b; margin-bottom: 10px; }
  #log { border-top: 1px solid #263322; padding-top: 12px; white-space: pre-wrap; }
  .slow { color: #ffb347; }
  .error { color: #ff5c5c; }
  .muted { color: #7f987b; }
</style>
<h1>elastik debug</h1>
<div id="stats">waiting...</div>
<div id="hint">source: /tmp/debug/requests</div>
<div id="log"></div>
<script>
const SINK = "/tmp/debug/requests";
const LIMIT = 500;
const stats = document.getElementById("stats");
const log = document.getElementById("log");
let seen = 0, total = 0, errors = 0, slow = 0;

function lineFor(r) {
  const ms = Number(r.client_ms || 0);
  const core = r.core_us == null ? "?" : r.core_us + "us";
  return `${r.rid || "?"} ${r.method || "?"} ${r.path || "?"} -> ${r.status || "?"} ${ms.toFixed(1)}ms core=${core}`;
}

function appendRecord(r) {
  total++;
  const ms = Number(r.client_ms || 0);
  const status = Number(r.status || 0);
  if (status >= 400) errors++;
  if (ms >= 100) slow++;
  stats.textContent = `total: ${total} | errors: ${errors} | slow: ${slow}`;
  const row = document.createElement("div");
  row.className = status >= 400 ? "error" : ms >= 100 ? "slow" : "";
  row.textContent = lineFor(r);
  log.appendChild(row);
  while (log.children.length > LIMIT) log.removeChild(log.firstChild);
}

async function refresh() {
  try {
    const res = await fetch(SINK, { cache: "no-store" });
    if (res.status === 404) {
      stats.textContent = "waiting for first debug record...";
      return;
    }
    if (res.status === 401 || res.status === 403) {
      stats.textContent = `auth required (${res.status}); set an Authorization header for this browser`;
      return;
    }
    if (!res.ok) {
      stats.textContent = `debug sink read failed: HTTP ${res.status}`;
      return;
    }
    const text = await res.text();
    const lines = text.trimEnd() ? text.trimEnd().split("\\n") : [];
    for (const line of lines.slice(seen)) {
      try { appendRecord(JSON.parse(line)); } catch (_) {}
    }
    seen = lines.length;
  } catch (err) {
    stats.textContent = "debug panel disconnected; retrying...";
  }
}

refresh();
setInterval(refresh, 3000);
const es = new EventSource("/listen/tmp/debug/requests");
es.onmessage = refresh;
es.addEventListener("put", refresh);
es.addEventListener("post", refresh);
es.addEventListener("lag", refresh);
</script>
"""


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
        "access-control-allow-origin": str,
        "access-control-allow-methods": str,
        "access-control-allow-headers": str,
        "access-control-expose-headers": str,
        "access-control-max-age": str,
        "content-security-policy": str,
        "x-frame-options": str,
        "x-content-type-options": str,
        "strict-transport-security": str,
        "permissions-policy": str,
        "cross-origin-opener-policy": str,
        "cross-origin-embedder-policy": str,
        "cross-origin-resource-policy": str,
    },
    total=False,
)


class ElastikError(Exception):
    def __init__(
        self,
        status: int,
        body: bytes,
        *,
        method: str = "",
        path: str = "",
        headers: dict[str, str] | None = None,
    ):
        self.status = status
        self.body = body
        self.method = method
        self.path = path
        self.headers = dict(headers or {})
        self.request_id = self.headers.get("x-request-id", "")
        self.core_elapsed_us = self.headers.get("x-elapsed-us", "")
        super().__init__(str(self))

    def __str__(self) -> str:
        route = f" {self.method} {self.path}" if self.method or self.path else ""
        details = []
        if self.request_id:
            details.append(f"request-id={self.request_id}")
        if self.core_elapsed_us:
            details.append(f"core-elapsed={self.core_elapsed_us}us")
        suffix = f" ({', '.join(details)})" if details else ""
        return f"elastik {self.status}{route}: {self.body[:200]!r}{suffix}"


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


class InsufficientStorage(ServerError):
    """507 Insufficient Storage."""


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

    def __init__(
        self,
        url: str | None = None,
        bearer_token: str | None = None,
        *,
        debug: bool | str = False,
    ):
        if url is None:
            from elastik._spawn import default_url
            url = default_url()
        if bearer_token is None:
            bearer_token = _best_env_token()
        self.url = url.rstrip("/")
        self.bearer_token = bearer_token
        self._etag_cache: dict[str, tuple[str, bytes]] = {}
        self._debug_enabled = False
        self._debug_level = "off"
        self._debug_slow_ms = 100.0
        self._debug_hook: DebugHook | None = None
        self._debug_record = False
        self._debug_verbose = 1
        self._debug_break_on: int | set[int] | None = None
        self._debug_sink: str | None = "/tmp/debug/requests"
        self._debug_local = threading.local()
        self.debug_history: list[dict[str, Any]] = []
        if debug:
            self.enable_debug(level="all" if debug is True else str(debug))

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

    def enable_debug(
        self,
        *,
        level: str | None = None,
        slow_ms: float = 100,
        hook: DebugHook | None = None,
        record: bool = False,
        verbose: int | None = None,
        break_on: int | Iterable[int] | None = None,
        sink: Any = _DEFAULT_DEBUG_SINK,
        panel: bool = False,
        panel_path: str = _DEBUG_PANEL_PATH,
    ) -> "Elastik":
        """Enable opt-in SDK request tracing.

        Debug records are observations of this client, not core logs. When
        `sink` is set, matching events are appended as JSON lines to `/tmp`
        memory worlds, so a core restart clears them. The sink is best-effort:
        debug write failures never break the original request.

        Levels:
          all    - record every request
          slow   - record slow requests and errors
          errors - record only 4xx/5xx responses

        `verbose=0/1/2/3` maps to errors/slow/all/all+redacted headers and is
        mutually exclusive with `level`. `record=True` keeps an in-memory
        `debug_history`; pass `sink="/tmp/debug/requests"` if you also want
        JSONL written into elastik. `panel=True` writes a tiny browser panel to
        `/tmp/debug-panel.html`.

        Hook signature:

            def hook(method: str, path: str, status: int,
                     elapsed_ms: float, request_id: str) -> None: ...
        """
        if verbose is not None:
            if level is not None:
                raise ValueError("use either level= or verbose=, not both")
            if verbose <= 0:
                level = "errors"
            elif verbose == 1:
                level = "slow"
            else:
                level = "all"
            self._debug_verbose = int(verbose)
        else:
            self._debug_verbose = 1
        level = (level or "all").lower()
        if level not in _DEBUG_LEVELS:
            raise ValueError(f"debug level must be one of {sorted(_DEBUG_LEVELS)}, got {level!r}")
        if sink is _DEFAULT_DEBUG_SINK:
            sink = None if record else "/tmp/debug/requests"
        self._debug_enabled = True
        self._debug_level = level
        self._debug_slow_ms = float(slow_ms)
        self._debug_hook = hook
        self._debug_record = bool(record)
        self._debug_break_on = _debug_normalize_break_on(break_on)
        self._debug_sink = sink
        if record:
            self.debug_history = []
        if self._debug_enabled and panel:
            self._debug_install_panel(panel_path)
        return self

    def disable_debug(self) -> "Elastik":
        """Disable SDK request tracing."""
        self._debug_enabled = False
        self._debug_level = "off"
        return self

    @property
    def debug_enabled(self) -> bool:
        """Whether SDK request tracing is currently enabled."""
        return self._debug_enabled

    def debug_stats(self) -> dict[str, Any]:
        """Summarize `debug_history` collected with enable_debug(record=True)."""
        history = list(self.debug_history)
        if not history:
            return {
                "total_requests": 0,
                "total_ms": 0,
                "avg_ms": 0,
                "p99_ms": 0,
                "by_method": {},
                "by_status": {},
                "slowest": None,
            }
        durations = sorted(float(row.get("client_ms", 0)) for row in history)
        total_ms = sum(durations)
        p99_index = min(len(durations) - 1, int(len(durations) * 0.99))
        by_method: dict[str, int] = {}
        by_status: dict[int, int] = {}
        for row in history:
            method = str(row.get("method", ""))
            status = int(row.get("status", 0))
            by_method[method] = by_method.get(method, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1
        slowest = max(history, key=lambda row: float(row.get("client_ms", 0)))
        return {
            "total_requests": len(history),
            "total_ms": round(total_ms, 3),
            "avg_ms": round(total_ms / len(history), 3),
            "p99_ms": round(durations[p99_index], 3),
            "by_method": by_method,
            "by_status": by_status,
            "slowest": slowest,
        }

    def _debug_install_panel(self, path: str) -> None:
        prior = self._debug_is_in_progress()
        self._debug_set_in_progress(True)
        try:
            self.put(path, _DEBUG_PANEL_HTML, content_type="text/html; charset=utf-8")
            print(f"\n  debug panel: {self.url}{_quote_path(path)}\n", file=sys.stderr)
        except Exception:
            _log.debug("failed to install elastik debug panel", exc_info=True)
        finally:
            self._debug_set_in_progress(prior)

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

        `content_type` is stored as the representation media type and
        returned as Content-Type. Other standard representation kwargs
        (Content-Encoding, Content-Language, Content-Disposition,
        Cache-Control, etc.) are in the core's built-in default-allow
        set and round-trip without configuration.

        Extra kwargs become `X-Meta-*` headers on the wire. **Whether
        they round-trip depends on the core's persist policy.** Under
        v7.2 default-deny, custom headers (including `X-Meta-*`) are
        only stored and audited when the operator opts in via
        `ELASTIK_PERSIST_HEADERS=x-meta-*`. With that allowlist set,
        durable worlds include them in audited representation
        metadata; without it, GET/HEAD will not echo them and the
        audit chain does not record them.

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
        """Return True when the current ETag is audit-chain backed.

        This is a storage-mode check, not a full audit-chain replay.
        """
        return self.checksum(path).strip('"').startswith("hmac-")

    def verify(self, path: str) -> bool:
        """Ask core to replay and verify the durable audit chain.

        Returns True only when core returns 200 with X-Audit-Valid: true.
        Memory worlds return False because they are not audit-backed. Broken
        chains return False. Cores that do not expose the verify endpoint
        return False after confirming the target path exists. Missing worlds
        and auth failures still raise the normal ElastikError subclasses.
        """
        world = _canonical_world_name(path)
        audit_path = f"/proc/audit/{world}/verify"
        resp = self.request("HEAD", audit_path)
        if resp.status == 200:
            return resp.headers.get("x-audit-valid") == "true"
        if resp.status in (204, 409):
            return False
        if resp.status == 404:
            try:
                self.head(path)
            except NotFound:
                _raise_for_response(resp, "HEAD", audit_path)
            return False
        if resp.status >= 400:
            _raise_for_response(resp, "HEAD", audit_path)
        return False

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

    def ls(self, prefix: str = "", *, depth: int = 1) -> list[str]:
        """List paths under prefix, pretending flat world keys are a tree.

        ``depth=1`` behaves like ``os.listdir``: immediate children only,
        with virtual directories ending in ``/``. ``depth=-1`` returns all
        descendants, like ``find``.
        """
        root = _canonical_prefix(prefix)
        paths = self.list_paths()
        children = [
            path
            for path in paths
            if not root or path == root or path.startswith(root + "/")
        ]
        if depth == -1:
            return children
        if depth < 1:
            raise ValueError("depth must be >= 1, or -1 for all descendants")
        out: list[str] = []
        seen: set[str] = set()
        for path in children:
            if root and path == root:
                out.append(path)
                continue
            rest = path[len(root):].lstrip("/") if root else path
            parts = rest.split("/")
            if len(parts) <= depth:
                out.append(path)
                continue
            name = "/".join(parts[:depth]) + "/"
            virtual = f"{root}/{name}" if root else name
            if virtual not in seen:
                seen.add(virtual)
                out.append(virtual)
        return out

    def tree(self, prefix: str = "") -> str:
        """Return a text tree view of stored paths under prefix."""
        root = _canonical_prefix(prefix)
        paths = self.ls(root, depth=-1) if root else self.ls(depth=-1)
        if not paths:
            return "(empty)"
        base_len = len(root.split("/")) if root else 0
        tree: dict[str, Any] = {}
        for path in paths:
            parts = path.split("/")[base_len:] if root else path.split("/")
            node = tree
            for part in parts:
                if part:
                    node = node.setdefault(part, {})
        lines: list[str] = []

        def walk(node: dict[str, Any], indent: str = "") -> None:
            items = sorted(node.items())
            for index, (name, children) in enumerate(items):
                last = index == len(items) - 1
                lines.append(f"{indent}{'└── ' if last else '├── '}{name}")
                walk(children, indent + ("    " if last else "│   "))

        if root:
            lines.append(root)
            walk(tree)
        else:
            walk(tree)
        return "\n".join(lines)

    def rm(self, path: str, *, recursive: bool = False, force: bool = False) -> int:
        """Delete one path, or recursively delete all paths under a prefix.

        Recursive deletion refuses an empty prefix or namespace root such as
        ``home`` unless ``force=True`` is explicit. Each delete is one HTTP
        request; there is no transaction or rollback.
        """
        if not recursive:
            return 1 if self.delete(path) else 0
        root = _canonical_prefix(path)
        _guard_destructive_prefix(root, "rm", force)
        targets = [p for p in self.ls(path, depth=-1) if not p.endswith("/")]
        count = 0
        for target in targets:
            if self.delete(target):
                count += 1
        return count

    def mv(
        self,
        src: str,
        dst: str,
        *,
        recursive: bool = False,
        overwrite: bool = False,
    ) -> int:
        """Move one path, or recursively move all paths under a prefix.

        This is copy+delete, not an atomic filesystem rename. Partial failures
        can leave source and destination paths side by side. Existing
        destinations are rejected unless ``overwrite=True``.
        """
        src_root = _canonical_prefix(src)
        dst_root = _canonical_prefix(dst)
        if src_root == dst_root:
            raise ValueError("mv() source and destination must be different")
        if not recursive:
            if not overwrite and self.exists(dst_root):
                raise FileExistsError(dst_root)
            self.copy(src_root, dst_root)
            self.delete(src_root)
            return 1
        if not src_root:
            raise ValueError("mv(recursive=True) requires a non-empty source prefix")
        if not dst_root:
            raise ValueError("mv(recursive=True) requires a non-empty destination prefix")
        targets = [p for p in self.ls(src_root, depth=-1) if not p.endswith("/")]
        if not overwrite:
            for target in targets:
                suffix = target[len(src_root):]
                candidate = dst_root + suffix
                if self.exists(candidate):
                    raise FileExistsError(candidate)
        count = 0
        for target in targets:
            suffix = target[len(src_root):]
            self.copy(target, dst_root + suffix)
            if self.delete(target):
                count += 1
        return count

    def du(self, prefix: str = "", *, max_workers: int = 4) -> dict[str, int]:
        """Return Content-Length for each stored path under prefix."""
        if max_workers < 1:
            raise ValueError("max_workers must be greater than 0")
        paths = [path for path in self.ls(prefix, depth=-1) if not path.endswith("/")]
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {path: pool.submit(self.sizeof, path) for path in paths}
            return {path: future.result() for path, future in futures.items()}

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
          data: timeline-world: home/task/a
          data: timeline-generation: 0123456789abcdef0123456789abcdef
          data: timeline-seq: 42
          data: timeline-body-sha256: ...

        The body is never embedded in the stream. Timeline fields are
        historical coordinates for durable body writes; GET/HEAD with the
        path reads the current value, not necessarily the signalled value.
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

    def _debug_after_response(
        self,
        method: str,
        path: str,
        request_headers: dict[str, str],
        response: Response,
        elapsed_ms: float,
    ) -> None:
        if not self._debug_enabled or self._debug_is_in_progress():
            return
        if _is_debug_path(path):
            return
        rid = response.headers.get("x-request-id", "?")
        event: dict[str, Any] = {
            "rid": rid,
            "method": method.upper(),
            "path": path,
            "status": response.status,
            "client_ms": round(elapsed_ms, 3),
            "core_us": _int_header(response.headers, "x-elapsed-us"),
            "bytes": len(response.body),
            "ts": time.time(),
        }
        if self._debug_verbose >= 3:
            event["request_headers"] = _redact_headers(request_headers)
            event["response_headers"] = _redact_headers(response.headers)
        if self._debug_hook is not None:
            try:
                self._debug_hook(method.upper(), path, response.status, elapsed_ms, rid)
            except Exception:
                _log.exception("elastik debug hook failed")
        if not self._debug_should_log(response.status, elapsed_ms):
            if _debug_break_matches(self._debug_break_on, response.status):
                breakpoint()
            return
        if self._debug_record:
            self.debug_history.append(dict(event))
        line = json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
        if not self._debug_sink:
            if _debug_break_matches(self._debug_break_on, response.status):
                breakpoint()
            return
        self._debug_append(self._debug_sink, line)
        if response.status >= 400:
            self._debug_append("/tmp/debug/errors", line)
        if elapsed_ms >= self._debug_slow_ms:
            self._debug_append("/tmp/debug/slow", line)
        if _debug_break_matches(self._debug_break_on, response.status):
            breakpoint()

    def _debug_should_log(self, status: int, elapsed_ms: float) -> bool:
        if self._debug_level == "all":
            return True
        if self._debug_level == "errors":
            return status >= 400
        if self._debug_level == "slow":
            return status >= 400 or elapsed_ms >= self._debug_slow_ms
        return False

    def _debug_append(self, path: str | None, line: str) -> None:
        if not path:
            return
        prior = self._debug_is_in_progress()
        self._debug_set_in_progress(True)
        try:
            body = line.encode("utf-8")
            try:
                self.post(path, body)
            except NotFound:
                self.put(path, b"", content_type="application/x-ndjson")
                self.post(path, body)
        except Exception:
            _log.debug("failed to append elastik debug record", exc_info=True)
        finally:
            self._debug_set_in_progress(prior)

    def _debug_is_in_progress(self) -> bool:
        return bool(getattr(self._debug_local, "in_progress", False))

    def _debug_set_in_progress(self, value: bool) -> None:
        self._debug_local.in_progress = value

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        """Raw HTTP escape hatch for methods plus headers that pass wire checks."""
        url = self.url + _quote_path(path)
        h = dict(headers or {})
        _reject_wire_headers(h)
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
                elapsed_ms = (time.perf_counter() - start) * 1000
                _log.debug(
                    "%s %s -> %d %dB %.1fms",
                    method,
                    path,
                    response.status,
                    len(response.body),
                    elapsed_ms,
                )
                self._debug_after_response(method, path, h, response, elapsed_ms)
                return response
        except urllib.error.HTTPError as e:
            response = Response(
                e.code,
                {k.lower(): v for k, v in (e.headers or {}).items()},
                e.read() if e.fp else b"",
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            _log.debug(
                "%s %s -> %d %dB %.1fms",
                method,
                path,
                response.status,
                len(response.body),
                elapsed_ms,
            )
            self._debug_after_response(method, path, h, response, elapsed_ms)
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

    def iterdir(self, depth: int = 1) -> list["WorldRef"]:
        return [WorldRef(self._e, path) for path in self._e.ls(self._path, depth=depth)]

    def walk(self) -> list["WorldRef"]:
        return self.iterdir(depth=-1)

    def glob(self, pattern: str) -> list["WorldRef"]:
        """Return immediate children whose leaf name matches pattern."""
        return [
            ref
            for ref in self.iterdir()
            if fnmatch.fnmatch(ref.name, pattern)
        ]

    def rglob(self, pattern: str) -> list["WorldRef"]:
        """Return descendants whose leaf name matches pattern."""
        return [
            ref
            for ref in self.walk()
            if fnmatch.fnmatch(ref.name, pattern)
        ]

    def rename(self, dst: str, *, overwrite: bool = False) -> "WorldRef":
        self._e.mv(self._path, dst, overwrite=overwrite)
        return WorldRef(self._e, dst)

    def rmtree(self, *, force: bool = False) -> int:
        return self._e.rm(self._path, recursive=True, force=force)

    @property
    def parent(self) -> "WorldRef":
        if "/" not in self._path:
            return WorldRef(self._e, "")
        return WorldRef(self._e, self._path.rsplit("/", 1)[0])

    @property
    def name(self) -> str:
        return self._path.rstrip("/").rsplit("/", 1)[-1]

    @property
    def suffix(self) -> str:
        name = self.name
        dot = name.rfind(".")
        return name[dot:] if dot > 0 else ""

    @property
    def stem(self) -> str:
        name = self.name
        dot = name.rfind(".")
        return name[:dot] if dot > 0 else name

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
    write_token = os.getenv("ELASTIK_WRITE_TOKEN")
    legacy_write_token = os.getenv("ELASTIK_TOKEN")
    if not write_token and legacy_write_token:
        warnings.warn(
            "ELASTIK_TOKEN is deprecated; rename it to ELASTIK_WRITE_TOKEN.",
            UserWarning,
            stacklevel=3,
        )
        write_token = legacy_write_token
    return (
        os.getenv("ELASTIK_APPROVE_TOKEN")
        or write_token
        or os.getenv("ELASTIK_READ_TOKEN", "")
    )


def _quote_path(path: str) -> str:
    proc_path = _canonical_proc_path(path)
    if proc_path is not None:
        return "/" + urllib.parse.quote(proc_path, safe="/")
    world = _canonical_world_name(path)
    if world == "proc" or world.startswith("proc/"):
        raise ValueError(
            "/proc is reserved; only /proc/version, /proc/worlds, /proc/du, /proc/df, /proc/pool, "
            "and /proc/audit/{path}/verify exist"
        )
    _validate_world_name(world)
    return "/" + urllib.parse.quote(world, safe="/")


def _canonical_proc_path(path: str) -> str | None:
    stripped = path.lstrip("/")
    if stripped in _PROC_ENDPOINTS:
        return stripped
    prefix = "proc/audit/"
    suffix = "/verify"
    if not stripped.startswith(prefix):
        return None
    if not stripped.endswith(suffix):
        raise ValueError("/proc/audit only exposes /proc/audit/{path}/verify")
    raw_world = stripped[len(prefix) : -len(suffix)].strip("/")
    if not raw_world:
        raise ValueError("/proc/audit verify requires a world path")
    world = _canonical_world_name(raw_world)
    _validate_world_name(world)
    return f"proc/audit/{world}/verify"


def _canonical_world_name(path: str) -> str:
    stripped = path.lstrip("/")
    first = stripped.split("/", 1)[0]
    if first in _NAMESPACES:
        return stripped
    return "home/" + stripped


def _canonical_prefix(path: str) -> str:
    if not path:
        return ""
    root = _canonical_world_name(path).rstrip("/")
    if root and root not in _RESERVED_WORLD_NAMES:
        _validate_world_name(root)
    return root


def _guard_destructive_prefix(prefix: str, operation: str, force: bool) -> None:
    if force:
        return
    if not prefix:
        raise ValueError(f"{operation}(recursive=True) would delete every path; pass force=True to confirm")
    if prefix in _NAMESPACES:
        raise ValueError(
            f"{operation}({prefix!r}, recursive=True) would delete the entire "
            f"{prefix!r} namespace; pass force=True to confirm"
        )


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
        if segment == "" or _is_dot_segment(segment):
            raise ValueError("empty, dot, and dot-dot path segments are not allowed")


def _is_dot_segment(segment: str) -> bool:
    lower = segment.lower()
    if lower.startswith("."):
        rest = lower[1:]
    elif lower.startswith("%2e"):
        rest = lower[3:]
    else:
        return False
    return rest == "" or rest in (".", "%2e")


def _set_if(headers: dict[str, str], name: str, value: str | None) -> None:
    if value is not None:
        headers[name] = str(value)


def _reject_wire_headers(headers: dict[str, str]) -> None:
    bad = [
        name
        for name in headers
        if name.strip().lower() in _FORBIDDEN_USER_HEADERS
    ]
    if bad:
        names = ", ".join(sorted(bad, key=str.lower))
        raise ValueError(
            "these headers are managed by the HTTP client and cannot be set "
            f"via headers=: {names}"
        )


# Layer 2: built-in default allow. Mirrors DEFAULT_PERSIST_HEADERS
# in core/src/http_semantics.rs. Standard representation headers
# that "travel with the bytes" -- shipped on so users get sensible
# round-trip without configuring anything.
_DEFAULT_PERSIST_HEADERS = frozenset(
    {
        "content-disposition",
        "content-encoding",
        "content-language",
        "content-md5",
        # `last-modified` intentionally NOT here -- ETag (HMAC-chained)
        # is the canonical version identifier; Last-Modified would
        # invite If-Modified-Since clients to bypass the audit-chained
        # If-None-Match flow. Mirror of the comment in
        # core/src/http_semantics.rs DEFAULT_PERSIST_HEADERS.
        "cache-control",
        "expires",
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-allow-credentials",
        "access-control-expose-headers",
        "access-control-max-age",
        "content-security-policy",
        "content-security-policy-report-only",
        "x-frame-options",
        "permissions-policy",
        "cross-origin-resource-policy",
        "cross-origin-opener-policy",
        "cross-origin-embedder-policy",
        # Browser response-policy hints outside the CSP family.
        "referrer-policy",
        "x-robots-tag",
    }
)


def _is_never_persisted_header(n: str) -> bool:
    """Layer 1: hard deny -- never persist regardless of allowlist.
    Mirrors `is_never_persisted_header` in core/src/http_semantics.rs."""
    return (
        n.startswith("sec-")
        or n.startswith("access-control-request-")
        or n.startswith("want-")
        # HTTP/2 + HTTP/3 pseudo-headers; Zipkin multi-header
        # propagation; AWS runtime injections; Cloudflare runtime
        # injections.
        or n.startswith(":")
        or n.startswith("x-b3-")
        or n.startswith("x-amzn-")
        or n.startswith("cf-")
        # Core-owned historical dereference proof headers.
        or n.startswith("x-timeline-")
        or n in _NON_PERSISTED_RESPONSE_HEADERS
    )


def _should_persist_response_header(
    name: str,
    user_allow: "HeaderAllowlist | None" = None,
    user_deny: "HeaderAllowlist | None" = None,
) -> bool:
    """Four-layer persist decision matching the Rust core:

      L1   (hard deny):    is_never_persisted_header -> False
      L1.5 (user deny):    matches user_deny          -> False
      L2   (default allow): DEFAULT_PERSIST_HEADERS    -> True
      L3   (user allow):    matches user_allow         -> True
      otherwise:                                          False

    Both `user_allow` and `user_deny` default to `None`, which
    skips that layer. The operator-side env vars are
    `ELASTIK_PERSIST_HEADERS` (allow) and `ELASTIK_DENY_HEADERS`
    (deny); see `HeaderAllowlist.from_env`.
    """
    n = name.strip().lower()
    if not n:
        return False
    if _is_never_persisted_header(n):
        return False
    if user_deny is not None and user_deny.matches(n):
        return False
    if n in _DEFAULT_PERSIST_HEADERS:
        return True
    if user_allow is not None and user_allow.matches(n):
        return True
    return False


class HeaderAllowlist:
    """User-configured allowlist for custom representation headers.
    Mirrors `crate::http_semantics::HeaderAllowlist` in the Rust core.

    Entries are normalized to lowercase. A trailing `*` makes an
    entry a prefix match (e.g. `x-my-*` matches `x-my-anything`).
    """

    __slots__ = ("_exact", "_prefixes")

    def __init__(self, exact: frozenset[str], prefixes: tuple[str, ...]) -> None:
        self._exact = exact
        self._prefixes = prefixes

    @classmethod
    def empty(cls) -> "HeaderAllowlist":
        return cls(frozenset(), ())

    @classmethod
    def parse(cls, raw: str) -> "HeaderAllowlist":
        exact: set[str] = set()
        prefixes: list[str] = []
        for entry in raw.split(","):
            entry = entry.strip().lower()
            if not entry:
                continue
            if entry.endswith("*"):
                prefix = entry[:-1]
                if prefix:
                    prefixes.append(prefix)
                continue
            exact.add(entry)
        return cls(frozenset(exact), tuple(prefixes))

    @classmethod
    def from_env(cls, env_var: str = "ELASTIK_PERSIST_HEADERS") -> "HeaderAllowlist":
        return cls.parse(os.environ.get(env_var, ""))

    def matches(self, name_lower: str) -> bool:
        return name_lower in self._exact or any(
            name_lower.startswith(p) for p in self._prefixes
        )

    def is_empty(self) -> bool:
        return not self._exact and not self._prefixes


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


def _is_debug_path(path: str) -> bool:
    return path.strip("/").startswith("tmp/debug/")


def _int_header(headers: dict[str, str], name: str) -> int | None:
    value = headers.get(name)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        lower = str(name).lower()
        redacted[lower] = "<redacted>" if _is_debug_secret_header(lower) else str(value)
    return redacted


def _is_debug_secret_header(name: str) -> bool:
    return name in _DEBUG_SECRET_HEADERS or name.endswith(_DEBUG_SECRET_SUFFIXES)


def _debug_normalize_break_on(value: int | Iterable[int] | None) -> int | set[int] | None:
    if value is None:
        return None
    if isinstance(value, int):
        return int(value)
    if isinstance(value, (str, bytes)):
        return int(value)
    return {int(item) for item in value}


def _debug_break_matches(break_on: int | set[int] | None, status: int) -> bool:
    if break_on is None:
        return False
    if isinstance(break_on, set):
        return status in break_on
    return status == int(break_on)


def _raise_for_response(resp: Response, method: str, path: str) -> None:
    _raise_error(resp.status, resp.body, method=method, path=path, headers=resp.headers)


def _raise_error(
    status: int,
    body: bytes,
    *,
    method: str = "",
    path: str = "",
    headers: dict[str, str] | None = None,
) -> None:
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
    elif status == 507:
        cls = InsufficientStorage
    elif status >= 500:
        cls = ServerError
    else:
        cls = ElastikError
    raise cls(status, body, method=method, path=path, headers=headers)


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
