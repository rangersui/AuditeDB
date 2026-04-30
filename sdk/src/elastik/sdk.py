"""L1 — atom bindings for elastik-core.

This is the SDK. It is not the frontend. The frontend is what you build
*with* these atoms (see sdk.reactor + your own scripts).

`e.put("/home/x", data)` is "Lumos" — a declaration. Underneath, the
runtime may store, audit, fan out, broadcast, cache, log. The caller
says three words.

stdlib only — no httpx, no requests. urllib + json. ~80 lines.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class ElastikError(Exception):
    def __init__(self, status: int, body: bytes):
        self.status = status
        self.body = body
        super().__init__(f"elastik {status}: {body[:200]!r}")


class Elastik:
    """Pythonic bindings to elastik-core's HTTP atoms.

    >>> e = Elastik("http://localhost:3105", token="t2")
    >>> e.put("/home/note", b"hello")           # PUT, returns dict
    >>> e.get("/home/note", raw=True)           # GET ?raw, returns bytes
    >>> e.head("/home/note")                    # HEAD, returns headers dict
    >>> e.delete("/home/note")                  # DELETE
    >>> e.list()                                # GET /proc/worlds
    """

    def __init__(self, url: str | None = None, token: str | None = None):
        if url is None:
            from elastik._spawn import default_url
            url = default_url()
        if token is None:
            token = os.getenv("ELASTIK_TOKEN", "")
        self.url = url.rstrip("/")
        self.token = token

    # ── atoms ──────────────────────────────────────────────────────

    def put(self, path: str, data: bytes | str, **meta: Any) -> dict:
        """PUT body to path. kwargs become X-Meta-* headers."""
        body = data.encode("utf-8") if isinstance(data, str) else data
        headers = {f"X-Meta-{k.replace('_', '-')}": str(v) for k, v in meta.items()}
        return self._json("PUT", path, body, headers)

    def get(self, path: str, raw: bool = False) -> Any:
        """GET path. raw=True returns bytes; otherwise the JSON envelope."""
        suffix = "?raw" if raw else ""
        status, _, body = self._raw("GET", path + suffix)
        if status == 404:
            raise ElastikError(404, body)
        if status >= 400:
            raise ElastikError(status, body)
        if raw:
            return body
        return json.loads(body)

    def head(self, path: str) -> dict[str, str]:
        """HEAD path. Returns headers as a lowercased dict."""
        status, headers, _ = self._raw("HEAD", path)
        if status == 404:
            raise ElastikError(404, b"")
        return headers

    def delete(self, path: str) -> bool:
        """DELETE path. Returns True on 204, False on 404."""
        status, _, _ = self._raw("DELETE", path)
        if status == 204:
            return True
        if status == 404:
            return False
        raise ElastikError(status, b"")

    def list(self) -> list[str]:
        """GET /proc/worlds. Returns list of world names."""
        status, _, body = self._raw("GET", "/proc/worlds")
        if status >= 400:
            raise ElastikError(status, body)
        return [w["name"] for w in json.loads(body)]

    def shaped(self, path: str, accept: str = "text/html",
               intent: str = "") -> bytes:
        """GET /shaped/<path> with Accept + X-Semantic-Intent. Forwards
        to whatever shaper sidecar elastik routes /shaped/ to. Bytes back."""
        headers = {"Accept": accept}
        if intent:
            headers["X-Semantic-Intent"] = intent
        status, _, body = self._raw("GET", f"/shaped{path}", headers=headers)
        if status >= 400:
            raise ElastikError(status, body)
        return body

    # ── transport ─────────────────────────────────────────────────

    def _raw(self, method: str, path: str, body: bytes | None = None,
             headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        url = self.url + (path if path.startswith("/") else "/" + path)
        h = dict(headers or {})
        if self.token:
            h.setdefault("Authorization", f"Bearer {self.token}")
        req = urllib.request.Request(url, data=body, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return (
                    r.status,
                    {k.lower(): v for k, v in r.headers.items()},
                    r.read(),
                )
        except urllib.error.HTTPError as e:
            return (
                e.code,
                {k.lower(): v for k, v in (e.headers or {}).items()},
                e.read() if e.fp else b"",
            )

    def _json(self, method: str, path: str, body: bytes | None,
              headers: dict[str, str] | None = None) -> dict:
        status, _, raw = self._raw(method, path, body, headers)
        if status >= 400:
            raise ElastikError(status, raw)
        try:
            return json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            return {"raw": raw}
