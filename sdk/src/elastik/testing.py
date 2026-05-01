"""Testing helpers for elastik SDK users.

FakeElastik is intentionally small: it is a local in-memory stand-in for
unit tests, not a replacement for the Rust core. Use the black-box tests
when you need wire-level HTTP semantics.
"""
from __future__ import annotations

import hashlib
from typing import Any

from elastik.sdk import (
    Elastik,
    NotFound,
    Response,
    WorldMeta,
    _body_bytes,
    _canonical_world_name,
    _validate_world_name,
)


class FakeElastik(Elastik):
    """In-memory SDK-compatible fake for handler/unit tests."""

    def __init__(self):
        self.url = "fake://elastik"
        self.token = "fake"
        self._etag_cache: dict[str, tuple[str, bytes]] = {}
        self._store: dict[str, tuple[bytes, WorldMeta]] = {}

    def __repr__(self) -> str:
        return f"<FakeElastik {len(self._store)} paths>"

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
        if_none_match: str | bool | None = None,
        create_only: bool = False,
        headers: dict[str, str] | None = None,
        **meta: Any,
    ) -> dict:
        body = _body_bytes(data, "put")
        world = self._world(path)
        wire_headers = {k.lower(): v for k, v in (headers or {}).items()}
        if content_type is None:
            content_type = wire_headers.get(
                "content-type",
                (
                    "text/plain; charset=utf-8"
                    if isinstance(data, str)
                    else "application/octet-stream"
                ),
            )
        headers: WorldMeta = {
            "etag": _fake_etag(body),
            "content-type": content_type,
            "content-length": str(len(body)),
            "accept-ranges": "bytes",
        }
        _set_if(headers, "content-encoding", content_encoding)
        _set_if(headers, "content-language", content_language)
        _set_if(headers, "content-disposition", content_disposition)
        _set_if(headers, "cache-control", cache_control)
        for key, value in wire_headers.items():
            if key.startswith("x-meta-"):
                headers[key] = value  # type: ignore[literal-required]
        for key, value in meta.items():
            headers[f"x-meta-{key.replace('_', '-').lower()}"] = str(value)  # type: ignore[literal-required]
        self._store[world] = (body, headers)
        self._etag_cache[world] = (headers["etag"], body)
        return {"status": 201, "etag": headers["etag"]}

    def post(self, path: str, data: bytes | str, **_kwargs: Any) -> dict:
        world = self._world(path)
        if world not in self._store:
            raise NotFound(404, b"not found", method="POST", path=path)
        old, headers = self._store[world]
        body = old + _body_bytes(data, "post")
        headers = dict(headers)
        headers["etag"] = _fake_etag(body)
        headers["content-length"] = str(len(body))
        self._store[world] = (body, headers)  # type: ignore[assignment]
        self._etag_cache.pop(world, None)
        return {"status": 200, "etag": headers["etag"]}

    def get(self, path: str, **_kwargs: Any) -> bytes:
        world = self._world(path)
        try:
            body, headers = self._store[world]
        except KeyError:
            raise NotFound(404, b"not found", method="GET", path=path) from None
        if _kwargs.get("if_none_match") == headers.get("etag"):
            return None  # type: ignore[return-value]
        byte_range = _kwargs.get("range")
        if byte_range is not None:
            start, end = byte_range
            return body[start : end + 1]
        return body

    def head(self, path: str) -> WorldMeta:
        world = self._world(path)
        try:
            return dict(self._store[world][1])  # type: ignore[return-value]
        except KeyError:
            raise NotFound(404, b"not found", method="HEAD", path=path) from None

    def delete(self, path: str, **_kwargs: Any) -> bool:
        world = self._world(path)
        self._etag_cache.pop(world, None)
        return self._store.pop(world, None) is not None

    def list(self) -> list[str]:
        return sorted(self._store)

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        method = method.upper()
        if method == "GET":
            try:
                return Response(200, self.head(path), self.get(path))
            except NotFound as e:
                return Response(e.status, {}, e.body)
        if method == "HEAD":
            try:
                return Response(200, self.head(path), b"")
            except NotFound as e:
                return Response(e.status, {}, e.body)
        if method == "PUT":
            result = self.put(path, body or b"", headers=headers or {})
            return Response(int(result["status"]), {"etag": result["etag"]}, b"")
        if method == "DELETE":
            return Response(204 if self.delete(path) else 404, {}, b"")
        return Response(405, {"allow": "GET, HEAD, PUT, POST, DELETE"}, b"")

    def _world(self, path: str) -> str:
        world = _canonical_world_name(path)
        _validate_world_name(world)
        return world


def _fake_etag(body: bytes) -> str:
    return "fake-" + hashlib.sha256(body).hexdigest()


def _set_if(headers: dict[str, str], name: str, value: str | None) -> None:
    if value is not None:
        headers[name] = value
