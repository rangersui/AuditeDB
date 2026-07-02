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
    HeaderAllowlist,
    NotFound,
    Response,
    TimelineCoordinate,
    TimelineMeta,
    TimelineReadResult,
    WorldMeta,
    _body_bytes,
    _canonical_world_name,
    _reject_wire_headers,
    _should_persist_response_header,
    _validate_world_name,
)


class FakeElastik(Elastik):
    """In-memory SDK-compatible fake for handler/unit tests.

    Mirrors the Rust core's four-layer header persistence policy
    (L1 hard deny, L1.5 user deny, L2 default allow, L3 user allow).
    By default reads `ELASTIK_PERSIST_HEADERS` and `ELASTIK_DENY_HEADERS`
    from the environment so SDK unit tests behave the same way the
    real core does under the same env. Pass
    `persist_allow=` / `persist_deny=` to override per fixture
    without touching the environment.
    """

    def __init__(
        self,
        *,
        persist_allow: HeaderAllowlist | None = None,
        persist_deny: HeaderAllowlist | None = None,
    ):
        super().__init__("fake://elastik", bearer_token="fake")
        self._store: dict[str, tuple[bytes, WorldMeta]] = {}
        self._persist_allow = (
            persist_allow
            if persist_allow is not None
            else HeaderAllowlist.from_env("ELASTIK_PERSIST_HEADERS")
        )
        self._persist_deny = (
            persist_deny
            if persist_deny is not None
            else HeaderAllowlist.from_env("ELASTIK_DENY_HEADERS")
        )

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
        if_none_match: str | None = None,
        create_only: bool = False,
        headers: dict[str, str] | None = None,
        **meta: Any,
    ) -> dict:
        body = _body_bytes(data, "put")
        world = self._world(path)
        _reject_wire_headers(headers or {})
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
            if _should_persist_response_header(
                key, self._persist_allow, self._persist_deny
            ):
                headers[key] = value  # type: ignore[literal-required]
        # `**meta` becomes X-Meta-* headers. Under the v7.2 default-deny
        # policy these are also custom representation headers and need
        # to pass the same filter; otherwise FakeElastik would lie
        # about production behavior. Operators using FakeElastik in
        # tests must export `ELASTIK_PERSIST_HEADERS=x-meta-*` to
        # mirror the production opt-in (or pass `persist_allow=` to
        # the constructor).
        for key, value in meta.items():
            meta_key = f"x-meta-{key.replace('_', '-').lower()}"
            if _should_persist_response_header(
                meta_key, self._persist_allow, self._persist_deny
            ):
                headers[meta_key] = str(value)  # type: ignore[literal-required]
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

    def read_timeline(self, coordinate: TimelineCoordinate) -> TimelineReadResult:
        if not isinstance(coordinate, TimelineCoordinate):
            raise TypeError(
                "read_timeline() requires TimelineCoordinate; "
                "use TimelineCoordinate.from_event(event)"
            )
        raise NotImplementedError(
            "FakeElastik does not retain audit timeline bodies; use black-box tests"
        )

    def get_timeline(self, coordinate: TimelineCoordinate) -> bytes:
        return self.read_timeline(coordinate).body

    def head_timeline(self, coordinate: TimelineCoordinate) -> TimelineMeta:
        if not isinstance(coordinate, TimelineCoordinate):
            raise TypeError(
                "head_timeline() requires TimelineCoordinate; "
                "use TimelineCoordinate.from_event(event)"
            )
        raise NotImplementedError(
            "FakeElastik does not retain audit timeline bodies; use black-box tests"
        )

    def verify(self, path: str) -> bool:
        self.head(path)
        return False

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
        _reject_wire_headers(headers or {})
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
