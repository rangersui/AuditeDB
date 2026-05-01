"""elastik — pastebin with HMAC that accidentally became a web OS.

Quickstart (NumPy-style — module-level calls, no instantiation):

    import elastik
    import secrets

    e = elastik.start(
        key=secrets.token_hex(32),        # HMAC audit-chain key, required
        token="write-token",              # T2: normal PUT/POST writes
        approve_token="admin-token",      # T3: DELETE + system namespaces
    )
    e.put("note", "hello", actor="me")    # bare paths map to /home/*
    print(e.get_text("note"))             # "hello"
    elastik.stop()                        # kills the child

Or skip the explicit start() and point at an already-running elastik
(env: `ELASTIK_URL=http://127.0.0.1:3105 ELASTIK_TOKEN=xxx`):

    import elastik
    elastik.put("/home/note", "hello")
    print(elastik.get_text("/home/note"))

Path rule: "foo" means "/home/foo". Explicit namespaces like /tmp,
/dev, and /sys are allowed for their own storage policy, but namespace
roots and /proc internals are reserved by the core.

put(..., actor="me") stores `X-Meta-Actor: me`. Standard HTTP
representation headers use named kwargs: content_type, cache_control,
content_encoding, content_language, and content_disposition.

Reactor (declarative event handlers):

    @elastik.listen("/home/inbox/*")
    def triage(body, world, meta):
        if b"urgent" in body:
            return elastik.Reply(f"/home/alerts/{world.split('/')[-1]}", body)
        return elastik.Archive()

    elastik.run()                         # blocks forever; only call after
                                          # registering at least one handler

Bundled binary lives at `elastik/_bin/elastik-core[.exe]` and is invoked
as a child process. No FFI, no compile-on-install. Same shape as
NumPy shipping precompiled C kernels.

Import note: `import elastik` loads a local `.env` once, filling only
missing environment variables. Existing process env always wins.
"""
from __future__ import annotations

import os
from typing import Any

from elastik.sdk import Elastik, ElastikError, Response
from elastik.reactor import (
    listen,
    run,
    clear_routes,
    unlisten,
    has_routes,
    MoveTo,
    Reply,
    Archive,
    Drop,
    Action,
    Ctx,
)
from elastik._spawn import (
    start,
    stop,
    is_running,
    default_url,
    binary_info,
    _load_dotenv,
)
from elastik.tools import (
    TrustedShellPool,
    ShellPool,
    ShellResult,
    ShellPoolError,
)

# Pull values from .env in CWD into os.environ once, on import. Existing
# env vars win — .env only fills holes. Module-level elastik.put/get
# read os.environ for ELASTIK_URL/TOKEN/etc., and start() reads
# ELASTIK_KEY, so the load has to happen before either path uses them.
_load_dotenv()

__all__ = [
    # Class — for users who want explicit instances
    "Elastik",
    "ElastikError",
    "Response",
    # Reactor sugar
    "listen", "run", "clear_routes", "unlisten", "has_routes",
    "MoveTo", "Reply", "Archive", "Drop", "Action", "Ctx",
    # Lifecycle
    "start", "stop", "is_running", "default_url", "binary_info",
    # Trusted local execution helpers for @listen handlers
    "TrustedShellPool", "ShellPool", "ShellResult", "ShellPoolError",
    # Module-level convenience (NumPy-shaped)
    "put", "post", "get", "get_text", "get_json",
    "head", "delete", "list_worlds", "request",
]

__version__ = "6.0.1"


# ── module-level singleton client ──────────────────────────────────
# Lazy: only built on first call. Lets `import elastik` succeed even if
# no server is running (you only need a server when you actually call).

_default_client: Elastik | None = None


def _client() -> Elastik:
    """Get-or-build the default singleton client.

    Pinned to ELASTIK_URL, or http://ELASTIK_HOST:ELASTIK_PORT
    (default http://127.0.0.1:3105). Token from ELASTIK_TOKEN.

    If you spawned a child via `elastik.start(port=N, token=T)`, that
    call returns its own client and ALSO updates this singleton so
    module-level `elastik.put(...)` lands at your child.
    """
    global _default_client
    if _default_client is None:
        if not _has_default_client_env():
            raise RuntimeError(
                "no default elastik client is configured. Call "
                "elastik.start(key=..., token=...), create Elastik(url, token), "
                "or set ELASTIK_URL/ELASTIK_HOST before using module-level "
                "elastik.put/get."
            )
        _default_client = Elastik(default_url())
    return _default_client


def _has_default_client_env() -> bool:
    return any(
        os.getenv(name)
        for name in (
            "ELASTIK_URL",
            "ELASTIK_HOST",
            "ELASTIK_PORT",
            "ELASTIK_TOKEN",
            "ELASTIK_READ_TOKEN",
            "ELASTIK_APPROVE_TOKEN",
        )
    )


def _set_default(client: Elastik) -> None:
    """Internal: rebind the singleton (called from start()).
    Public API is just: call start(), use module-level functions."""
    global _default_client
    _default_client = client


# Re-export start() to also bind the singleton, so the next 模式 works:
#   e = elastik.start()      # works (returns client)
#   elastik.put("/x", "y")   # also works (uses the same client)
_orig_start = start


def start(*args: Any, **kwargs: Any):  # type: ignore[no-redef]
    client = _orig_start(*args, **kwargs)
    _set_default(client)
    return client


# ── module-level CRUD ──────────────────────────────────────────────
# These are the "np.array([...])" of elastik. Brutal. One import,
# call.

def put(
    path: str,
    data,
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
    """elastik.put('/home/note', 'hello', actor='me') -> {'status': 201, ...}"""
    return _client().put(
        path,
        data,
        content_type=content_type,
        content_encoding=content_encoding,
        content_language=content_language,
        content_disposition=content_disposition,
        cache_control=cache_control,
        if_match=if_match,
        if_none_match=if_none_match,
        headers=headers,
        **meta,
    )


def post(
    path: str,
    data,
    *,
    if_match: str | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    """elastik.post('/home/log', 'more') -> {'status': 200, ...}"""
    return _client().post(path, data, if_match=if_match, headers=headers)


def get(
    path: str,
    *,
    range: tuple[int, int] | None = None,
    if_none_match: str | None = None,
    if_range: str | None = None,
    headers: dict[str, str] | None = None,
) -> bytes | None:
    """elastik.get('/home/note') -> bytes"""
    return _client().get(
        path,
        range=range,
        if_none_match=if_none_match,
        if_range=if_range,
        headers=headers,
    )


def get_text(
    path: str,
    *,
    encoding: str = "utf-8",
    errors: str = "strict",
    range: tuple[int, int] | None = None,
    if_none_match: str | None = None,
    if_range: str | None = None,
    headers: dict[str, str] | None = None,
) -> str | None:
    """elastik.get_text('/home/note') -> str, or None on 304"""
    return _client().get_text(
        path,
        encoding=encoding,
        errors=errors,
        range=range,
        if_none_match=if_none_match,
        if_range=if_range,
        headers=headers,
    )


def get_json(
    path: str,
    *,
    encoding: str = "utf-8",
    range: tuple[int, int] | None = None,
    if_none_match: str | None = None,
    if_range: str | None = None,
    headers: dict[str, str] | None = None,
) -> Any | None:
    """elastik.get_json('/home/config') -> decoded JSON, or None on 304"""
    return _client().get_json(
        path,
        encoding=encoding,
        range=range,
        if_none_match=if_none_match,
        if_range=if_range,
        headers=headers,
    )


def head(path: str) -> dict[str, str]:
    """elastik.head('/home/note') -> {'x-meta-...': '...'}"""
    return _client().head(path)


def delete(path: str, *, if_match: str | None = None) -> bool:
    """elastik.delete('/home/note') -> True/False"""
    return _client().delete(path, if_match=if_match)


def list_worlds() -> list[str]:
    """elastik.list_worlds() -> ['inbox/x', 'archive/y', ...]"""
    return _client().list()


def request(
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    """elastik.request('OPTIONS', '/home/x') -> Response"""
    return _client().request(method, path, body, headers)
