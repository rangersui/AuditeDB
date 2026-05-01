"""elastik — tiny HTTP byte store + event stream.

The first-class surface is intentionally small:
  start, put, get, get_text, head, delete, list_paths, stop.

Quickstart (module-level calls, no instantiation):

    import elastik
    import secrets

    e = elastik.start(
        key=secrets.token_hex(32),        # HMAC audit-chain key, required
        token="write-token",              # T2: normal PUT/POST writes
    )
    e.put("note", "hello")                # PUT /home/note, replace body
    print(e.get_text("note"))             # "hello"
    print(e.get("note"))                  # b"hello"
    elastik.stop()                        # kills the child

Or skip the explicit start() and point at an already-running elastik
(env: `ELASTIK_URL=http://127.0.0.1:3105 ELASTIK_TOKEN=xxx`):

    import elastik
    elastik.put("/home/note", "hello")
    print(elastik.get_text("/home/note"))

Path rule: "foo" and "/foo" both mean "/home/foo". "tmp/foo" means
"/tmp/foo" because tmp is an explicit namespace. Namespace roots and
/proc internals are reserved by the core.

put(..., project="demo") stores `X-Meta-Project: demo`. These kwargs
are plain metadata, not auth or audit fields. Standard HTTP
representation headers use named kwargs: content_type, cache_control,
content_encoding, content_language, and content_disposition.

Reactor (declarative event handlers):

    @elastik.listen("/home/inbox/*")
    def triage(body, path, meta):
        if b"urgent" in body:             # body is always first
            elastik.put(f"/home/alerts/{path.split('/')[-1]}", body)

    elastik.run()                         # blocks forever; only call after
                                          # registering at least one handler

Handlers may either do side effects directly (normal Python) or return
Action objects like Reply/Archive/MoveTo/Drop for declarative routing.
`world` is accepted as an older name for the same value as `path`.

Bundled binary lives at `elastik/_bin/elastik-core[.exe]` and is invoked
as a child process. No FFI, no compile-on-install. Same shape as
NumPy shipping precompiled C kernels.

Import note: `import elastik` loads a local `.env` once, filling only
missing environment variables. Existing process env always wins. Set
ELASTIK_NO_DOTENV=1 before import to disable this and call
elastik.load_dotenv(path) yourself.
"""
from __future__ import annotations

import os
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from elastik.sdk import (
    Elastik,
    ElastikError,
    Forbidden,
    NotFound,
    PayloadTooLarge,
    PreconditionFailed,
    Response,
    ServerError,
    Unauthorized,
    WorldMeta,
)
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
    start as _spawn_start,
    stop,
    is_running,
    default_url,
    binary_info,
    live_info,
    _load_dotenv as load_dotenv,
)
from elastik.tools import (
    TrustedShellPool,
    ShellPool,
    ShellResult,
    ShellPoolError,
)

# Pull values from .env in CWD into os.environ once, on import unless
# ELASTIK_NO_DOTENV=1 is set. Existing env vars win — .env only fills holes.
# Users who want explicit control can set ELASTIK_NO_DOTENV=1 and call
# elastik.load_dotenv(path) themselves.
if os.getenv("ELASTIK_NO_DOTENV") != "1":
    load_dotenv()

__all__ = [
    "__version__",
    # Class — for users who want explicit instances
    "Elastik",
    "ElastikError",
    "Unauthorized", "Forbidden", "NotFound", "PreconditionFailed",
    "PayloadTooLarge", "ServerError",
    "Response",
    "WorldMeta",
    # Reactor sugar
    "listen", "run", "clear_routes", "unlisten", "has_routes",
    "MoveTo", "Reply", "Archive", "Drop", "Action", "Ctx",
    # Lifecycle
    "start", "stop", "is_running", "default_url", "binary_info", "live_info",
    "load_dotenv", "show_config",
    # Trusted local execution helpers for @listen handlers
    "TrustedShellPool", "ShellPool", "ShellResult", "ShellPoolError",
    # Module-level convenience (NumPy-shaped)
    "put", "put_text", "put_json", "post", "get", "get_text", "get_json",
    "head", "delete", "list_worlds", "list_paths", "list_keys", "request",
]

try:
    __version__ = version("elastik")
except PackageNotFoundError:
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


def _mask(value: str | None) -> str:
    if not value:
        return "<unset>"
    if len(value) <= 8:
        return "<set>"
    return f"{value[:4]}...{value[-4:]}"


def show_config() -> None:
    """Print the SDK/core configuration useful for bug reports."""
    info = binary_info()
    live = live_info()
    url = live.get("url", default_url())
    url_label = " (live)" if "url" in live else " (default)"
    data = live.get("data_dir") or os.getenv("ELASTIK_DATA", "<default ./data>")
    data_label = " (live)" if "data_dir" in live else " (default)"
    print(f"elastik {__version__}")
    print(f"  core:    {info.get('path', '<unknown>')}")
    print(f"  exists:  {info.get('exists', '<unknown>')}")
    print(f"  url:     {url}{url_label}")
    print(f"  data:    {data}{data_label}")
    print(f"  running: {is_running()}")
    print(f"  key:     {_mask(os.getenv('ELASTIK_KEY'))}")
    print(f"  read:    {_mask(os.getenv('ELASTIK_READ_TOKEN'))}")
    print(f"  write:   {_mask(os.getenv('ELASTIK_TOKEN'))}")
    print(f"  approve: {_mask(os.getenv('ELASTIK_APPROVE_TOKEN'))}")


# Re-export start() to also bind the singleton, so the next 模式 works:
#   e = elastik.start()      # works (returns client)
#   elastik.put("/x", "y")   # also works (uses the same client)
def start(
    port: int | None = None,
    host: str | None = None,
    key: str | None = None,
    read_token: str | None = None,
    token: str | None = None,
    approve_token: str | None = None,
    data_dir: str | None = None,
    quiet: bool = True,
) -> Elastik:
    client = _spawn_start(
        port=port,
        host=host,
        key=key,
        read_token=read_token,
        token=token,
        approve_token=approve_token,
        data_dir=data_dir,
        quiet=quiet,
    )
    _set_default(client)
    return client


# ── module-level CRUD ──────────────────────────────────────────────
# These are the "np.array([...])" of elastik. Brutal. One import,
# call.

def put(
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
        create_only=create_only,
        headers=headers,
        **meta,
    )


def put_text(
    path: str,
    text: str,
    *,
    encoding: str = "utf-8",
    **kwargs: Any,
) -> dict:
    """elastik.put_text('/home/note', 'hello') -> {'status': 201, ...}"""
    return _client().put_text(path, text, encoding=encoding, **kwargs)


def put_json(
    path: str,
    value: Any,
    *,
    ensure_ascii: bool = False,
    **kwargs: Any,
) -> dict:
    """elastik.put_json('/home/config', {'ok': True}) -> {'status': 201, ...}"""
    return _client().put_json(path, value, ensure_ascii=ensure_ascii, **kwargs)


def post(
    path: str,
    data: bytes | str,
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


def head(path: str) -> WorldMeta:
    """elastik.head('/home/note') -> {'x-meta-...': '...'}"""
    return _client().head(path)


def delete(path: str, *, if_match: str | None = None) -> bool:
    """elastik.delete('/home/note') -> True/False"""
    return _client().delete(path, if_match=if_match)


def list_worlds() -> list[str]:
    """Older name for list_paths()."""
    import warnings

    warnings.warn(
        "list_worlds() is renamed list_paths(); list_worlds remains as a compatibility alias",
        DeprecationWarning,
        stacklevel=2,
    )
    return _client().list()


def list_paths() -> list[str]:
    """elastik.list_paths() -> stored paths/keys."""
    return _client().list_paths()


def list_keys() -> list[str]:
    """elastik.list_keys() -> stored paths/keys."""
    return _client().list_keys()


def request(
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    """elastik.request('OPTIONS', '/home/x') -> Response"""
    return _client().request(method, path, body, headers)
