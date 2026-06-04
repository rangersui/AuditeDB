"""elastik: Python client for Elastik L5.

HTTP adapter verbs:
  PUT, GET, HEAD, POST, DELETE, LISTEN.

The beginner Python surface is intentionally small:
  start, put, get, get_text, head, delete, list_paths, stop.

Quickstart (module-level calls, no instantiation):

    import elastik
    import secrets

    e = elastik.start(
        key=secrets.token_hex(32),        # HMAC audit-chain key, required
        write_token="write-token",        # T2: normal PUT/POST writes
    )
    e.put("note", "hello")                # PUT /home/note, replace body
    print(e.get_text("note"))             # "hello"
    print(e.get("note"))                  # b"hello"
    elastik.stop()                        # kills the child

Or skip the explicit start() and point at an already-running elastik
(env: `ELASTIK_URL=http://127.0.0.1:3105 ELASTIK_WRITE_TOKEN=xxx`):

    import elastik
    elastik.put("/home/note", "hello")
    print(elastik.get_text("/home/note"))

Path rule: "foo" and "/foo" both mean "/home/foo". "tmp/foo" means
"/tmp/foo" because tmp is an explicit namespace. Namespace roots and
/proc internals are reserved by the core.

put(..., project="demo") sends `X-Meta-Project: demo`. These kwargs do not
drive auth or routing. They round-trip and enter audited representation
metadata only when the core is started with `ELASTIK_PERSIST_HEADERS=x-meta-*`
or another allowlist that includes them. Standard HTTP representation headers
use named kwargs: content_type, cache_control, content_encoding,
content_language, and content_disposition.

Reactor (declarative event handlers):

    @elastik.listen("/home/inbox/*")
    def triage(body, path, meta):
        if b"urgent" in body:             # body is always first
            elastik.put(f"/home/alerts/{path.split('/')[-1]}", body)

    elastik.run()                         # blocks forever; only call after
                                          # registering at least one handler

    @elastik.on_startup
    def ready(e):
        e.put("/sys/health/worker-1", "alive")

    @elastik.on_shutdown
    def gone(e):
        e.delete("/sys/health/worker-1")

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
from typing import Any

from elastik.sdk import (
    Elastik,
    ElastikError,
    DebugHook,
    Forbidden,
    InsufficientStorage,
    NotFound,
    PayloadTooLarge,
    PreconditionFailed,
    Response,
    ServerError,
    Unauthorized,
    WorldMeta,
    WorldRef,
    WorldReader,
)
from elastik.testing import FakeElastik
from elastik.reactor import (
    listen,
    run,
    clear_routes,
    clear_lifecycle_hooks,
    unlisten,
    has_routes,
    on_startup,
    on_shutdown,
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
    decode_disk_name,
    encode_disk_name,
)
from elastik._coap_client import CoapClient, CoapResponse, get as coap_get, put as coap_put

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
    "DebugHook",
    "Unauthorized", "Forbidden", "NotFound", "PreconditionFailed",
    "PayloadTooLarge", "InsufficientStorage", "ServerError",
    "Response",
    "WorldMeta", "WorldRef", "WorldReader", "FakeElastik",
    # Reactor sugar
    "listen", "run", "clear_routes", "clear_lifecycle_hooks",
    "unlisten", "has_routes", "on_startup", "on_shutdown",
    "MoveTo", "Reply", "Archive", "Drop", "Action", "Ctx",
    # Lifecycle
    "start", "stop", "is_running", "default_url", "binary_info", "live_info",
    "load_dotenv", "show_config",
    # Trusted local execution helpers for @listen handlers
    "TrustedShellPool", "ShellPool", "ShellResult", "ShellPoolError",
    "decode_disk_name", "encode_disk_name",
    "CoapClient", "CoapResponse", "coap_get", "coap_put",
    # Module-level convenience (NumPy-shaped)
    "put", "put_text", "put_json", "put_gzip", "put_csv", "put_struct",
    "post", "get", "get_cached", "get_gzip", "get_text", "get_json",
    "get_csv", "get_struct", "head", "delete", "exists", "sizeof",
    "checksum", "is_audited", "verify", "diff", "preview", "copy",
    "ls", "tree", "rm", "mv", "du",
    "put_many", "get_many", "open", "tmp",
    "list_worlds", "list_paths", "list_keys", "request",
]

__version__ = "8.2.0"


# ── module-level singleton client ──────────────────────────────────
# Lazy: only built on first call. Lets `import elastik` succeed even if
# no server is running (you only need a server when you actually call).

_default_client: Elastik | None = None


def _client() -> Elastik:
    """Get-or-build the default singleton client.

    Pinned to ELASTIK_URL, or http://ELASTIK_HOST:ELASTIK_PORT
    (default http://127.0.0.1:3105). Bearer token from the strongest
    configured env token.

    If you spawned a child via `elastik.start(port=N, write_token=T)`, that
    call returns its own client and ALSO updates this singleton so
    module-level `elastik.put(...)` lands at your child.
    """
    global _default_client
    if _default_client is None:
        if not _has_default_client_env():
            raise RuntimeError(
                "no default elastik client is configured. Call "
                "elastik.start(key=..., write_token=...), create Elastik(url, bearer_token=...), "
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
            "ELASTIK_WRITE_TOKEN",
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
    print(f"  write:   {_mask(os.getenv('ELASTIK_WRITE_TOKEN'))}")
    print(f"  approve: {_mask(os.getenv('ELASTIK_APPROVE_TOKEN'))}")


# Re-export start() to also bind the singleton, so the next 模式 works:
#   e = elastik.start()      # works (returns client)
#   elastik.put("/x", "y")   # also works (uses the same client)
def start(
    port: int | None = None,
    host: str | None = None,
    key: str | None = None,
    read_token: str | None = None,
    write_token: str | None = None,
    approve_token: str | None = None,
    data_dir: str | None = None,
    quiet: bool = True,
    debug: bool | str = False,
) -> Elastik:
    client = _spawn_start(
        port=port,
        host=host,
        key=key,
        read_token=read_token,
        write_token=write_token,
        approve_token=approve_token,
        data_dir=data_dir,
        quiet=quiet,
        debug=debug,
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
    if_none_match: str | None = None,
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


def put_gzip(path: str, data: bytes | str, **kwargs: Any) -> dict:
    """elastik.put_gzip('/home/log.gz', 'hello') -> {'status': 201, ...}"""
    return _client().put_gzip(path, data, **kwargs)


def put_csv(path: str, rows: Any, **kwargs: Any) -> dict:
    """elastik.put_csv('/home/table.csv', rows) -> {'status': 201, ...}"""
    return _client().put_csv(path, rows, **kwargs)


def put_struct(path: str, fmt: str, *values: Any, **kwargs: Any) -> dict:
    """elastik.put_struct('/dev/sensor/0', '>ffi', ...) -> {'status': 201, ...}"""
    return _client().put_struct(path, fmt, *values, **kwargs)


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


def get_cached(path: str) -> bytes:
    """elastik.get_cached('/home/note') -> bytes using SDK ETag cache."""
    return _client().get_cached(path)


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


def get_gzip(path: str) -> bytes:
    """elastik.get_gzip('/home/log.gz') -> decompressed bytes."""
    return _client().get_gzip(path)


def get_csv(path: str) -> list[list[str]]:
    """elastik.get_csv('/home/table.csv') -> rows."""
    return _client().get_csv(path)


def get_struct(path: str, fmt: str) -> tuple[Any, ...]:
    """elastik.get_struct('/dev/sensor/0', '>ffi') -> tuple."""
    return _client().get_struct(path, fmt)


def head(path: str) -> WorldMeta:
    """elastik.head('/home/note') -> {'x-meta-...': '...'}"""
    return _client().head(path)


def delete(path: str, *, if_match: str | None = None) -> bool:
    """elastik.delete('/home/note') -> True/False"""
    return _client().delete(path, if_match=if_match)


def exists(path: str) -> bool:
    """elastik.exists('/home/note') -> bool"""
    return _client().exists(path)


def sizeof(path: str) -> int:
    """elastik.sizeof('/home/blob') -> Content-Length as int"""
    return _client().sizeof(path)


def checksum(path: str) -> str:
    """elastik.checksum('/home/blob') -> ETag"""
    return _client().checksum(path)


def is_audited(path: str) -> bool:
    """Return True when the current ETag is audit-chain backed."""
    return _client().is_audited(path)


def verify(path: str) -> bool:
    """Ask core to replay and verify the durable audit chain."""
    return _client().verify(path)


def diff(path: str, new_data: str) -> str:
    """Return a unified text diff against new_data."""
    return _client().diff(path, new_data)


def preview(path: str, **kwargs: Any) -> str:
    """Return a shortened text preview using a small Range GET."""
    return _client().preview(path, **kwargs)


def copy(src: str, dst: str, **meta: Any) -> dict:
    """elastik.copy('/home/a', '/home/b') -> {'status': 201, ...}"""
    return _client().copy(src, dst, **meta)


def ls(prefix: str = "", *, depth: int = 1) -> list[str]:
    """List paths under prefix, with virtual directory entries ending in /."""
    return _client().ls(prefix, depth=depth)


def tree(prefix: str = "") -> str:
    """Return a text tree view of stored paths under prefix."""
    return _client().tree(prefix)


def rm(path: str, *, recursive: bool = False, force: bool = False) -> int:
    """Delete one path, or all paths under a prefix when recursive=True."""
    return _client().rm(path, recursive=recursive, force=force)


def mv(
    src: str,
    dst: str,
    *,
    recursive: bool = False,
    overwrite: bool = False,
) -> int:
    """Move one path, or all paths under a prefix when recursive=True."""
    return _client().mv(src, dst, recursive=recursive, overwrite=overwrite)


def du(prefix: str = "", *, max_workers: int = 4) -> dict[str, int]:
    """Return Content-Length for each stored path under prefix."""
    return _client().du(prefix, max_workers=max_workers)


def put_many(
    items: dict[str, bytes | str],
    *,
    max_workers: int = 4,
    **kwargs: Any,
) -> dict[str, dict]:
    """PUT many paths concurrently; each item is still one HTTP request."""
    return _client().put_many(items, max_workers=max_workers, **kwargs)


def get_many(paths: list[str], *, max_workers: int = 4) -> dict[str, bytes | None]:
    """GET many paths concurrently; each path is still one HTTP request."""
    return _client().get_many(paths, max_workers=max_workers)


def open(path: str, mode: str = "rb") -> WorldReader:
    """Open a read-only file-like object backed by Range GETs."""
    return _client().open(path, mode)


def tmp(name: str = ""):
    """elastik.tmp('scratch') -> context manager yielding a /tmp path."""
    return _client().tmp(name)


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
