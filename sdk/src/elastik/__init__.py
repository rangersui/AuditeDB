"""elastik — pastebin with HMAC that accidentally became a web OS.

Quickstart (NumPy-style — module-level calls, no instantiation):

    import elastik

    e = elastik.start(token="x")          # spawns the bundled rust core
    e.put("/home/note", "hello")          # PUT
    print(e.get("/home/note"))            # bytes back
    elastik.stop()                        # kills the child

Or skip the explicit start() and point at an already-running elastik
(env: `ELASTIK_URL=http://127.0.0.1:3105 ELASTIK_TOKEN=xxx`):

    import elastik
    elastik.put("/home/note", "hello")
    print(elastik.get("/home/note"))

Reactor (declarative event handlers — see Elastik-core/README.md §L2):

    @elastik.listen("/home/inbox/*")
    def triage(body, world, meta):
        if b"urgent" in body:
            return elastik.Reply(f"/home/alerts/{world.split('/')[-1]}", body)
        return elastik.Archive()

Bundled binary lives at `elastik/_bin/elastik-core[.exe]` and is invoked
as a child process. No FFI, no compile-on-install. Same shape as
NumPy shipping precompiled C kernels.
"""
from __future__ import annotations

from typing import Any

from elastik.sdk import Elastik, ElastikError, Response
from elastik.reactor import (
    listen,
    run,
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
    "listen", "run", "MoveTo", "Reply", "Archive", "Drop", "Action", "Ctx",
    # Lifecycle
    "start", "stop", "is_running", "default_url", "binary_info",
    # Trusted local execution helpers for @listen handlers
    "TrustedShellPool", "ShellPool", "ShellResult", "ShellPoolError",
    # Module-level convenience (NumPy-shaped)
    "put", "post", "get", "head", "delete", "list_worlds", "request",
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
        _default_client = Elastik(default_url())
    return _default_client


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
