"""elastik — pastebin with HMAC that accidentally became a web OS.

Quickstart (NumPy-style — module-level calls, no instantiation):

    import elastik

    e = elastik.start(token="x")          # spawns the bundled rust core
    e.put("/home/note", "hello")          # PUT
    print(e.get("/home/note", raw=True))  # bytes back
    elastik.stop()                        # kills the child

Or skip the explicit start() and point at an already-running elastik
(env: `ELASTIK_URL=http://127.0.0.1:3105 ELASTIK_TOKEN=xxx`):

    import elastik
    elastik.put("/home/note", "hello")
    print(elastik.get("/home/note", raw=True))

Reactor (declarative event handlers — see Elastik-core/README.md §L2):

    @elastik.listen("/home/inbox/*")
    def triage(body, world, meta):
        if b"urgent" in body:
            return elastik.Reply(f"/home/alerts/{world.split('/')[-1]}", body)
        return elastik.Archive()

    elastik.serve(port=3200)              # runs as fanout sidecar

Bundled binary lives at `elastik/_bin/elastik-core[.exe]` and is invoked
as a child process. No FFI, no compile-on-install. Same shape as
NumPy shipping precompiled C kernels.
"""
from __future__ import annotations

import os
from typing import Any

from elastik.sdk import Elastik, ElastikError
from elastik.reactor import (
    listen,
    MoveTo,
    Reply,
    Archive,
    Drop,
    Action,
    Ctx,
    finalize,
    serve,
)
from elastik._spawn import (
    start,
    stop,
    is_running,
    default_url,
    binary_info,
)

__all__ = [
    # Class — for users who want explicit instances
    "Elastik",
    "ElastikError",
    # Reactor sugar
    "listen", "MoveTo", "Reply", "Archive", "Drop", "Action", "Ctx",
    "finalize", "serve",
    # Lifecycle
    "start", "stop", "is_running", "default_url", "binary_info",
    # Module-level convenience (NumPy-shaped)
    "put", "get", "head", "delete", "list_worlds", "shaped",
]

__version__ = "0.0.2"


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
        _default_client = Elastik(
            default_url(),
            token=os.getenv("ELASTIK_TOKEN", ""),
        )
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

def put(path: str, data, **meta: Any) -> dict:
    """elastik.put('/home/note', 'hello', actor='me') -> {'ok': True, ...}"""
    return _client().put(path, data, **meta)


def get(path: str, raw: bool = False) -> Any:
    """elastik.get('/home/note', raw=True) -> bytes
       elastik.get('/home/note')           -> dict envelope"""
    return _client().get(path, raw=raw)


def head(path: str) -> dict[str, str]:
    """elastik.head('/home/note') -> {'x-meta-...': '...'}"""
    return _client().head(path)


def delete(path: str) -> bool:
    """elastik.delete('/home/note') -> True/False"""
    return _client().delete(path)


def list_worlds() -> list[str]:
    """elastik.list_worlds() -> ['inbox/x', 'archive/y', ...]"""
    return _client().list()


def shaped(path: str, accept: str = "text/html", intent: str = "") -> bytes:
    """elastik.shaped('/home/x', accept='text/html', intent='render as card')"""
    return _client().shaped(path, accept=accept, intent=intent)
