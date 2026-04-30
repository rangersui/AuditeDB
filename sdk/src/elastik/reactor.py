"""L2 — declarative reactor sugar over L1 atoms.

The reactor is the "千人千面 in one event loop" pattern, made writable.
Two deployment shapes; same `@listen` syntax for both:

  1. **Plugin** (in-process with elastik-python).
     Write a plugin file, end with `ROUTES, handle = finalize()`.
     elastik-python's plugin runtime hot-loads it.

  2. **Sidecar** (separate process; elastik-core fans out via HTTP).
     Run `python my_agent.py` which calls `serve(host, port)`.
     Configure elastik-core with
     `ELASTIK_LISTENERS="/home/inbox/*=http://my-agent:port"`.

Both shapes match the manifesto: code lives in one place; the runtime
decides how to invoke it. The handler is pure — input -> Action.

Action classes describe intent. Execution happens in the reactor (not
in the handler). This is the Harvard split inside the reactor itself:
handler = judgment, executor = side effects.

stdlib + sdk.elastik. ~200 lines.
"""
from __future__ import annotations

import http.server
import inspect
import json
import threading
from typing import Any, Callable

from elastik.sdk import Elastik
from elastik._spawn import default_url


# ── registration ────────────────────────────────────────────────────

_routes: dict[str, Callable[..., Any]] = {}


def listen(pattern: str):
    """Register a handler for a path pattern.

    Pattern is prefix-with-trailing-`*`:
      "/home/inbox/*"  matches "/home/inbox/alice/abc"
      "/home/foo"      matches exactly "/home/foo"
      "*"              matches everything

    The handler signature is introspected. It receives `body` (bytes)
    plus any of these named kwargs it asks for:
      world    str    — the URL path that was written
      version  int    — the new version after the write
      pattern  str    — the registered pattern that matched
      meta     dict   — X-Meta-* headers as a flat dict
      e        Elastik— SDK client, pre-bound to the configured backend

    Return: an Action, a list of Actions, or None.
    """
    def deco(func: Callable[..., Any]) -> Callable[..., Any]:
        _routes[pattern] = func
        return func
    return deco


def _matches(pattern: str, path: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    return path == pattern


# ── actions (intent objects) ───────────────────────────────────────

class Action:
    """Base. Subclasses describe intent; .execute(ctx) does the work."""

    def execute(self, ctx: Ctx) -> None:
        raise NotImplementedError


class MoveTo(Action):
    """Write to dest, then delete the source."""

    def __init__(self, dest: str, **meta: Any):
        self.dest = dest
        self.meta = meta

    def execute(self, ctx: Ctx) -> None:
        ctx.e.put(self.dest, ctx.body, **self.meta)
        ctx.e.delete(ctx.world)


class Reply(Action):
    """Write a new world. Source untouched."""

    def __init__(self, dest: str, body: bytes | str, **meta: Any):
        self.dest = dest
        self.body = body
        self.meta = meta

    def execute(self, ctx: Ctx) -> None:
        ctx.e.put(self.dest, self.body, **self.meta)


class Archive(Action):
    """Move source under prefix/<basename>."""

    def __init__(self, prefix: str = "/home/archive/"):
        self.prefix = prefix

    def execute(self, ctx: Ctx) -> None:
        name = ctx.world.rstrip("/").rsplit("/", 1)[-1] or "anon"
        ctx.e.put(self.prefix.rstrip("/") + "/" + name, ctx.body)
        ctx.e.delete(ctx.world)


class Drop(Action):
    """Delete the source. No reply."""

    def execute(self, ctx: Ctx) -> None:
        ctx.e.delete(ctx.world)


# ── context passed to handlers + actions ────────────────────────────

class Ctx:
    __slots__ = ("body", "world", "version", "pattern", "meta", "e")

    def __init__(self, body: bytes, world: str, version: int,
                 pattern: str, meta: dict[str, str], e: Elastik):
        self.body = body
        self.world = world
        self.version = version
        self.pattern = pattern
        self.meta = meta
        self.e = e


# ── core dispatch (used by both plugin and sidecar shape) ──────────

def _call_handler(handler: Callable[..., Any], ctx: Ctx) -> Any:
    """Pass only the kwargs the handler signature asks for."""
    sig = inspect.signature(handler)
    accepts = sig.parameters.keys()
    candidates = {
        "world": ctx.world,
        "version": ctx.version,
        "pattern": ctx.pattern,
        "meta": ctx.meta,
        "e": ctx.e,
    }
    kwargs = {k: v for k, v in candidates.items() if k in accepts}
    has_var = any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )
    if has_var:
        kwargs = candidates
    return handler(ctx.body, **kwargs)


def _run_action(result: Any, ctx: Ctx) -> None:
    if result is None:
        return
    if isinstance(result, Action):
        result.execute(ctx)
        return
    if isinstance(result, (list, tuple)):
        for item in result:
            if isinstance(item, Action):
                item.execute(ctx)
        return
    # Anything else — ignored. Reactor is forgiving by design; the
    # PUT response shouldn't fail because a handler returned a string.


def _dispatch(world: str, body: bytes, version: int, meta: dict[str, str],
              e: Elastik) -> None:
    """Find every matching handler, run it, execute its action(s)."""
    for pattern, handler in _routes.items():
        if not _matches(pattern, world):
            continue
        ctx = Ctx(body=body, world=world, version=version,
                  pattern=pattern, meta=meta, e=e)
        try:
            result = _call_handler(handler, ctx)
            _run_action(result, ctx)
        except Exception as ex:
            print(f"  reactor [{pattern}] raised: "
                  f"{type(ex).__name__}: {ex}", flush=True)


# ── shape 1: emit ROUTES + handle for elastik-python plugin runtime ─

def finalize(elastik_url: str | None = None,
             token: str | None = None) -> tuple[list[str], Callable]:
    """Return (ROUTES, handle) for an elastik-python plugin.

    Use at the bottom of a plugin file:

        from sdk.reactor import listen, MoveTo, finalize
        @listen("/home/inbox/*")
        def triage(body): return MoveTo("/home/archive/")
        ROUTES, handle = finalize()
    """
    e = Elastik(elastik_url or default_url(), token=token)
    routes = list(_routes.keys())

    async def handle(method: str, body: Any, params: dict) -> dict:
        if method != "PUT":
            return {"_status": 200, "ok": True, "skipped": method}
        scope = params.get("_scope", {})
        world = scope.get("path", "")
        version = int(scope.get("_version", 0))
        meta = {
            k.decode().lower(): v.decode()
            for k, v in scope.get("headers", [])
            if k.decode().lower().startswith("x-meta-")
        }
        body_bytes = body if isinstance(body, (bytes, bytearray)) else \
            (body or "").encode("utf-8")
        _dispatch(world, body_bytes, version, meta, e)
        return {"_status": 200, "ok": True}

    return routes, handle


# ── shape 2: standalone sidecar HTTP server ────────────────────────

def serve(host: str = "127.0.0.1", port: int = 3200,
          elastik_url: str | None = None,
          token: str | None = None) -> None:
    """Run an HTTP server that elastik-core's fanout posts to.

    elastik-core sends:
      POST /<anything>
      X-Elastik-World: <url path>
      X-Elastik-Version: <int>
      X-Elastik-Pattern: <matched pattern>
      X-Meta-*: <forwarded>
      body: the original PUT body
    """
    elastik_url = elastik_url or default_url()
    e = Elastik(elastik_url, token=token)
    state = {"e": e}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n)
            world = self.headers.get("X-Elastik-World", "")
            version = int(self.headers.get("X-Elastik-Version", "0") or "0")
            pattern = self.headers.get("X-Elastik-Pattern", "")
            meta = {
                k.lower(): v for k, v in self.headers.items()
                if k.lower().startswith("x-meta-")
            }
            # reactor matches all registered patterns against the world,
            # not just the one elastik-core sent (X-Elastik-Pattern is
            # informational — one elastik-core listener URL may serve
            # many @listen patterns in one process).
            _dispatch(world, body, version, meta, state["e"])
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        # Quiet by default
        def log_message(self, *_): pass

    srv = http.server.ThreadingHTTPServer((host, port), Handler)
    print(f"reactor sidecar listening on http://{host}:{port}/", flush=True)
    print(f"  elastik backend: {elastik_url}", flush=True)
    print(f"  registered patterns: {list(_routes.keys())}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
