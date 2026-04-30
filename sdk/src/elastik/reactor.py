"""Declarative reactor vocabulary over elastik HTTP atoms.

The Rust core does not know about plugins or callbacks. This
module is SDK-side vocabulary only: register handlers, describe actions,
and let `run(...)` feed core SSE events into `_dispatch(...)`. Other
adapters can still feed polling, filesystem notifications, queues, or
anything else that can provide `world`, `body`, `etag`, and `meta`.
"""
from __future__ import annotations

import inspect
import sys
import time
from typing import Any, Callable

from elastik.sdk import Elastik


_routes: dict[str, Callable[..., Any]] = {}


def listen(pattern: str):
    """Register a handler for a path pattern.

    Pattern is prefix-with-trailing-`*`:
      "/home/inbox/*"  matches "/home/inbox/alice/abc"
      "/home/foo"      matches exactly "/home/foo"
      "*"              matches everything

    The handler receives `body` plus any named kwargs it asks for:
    `world`, `etag`, `pattern`, `meta`, `e`.
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


class Action:
    """Base class for intent objects."""

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


class Ctx:
    __slots__ = ("body", "world", "etag", "pattern", "meta", "e", "method", "event")

    def __init__(
        self,
        body: bytes,
        world: str,
        etag: str,
        pattern: str,
        meta: dict[str, str],
        e: Elastik,
        method: str = "",
        event: dict[str, str] | None = None,
    ):
        self.body = body
        self.world = world
        self.etag = etag
        self.pattern = pattern
        self.meta = meta
        self.e = e
        self.method = method
        self.event = event or {}


def _call_handler(handler: Callable[..., Any], ctx: Ctx) -> Any:
    sig = inspect.signature(handler)
    accepts = sig.parameters.keys()
    candidates = {
        "world": ctx.world,
        "etag": ctx.etag,
        "pattern": ctx.pattern,
        "meta": ctx.meta,
        "e": ctx.e,
        "method": ctx.method,
        "event": ctx.event,
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


def _dispatch(
    world: str,
    body: bytes,
    etag: str,
    meta: dict[str, str],
    e: Elastik,
    method: str = "",
    event: dict[str, str] | None = None,
) -> None:
    """Run registered handlers. Transport adapters call this."""
    for pattern, handler in _routes.items():
        if not _matches(pattern, world):
            continue
        ctx = Ctx(
            body=body,
            world=world,
            etag=etag,
            pattern=pattern,
            meta=meta,
            e=e,
            method=method,
            event=event,
        )
        result = _call_handler(handler, ctx)
        _run_action(result, ctx)


def run(e: Elastik | None = None, reconnect: bool = True, retry_s: float = 1.0) -> None:
    """Consume core SSE and dispatch registered @listen handlers.

    One connection listens to `*`; local `_dispatch` does pattern
    matching. That keeps the core tiny and lets curl observe the same
    stream:

        curl -N http://127.0.0.1:3105/listen/*
    """
    e = e or Elastik()
    last_event_id = ""
    while True:
        try:
            for event in e.listen("*", last_event_id=last_event_id or None):
                if event.get("id"):
                    last_event_id = event["id"]
                if event.get("event") == "lag":
                    print(
                        f"elastik reactor: missed SSE events: {event.get('data', '')}",
                        file=sys.stderr,
                    )
                    continue
                world = event.get("path", "")
                method = event.get("method", event.get("event", "")).upper()
                if not world:
                    continue
                if method == "DELETE":
                    _dispatch(world, b"", event.get("etag", ""), {}, e, method, event)
                    continue
                try:
                    body = e.get(world)
                    head = e.head(world)
                except Exception:
                    continue
                meta = {
                    k: v
                    for k, v in head.items()
                    if k.lower().startswith("x-meta-")
                }
                _dispatch(world, body, head.get("etag", event.get("etag", "")), meta, e, method, event)
        except KeyboardInterrupt:
            raise
        except Exception:
            if not reconnect:
                raise
            time.sleep(retry_s)
