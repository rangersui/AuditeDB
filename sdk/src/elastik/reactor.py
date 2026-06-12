"""Declarative reactor vocabulary over elastik HTTP atoms.

The Rust core does not know about plugins or callbacks. This
module is SDK-side vocabulary only: register handlers, describe actions,
and let `run(...)` feed core SSE events into `_dispatch(...)`. Other
adapters can still feed polling, filesystem notifications, queues, or
anything else that can provide `path`, `body`, `etag`, and `meta`.
"""
from __future__ import annotations

import inspect
import sys
import time
from typing import Any, Callable, TypeVar

from elastik.sdk import Elastik


F = TypeVar("F", bound=Callable[..., Any])

_routes: dict[str, Callable[..., Any]] = {}
_startup_hooks: list[Callable[..., Any]] = []
_shutdown_hooks: list[Callable[..., Any]] = []


def listen(pattern: str, *, replace: bool = False) -> Callable[[F], F]:
    """Register a handler for a path pattern.

    Pattern is prefix-with-trailing-`*`:
      "/home/inbox/*"  matches "/home/inbox/alice/abc"
      "/home/foo"      matches exactly "/home/foo"
      "*"              matches everything

    The handler receives `body` as the first positional argument plus
    any named kwargs it asks for: `path`, `world` (compat alias),
    `etag`, `pattern`, `meta`, `e`.

    `body` is fetched with `GET path` when the event is dispatched. It is
    the current value at dispatch time, not a historical dereference of the
    SSE event's timeline fields.

    Registering the same pattern twice is usually a bug, so it raises
    ValueError unless `replace=True` is explicit.
    """
    def deco(func: F) -> F:
        if pattern in _routes and not replace:
            raise ValueError(
                f"handler already registered for {pattern!r}; "
                "call unlisten(), clear_routes(), or listen(..., replace=True)"
            )
        _routes[pattern] = func
        return func
    return deco


def unlisten(pattern: str) -> None:
    """Remove one registered handler pattern if present."""
    _routes.pop(pattern, None)


def clear_routes() -> None:
    """Remove all registered handlers. Useful for tests and notebooks."""
    _routes.clear()


def on_startup(func: F) -> F:
    """Register a function called once before run() starts consuming events.

    Hooks may accept no arguments or ask for `e`; both forms are supported:

        @elastik.on_startup
        def ready(e):
            e.put("/sys/health/worker-1", "alive")
    """
    _startup_hooks.append(func)
    return func


def on_shutdown(func: F) -> F:
    """Register a function called when run() exits.

    Shutdown hooks run in reverse registration order. They may accept no
    arguments or ask for `e`.
    """
    _shutdown_hooks.append(func)
    return func


def clear_lifecycle_hooks() -> None:
    """Remove startup/shutdown hooks. Useful for tests and notebooks."""
    _startup_hooks.clear()
    _shutdown_hooks.clear()


def has_routes() -> bool:
    """Return True when at least one @listen handler is registered."""
    return bool(_routes)


def _call_lifecycle_hook(hook: Callable[..., Any], e: Elastik) -> Any:
    sig = inspect.signature(hook)
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
        return hook(e=e)
    if "e" in sig.parameters:
        return hook(e=e)
    return hook()


def _run_startup_hooks(e: Elastik) -> None:
    for hook in list(_startup_hooks):
        _call_lifecycle_hook(hook, e)


def _run_shutdown_hooks(e: Elastik) -> None:
    for hook in reversed(list(_shutdown_hooks)):
        _call_lifecycle_hook(hook, e)


def _matches(pattern: str, path: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    return path == pattern


def _matching_routes(path: str) -> list[tuple[str, Callable[..., Any]]]:
    return [
        (pattern, handler)
        for pattern, handler in _routes.items()
        if _matches(pattern, path)
    ]


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
        ctx.e.delete(ctx.path)


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
        name = ctx.path.rstrip("/").rsplit("/", 1)[-1] or "anon"
        ctx.e.put(self.prefix.rstrip("/") + "/" + name, ctx.body)
        ctx.e.delete(ctx.path)


class Drop(Action):
    """Delete the source. No reply."""

    def execute(self, ctx: Ctx) -> None:
        ctx.e.delete(ctx.path)


class Ctx:
    __slots__ = (
        "body",
        "path",
        "world",
        "etag",
        "pattern",
        "meta",
        "e",
        "method",
        "event",
    )

    def __init__(
        self,
        body: bytes,
        path: str,
        etag: str,
        pattern: str,
        meta: dict[str, str],
        e: Elastik,
        method: str = "",
        event: dict[str, str] | None = None,
    ):
        self.body = body
        self.path = path
        self.world = path  # compatibility alias for early 6.0 handlers
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
        "path": ctx.path,
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
    routes: list[tuple[str, Callable[..., Any]]] | None = None,
) -> None:
    """Run registered handlers. Transport adapters call this."""
    selected = routes if routes is not None else _matching_routes(world)
    for pattern, handler in selected:
        ctx = Ctx(
            body=body,
            path=world,
            etag=etag,
            pattern=pattern,
            meta=meta,
            e=e,
            method=method,
            event=event,
        )
        result = _call_handler(handler, ctx)
        _run_action(result, ctx)


def run(
    e: Elastik | None = None,
    reconnect: bool = True,
    retry_s: float = 1.0,
    max_events: int | None = None,
) -> None:
    """Consume core SSE and dispatch registered @listen handlers.

    One connection listens to `*`; local `_dispatch` does pattern
    matching. That keeps the core tiny and lets curl observe the same
    stream:

        curl -N http://127.0.0.1:3105/listen/*

    By default `reconnect=True` retries forever and logs failures to
    stderr. Use `reconnect=False` under an external supervisor when you
    prefer fail-fast process restarts.

    `max_events` is mainly for examples and tests: run returns after
    dispatching that many matching events.
    """
    if not _routes:
        raise RuntimeError(
            "elastik.run() has no @elastik.listen handlers registered. "
            "Register a handler first, or remove run() if you only need put/get."
        )
    if e is None:
        e = Elastik()
    last_event_id = ""
    dispatched = 0
    failure: BaseException | None = None
    try:
        _run_startup_hooks(e)
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
                    routes = _matching_routes(world)
                    if not routes:
                        continue
                    if method == "DELETE":
                        _dispatch(
                            world,
                            b"",
                            event.get("etag", ""),
                            {},
                            e,
                            method,
                            event,
                            routes=routes,
                        )
                        dispatched += 1
                        if max_events is not None and dispatched >= max_events:
                            return
                        continue
                    try:
                        body = e.get(world)
                        head = e.head(world)
                    except Exception as exc:
                        print(
                            f"elastik reactor: failed to fetch {world}: "
                            f"{type(exc).__name__}: {exc}",
                            file=sys.stderr,
                        )
                        continue
                    meta = {
                        k: v
                        for k, v in head.items()
                        if k.lower().startswith("x-meta-")
                    }
                    _dispatch(
                        world,
                        body,
                        head.get("etag", event.get("etag", "")),
                        meta,
                        e,
                        method,
                        event,
                        routes=routes,
                    )
                    dispatched += 1
                    if max_events is not None and dispatched >= max_events:
                        return
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                if not reconnect:
                    raise
                print(
                    f"elastik reactor: {type(exc).__name__}: {exc}; "
                    f"retrying in {retry_s}s",
                    file=sys.stderr,
                )
                time.sleep(retry_s)
    except BaseException as exc:
        failure = exc
        raise
    finally:
        if failure is None:
            _run_shutdown_hooks(e)
        else:
            try:
                _run_shutdown_hooks(e)
            except BaseException as cleanup_exc:
                print(
                    "elastik reactor: shutdown hook failed during unwind: "
                    f"{type(cleanup_exc).__name__}: {cleanup_exc}",
                    file=sys.stderr,
                )
