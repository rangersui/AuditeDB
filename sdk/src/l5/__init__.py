"""In-process L5 Engine Python handle."""

from __future__ import annotations

import json
import threading
import weakref
from collections.abc import Iterator, Mapping, Sequence
from os import PathLike
from pathlib import Path
from types import ModuleType, TracebackType
from typing import TYPE_CHECKING, Callable, TypeVar

if TYPE_CHECKING:
    from ._ffi import l5_ffi as _ffi_types


HeaderInput = Mapping[str, str] | Sequence[tuple[str, str]] | None
T = TypeVar("T")


class L5Error(Exception):
    """Base class for errors raised by the embedded L5 Python SDK."""

    def __init__(self, message: str = "") -> None:
        super().__init__(message or self.__class__.__name__)


class InvalidConfig(L5Error):
    """Invalid Engine configuration."""


class InvalidSecret(L5Error):
    """Invalid HMAC key or secret input."""


class InvalidWorld(L5Error):
    """Invalid world path."""


class BuildError(L5Error):
    """Engine startup failed."""


class DataRootLockHeld(BuildError):
    """The data root is already locked by another Engine process."""

    def __init__(
        self,
        message: str = "data root is locked",
        *,
        path: str | None = None,
        holder_pid: str | None = None,
    ) -> None:
        self.path = path
        self.holder_pid = holder_pid
        super().__init__(message)


class AuthError(L5Error):
    """The requested operation requires a higher access tier."""

    def __init__(self, message: str = "operation is not authorised", *, gate: str | None = None) -> None:
        self.gate = gate
        super().__init__(message)


class InvalidWorldName(InvalidWorld):
    """The world name is not accepted by the Engine."""


class InvalidMetadata(L5Error):
    """Content type or metadata headers are invalid."""


class NotFound(L5Error):
    """The requested world does not exist."""


class AppendOnly(L5Error):
    """The requested world only accepts append/delete-ledger writes."""


class PayloadTooLarge(L5Error):
    """The request body exceeds the configured world limit."""

    def __init__(self, message: str = "payload too large", *, max_size: int | None = None) -> None:
        self.max_size = max_size
        super().__init__(message)


class PreconditionFailed(L5Error):
    """An optimistic concurrency precondition failed."""


class QuotaExceeded(L5Error):
    """A storage or memory quota would be exceeded."""

    def __init__(
        self,
        message: str = "quota exceeded",
        *,
        used: int | None = None,
        quota: int | None = None,
        projected: int | None = None,
    ) -> None:
        self.used = used
        self.quota = quota
        self.projected = projected
        super().__init__(message)


class StorageError(L5Error):
    """The storage backend failed."""


class TransientStorage(StorageError):
    """The storage backend is temporarily unavailable."""


class InsufficientStorage(StorageError):
    """The storage backend has insufficient space."""


class SubscriptionLimit(L5Error):
    """The Engine cannot create another subscription."""


class ShuttingDown(L5Error):
    """The Engine is shutting down."""


class InternalInvariant(L5Error):
    """An internal Engine invariant failed."""


class UnknownEngineError(L5Error):
    """The FFI binding received an unmapped Engine error."""


def _message_from(exc: BaseException, default: str) -> str:
    for attr in ("message", "detail"):
        value = getattr(exc, attr, None)
        if value:
            return str(value)
    return default


def _translate_ffi_error(ffi: ModuleType, exc: BaseException) -> L5Error:
    error = ffi.FfiError
    if isinstance(exc, error.InvalidConfig):
        return InvalidConfig(_message_from(exc, "invalid configuration"))
    if isinstance(exc, error.InvalidSecret):
        return InvalidSecret(_message_from(exc, "invalid secret"))
    if isinstance(exc, error.InvalidWorld):
        return InvalidWorld(_message_from(exc, "invalid world"))
    if isinstance(exc, error.BuildDataRootLockHeld):
        path = getattr(exc, "path", None)
        pid = getattr(exc, "holder_pid", None)
        suffix = "" if pid is None else f" (last writer: PID {pid})"
        return DataRootLockHeld(f"data root is locked{suffix}", path=path, holder_pid=pid)
    if isinstance(exc, error.BuildDataRootIo):
        return BuildError(_message_from(exc, "data root I/O failure"))
    if isinstance(exc, error.BuildHmacKeyMissing):
        return InvalidSecret("HMAC key is required")
    if isinstance(exc, error.BuildAuditChainCorrupted):
        world = getattr(exc, "world", "")
        detail = _message_from(exc, "audit chain corrupted")
        return BuildError(f"{world}: {detail}" if world else detail)
    if isinstance(exc, error.BuildStorage):
        return StorageError(_message_from(exc, "storage failure"))
    if isinstance(exc, error.UnknownBuildError):
        return BuildError(_message_from(exc, "unknown build error"))
    if isinstance(exc, error.RuntimeInitFailed):
        return BuildError(_message_from(exc, "runtime initialisation failed"))
    if isinstance(exc, error.Auth):
        gate = getattr(exc, "gate", None)
        gate_name = getattr(gate, "name", None)
        return AuthError(_message_from(exc, "operation is not authorised"), gate=gate_name)
    if isinstance(exc, error.InvalidWorldName):
        return InvalidWorldName("invalid world name")
    if isinstance(exc, error.InvalidMetadata):
        return InvalidMetadata(_message_from(exc, "invalid metadata"))
    if isinstance(exc, error.NotFound):
        return NotFound("world not found")
    if isinstance(exc, error.AppendOnly):
        return AppendOnly("world is append-only")
    if isinstance(exc, error.PayloadTooLarge):
        max_size = getattr(exc, "max", None)
        detail = "payload too large" if max_size is None else f"payload exceeds {max_size} bytes"
        return PayloadTooLarge(detail, max_size=max_size)
    if isinstance(exc, error.PreconditionFailed):
        return PreconditionFailed(_message_from(exc, "precondition failed"))
    if isinstance(exc, error.QuotaExceeded):
        return QuotaExceeded(
            str(exc),
            used=getattr(exc, "used", None),
            quota=getattr(exc, "quota", None),
            projected=getattr(exc, "projected", None),
        )
    if isinstance(exc, error.TransientStorage):
        return TransientStorage("transient storage failure")
    if isinstance(exc, error.InsufficientStorage):
        return InsufficientStorage("insufficient storage")
    if isinstance(exc, error.Storage):
        return StorageError("storage failure")
    if isinstance(exc, error.SubscriptionLimit):
        return SubscriptionLimit("subscription limit reached")
    if isinstance(exc, error.ShuttingDown):
        return ShuttingDown("engine is shutting down")
    if isinstance(exc, error.InternalInvariant):
        return InternalInvariant(_message_from(exc, "internal invariant failed"))
    if isinstance(exc, error.UnknownEngineError):
        return UnknownEngineError(_message_from(exc, "unknown engine error"))
    return L5Error(str(exc))


def _call_ffi(ffi: ModuleType, operation: Callable[[], T]) -> T:
    try:
        return operation()
    except ffi.FfiError as exc:
        raise _translate_ffi_error(ffi, exc) from exc
    except ffi.InternalError as exc:
        raise InternalInvariant(str(exc)) from exc


def _load_ffi() -> ModuleType:
    try:
        from ._ffi import l5_ffi
    except (OSError, ImportError, AttributeError) as exc:
        raise InternalInvariant(f"failed to load L5 FFI: {exc}") from exc
    except Exception as exc:
        if exc.__class__.__name__ == "InternalError":
            raise InternalInvariant(f"failed to load L5 FFI: {exc}") from exc
        raise

    return l5_ffi


class Subscription:
    """Blocking iterator over Engine subscription events."""

    def __init__(
        self,
        ffi: ModuleType,
        subscription: "_ffi_types.FfiSubscription",
    ) -> None:
        self._ffi = ffi
        self._subscription = subscription
        self._closed = False
        self._close_lock = threading.Lock()

    def next(self, timeout_ms: int = 1000) -> dict[str, object] | None:
        """Return one event dict, a control dict, or None on timeout."""

        if self._closed:
            return {"kind": "closed"}
        item = _call_ffi(self._ffi, lambda: self._subscription.next(int(timeout_ms)))
        kind = item.kind
        if kind == self._ffi.FfiSubscriptionNextKind.EVENT and item.event is not None:
            return self._event(item.event)
        if kind == self._ffi.FfiSubscriptionNextKind.TIMEOUT:
            return None
        if kind == self._ffi.FfiSubscriptionNextKind.LAGGED:
            return {"kind": "lagged", "skipped": item.skipped}
        if kind == self._ffi.FfiSubscriptionNextKind.RESET:
            reason = item.reset_reason
            return {
                "kind": "reset",
                "reason": None if reason is None else reason.name.lower(),
            }
        return {"kind": kind.name.lower()}

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        try:
            _call_ffi(self._ffi, self._subscription.close)
        except BaseException:
            with self._close_lock:
                self._closed = False
            raise

    def __enter__(self) -> "Subscription":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def __iter__(self) -> "Subscription":
        return self

    def __next__(self) -> dict[str, object]:
        while True:
            item = self.next()
            if item is None:
                continue
            if item.get("kind") == "closed":
                raise StopIteration
            return item

    def _event(self, event: "_ffi_types.FfiChangeEvent") -> dict[str, object]:
        out = {
            "kind": "event",
            "id": int(event.id),
            "cursor": event.cursor,
            "verb": event.verb.name.lower(),
            "path": str(event.path),
            "etag": str(event.etag),
        }
        optional_fields = {
            "timeline_world": event.timeline_world,
            "timeline_generation": event.timeline_generation,
            "timeline_seq": event.timeline_seq,
            "timeline_body_sha256": event.timeline_body_sha256,
            "delete_ledger_cursor": event.delete_ledger_cursor,
            "delete_ledger_seq": event.delete_ledger_seq,
            "delete_subject_generation": event.delete_subject_generation,
            "audit_event_type": event.audit_event_type,
            "audit_event_target": event.audit_event_target,
            "body_sha256": event.body_sha256,
            "body_size": event.body_size,
            "content_type": event.content_type,
        }
        out.update({key: value for key, value in optional_fields.items() if value is not None})
        return out


class Engine:
    """Small Python wrapper around the native UniFFI Engine handle."""

    def __init__(self, data_root: str | PathLike[str], *, key: bytes) -> None:
        ffi = _load_ffi()
        config = ffi.FfiEngineConfig(
            data_root=str(Path(data_root)),
            hmac_key=bytes(key),
            read_token=None,
            write_token=None,
            approve_token=None,
            max_world_bytes=None,
            max_memory_bytes=None,
            max_storage_bytes=None,
            max_listen_connections=None,
            listen_replay_max=None,
            read_cache_max_entries=None,
        )
        self._ffi = ffi
        self._engine: "_ffi_types.FfiEngine | None" = _call_ffi(
            ffi, lambda: ffi.FfiEngine.open(config)
        )
        self._closed = False
        self._closing = False
        self._close_lock = threading.RLock()
        self._close_cv = threading.Condition(self._close_lock)
        self._subscriptions: weakref.WeakSet[Subscription] = weakref.WeakSet()

    def put(
        self,
        path: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        headers: HeaderInput = None,
    ) -> object:
        """Replace ``path`` with ``data``."""

        engine = self._engine_handle()
        representation = self._ffi.FfiRepresentation(
            body=bytes(data),
            content_type=str(content_type),
            headers=self._headers(headers),
        )
        return _call_ffi(
            self._ffi,
            lambda: engine.replace(
                path,
                representation,
                self._preconditions(),
                self._access_tier("Write"),
            ),
        )

    def get(self, path: str) -> bytes:
        """Read ``path`` and return its body bytes."""

        result = self._read(path)
        return bytes(result.representation.body)

    def get_text(
        self,
        path: str,
        *,
        encoding: str = "utf-8",
        errors: str = "strict",
    ) -> str:
        """Read ``path`` and decode its body as text."""

        return self.get(path).decode(encoding, errors)

    def get_json(
        self,
        path: str,
        *,
        encoding: str = "utf-8",
    ) -> object:
        """Read ``path`` and parse its body as JSON."""

        return json.loads(self.get_text(path, encoding=encoding))

    def head(self, path: str) -> dict[str, str]:
        """Return metadata for ``path`` without exposing the body."""

        result = self._read(path)
        representation = result.representation
        headers = {
            "etag": str(result.etag),
            "content-type": str(representation.content_type),
            "content-length": str(len(representation.body)),
        }
        headers.update(
            {str(header.name).lower(): str(header.value) for header in representation.headers}
        )
        return headers

    def append(self, path: str, data: bytes) -> object:
        """Append ``data`` to ``path``."""

        engine = self._engine_handle()
        body = bytes(data)
        try:
            return _call_ffi(
                self._ffi,
                lambda: engine.append(
                    path,
                    body,
                    self._preconditions(),
                    self._access_tier("Write"),
                ),
            )
        except NotFound:
            self.put(path, b"")
            engine = self._engine_handle()
            return _call_ffi(
                self._ffi,
                lambda: engine.append(
                    path,
                    body,
                    self._preconditions(),
                    self._access_tier("Write"),
                ),
            )

    def delete(self, path: str) -> bool:
        """Delete ``path``."""

        engine = self._engine_handle()
        try:
            _call_ffi(
                self._ffi,
                lambda: engine.delete(
                    path,
                    self._preconditions(),
                    self._access_tier("Approve"),
                ),
            )
            return True
        except NotFound:
            return False

    def __getitem__(self, path: str) -> bytes:
        try:
            return self.get(path)
        except NotFound as exc:
            raise KeyError(path) from exc

    def __setitem__(self, path: str, data: bytes) -> None:
        self.put(path, data)

    def __delitem__(self, path: str) -> None:
        if not self.delete(path):
            raise KeyError(path)

    def __contains__(self, path: object) -> bool:
        if not isinstance(path, str):
            return False
        engine = self._engine_handle()
        return _call_ffi(
            self._ffi,
            lambda: engine.read(path, self._access_tier("Read")),
        ) is not None

    def __iter__(self) -> Iterator[str]:
        return iter(self.list_worlds())

    def __len__(self) -> int:
        return len(self.list_worlds())

    def __bool__(self) -> bool:
        return True

    def list_worlds(self) -> list[str]:
        """Return every canonical world known to the Engine."""

        engine = self._engine_handle()
        return list(_call_ffi(
            self._ffi,
            lambda: engine.worlds(self._access_tier("Read")),
        ))

    def ls(self) -> list[str]:
        """Alias for :meth:`list_worlds`."""

        return self.list_worlds()

    def verify(self, path: str) -> bool:
        """Return True when ``path`` has a valid durable audit chain."""

        result = self._audit_verify(path)
        return bool(result.is_VALID())

    def chain_head(self, path: str) -> dict[str, str | int] | None:
        """Return the verified audit summary available through FFI."""

        result = self._audit_verify(path)
        if result.is_VALID():
            valid = result.valid
            return {
                "events": int(valid.events),
                "genesis": str(valid.genesis),
                "latest": str(valid.latest),
            }
        return None

    def du(self) -> dict[str, int]:
        """Return per-world byte usage."""

        engine = self._engine_handle()
        return {
            str(usage.world): int(usage.bytes)
            for usage in _call_ffi(
                self._ffi,
                lambda: engine.du(self._access_tier("Read")),
            )
        }

    def df(self) -> dict[str, int | None]:
        """Return aggregate storage and memory usage."""

        engine = self._engine_handle()
        snapshot = _call_ffi(
            self._ffi,
            lambda: engine.df(self._access_tier("Read")),
        )
        return {
            "storage_used": int(snapshot.storage_used),
            "storage_current_body_bytes": int(snapshot.storage_current_body_bytes),
            "storage_retained_cas_body_bytes": int(snapshot.storage_retained_cas_body_bytes),
            "storage_audit_chain_events": int(snapshot.storage_audit_chain_events),
            "storage_quota": None
            if snapshot.storage_quota is None
            else int(snapshot.storage_quota),
            "memory_used": int(snapshot.memory_used),
            "memory_quota": int(snapshot.memory_quota),
            "worlds": int(snapshot.worlds),
        }

    def subscribe(self, pattern: str, *, after_cursor: str | None = None) -> Subscription:
        """Open a blocking in-process subscription iterator."""

        with self._close_lock:
            self._ensure_open()
            engine = self._engine
            if engine is None:
                raise RuntimeError("L5 Engine handle is closed")
            resume = self._ffi.FfiSubscriptionResume(after_cursor=after_cursor)
            subscription = _call_ffi(
                self._ffi,
                lambda: engine.subscribe(
                    str(pattern),
                    self._access_tier("Read"),
                    resume,
                ),
            )
            wrapped = Subscription(self._ffi, subscription)
            self._subscriptions.add(wrapped)
            return wrapped

    def __enter__(self) -> "Engine":
        self._engine_handle()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Shut down the embedded Engine handle."""

        with self._close_cv:
            while self._closing:
                self._close_cv.wait()
            if self._closed:
                return
            self._closing = True
            subscriptions = list(self._subscriptions)
            self._subscriptions.clear()
            engine = self._engine
        first_error: BaseException | None = None
        for subscription in subscriptions:
            try:
                subscription.close()
            except BaseException as exc:
                first_error = exc
                break
        if first_error is not None:
            with self._close_cv:
                self._closing = False
                self._subscriptions.update(subscriptions)
                self._close_cv.notify_all()
            raise first_error
        if engine is not None:
            try:
                _call_ffi(self._ffi, engine.shutdown)
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            with self._close_cv:
                self._closing = False
                self._subscriptions.update(subscriptions)
                self._close_cv.notify_all()
            raise first_error
        with self._close_cv:
            self._engine = None
            self._closed = True
            self._closing = False
            self._close_cv.notify_all()

    def _ensure_open(self) -> None:
        if self._closed or self._closing or self._engine is None:
            raise RuntimeError("L5 Engine handle is closed")

    def _engine_handle(self) -> "_ffi_types.FfiEngine":
        with self._close_lock:
            self._ensure_open()
            engine = self._engine
            if engine is None:
                raise RuntimeError("L5 Engine handle is closed")
            return engine

    def _read(self, path: str) -> "_ffi_types.FfiReadResult":
        engine = self._engine_handle()
        result = _call_ffi(
            self._ffi,
            lambda: engine.read(path, self._access_tier("Read")),
        )
        if result is None:
            raise NotFound(f"{path!r} not found")
        return result

    def _audit_verify(self, path: str) -> "_ffi_types.FfiAuditVerify":
        engine = self._engine_handle()
        return _call_ffi(
            self._ffi,
            lambda: engine.audit_verify(path, self._access_tier("Read")),
        )

    def _preconditions(self) -> "_ffi_types.FfiPreconditions":
        return self._ffi.FfiPreconditions(if_match=[], if_none_match=[])

    def _access_tier(self, name: str) -> "_ffi_types.FfiAccessTier":
        tier = self._ffi.FfiAccessTier
        if hasattr(tier, name):
            return getattr(tier, name)
        return getattr(tier, name.upper())

    def _headers(self, headers: HeaderInput) -> list["_ffi_types.FfiHeader"]:
        if headers is None:
            return []
        items = headers.items() if isinstance(headers, Mapping) else headers
        return [
            self._ffi.FfiHeader(name=str(name), value=str(value))
            for name, value in items
        ]


def open(data_root: str | PathLike[str], *, key: bytes) -> Engine:
    """Open an embedded L5 Engine rooted at ``data_root``."""

    return Engine(data_root, key=key)


__all__ = [
    "AppendOnly",
    "AuthError",
    "BuildError",
    "DataRootLockHeld",
    "Engine",
    "InsufficientStorage",
    "InternalInvariant",
    "InvalidConfig",
    "InvalidMetadata",
    "InvalidSecret",
    "InvalidWorld",
    "InvalidWorldName",
    "L5Error",
    "NotFound",
    "PayloadTooLarge",
    "PreconditionFailed",
    "QuotaExceeded",
    "ShuttingDown",
    "StorageError",
    "Subscription",
    "SubscriptionLimit",
    "TransientStorage",
    "UnknownEngineError",
    "open",
]
