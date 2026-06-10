# AuditeDB FFI

`elastik-ffi` is the UniFFI adapter for the Elastik L5 Engine.

This crate is deliberately not an HTTP binding. Its upstream is the Rust
`Engine` facade from `elastik-core`; HTTP, CoAP, SDK wire clients, and this FFI
crate are sibling adapters.

## Current Surface

- `crate-type = ["lib", "cdylib"]`
- UniFFI scaffolding compiles
- `FfiEngine.open(config)` — construct an Engine with an embedded Tokio runtime
- `engine.config_summary()` — normalized, non-secret configuration accepted by
  the adapter: empty tokens are unset, and `0` is normalized only for Engine
  fields that treat zero as "use the default"
- `engine.verify_token(token)` — check caller access tier without side effects
- `engine.read`, `replace`, `append`, `delete` — Engine verbs bound directly
- `delete_with_metadata()` preserves representation content-type and metadata
  headers in the Engine delete audit ledger; plain `delete()` remains the
  empty-metadata convenience wrapper
- `engine.worlds`, `du`, `df`, `pool`, `audit_verify` — typed introspection
- `engine.subscribe(pattern, tier, since)` — blocking `FfiSubscription.next(timeout_ms)`
  receiver with explicit `close()` for deterministic slot release in
  garbage-collected languages; `close()` wakes a currently blocked `next()`
  instead of waiting for the timeout window
- subscription events expose Engine verbs (`Replace`, `Append`, `Delete`), not
  HTTP method strings
- `engine.shutdown()` — orderly Engine shutdown (also called automatically on drop)
- 24-variant `FfiError` with structured payloads (quota numbers, sqlite codes,
  auth gate identity) — errors cross the FFI boundary without information loss

## Quick Start

Generate Python bindings from this directory (the repository root is not a
Cargo workspace):

```powershell
cargo build
cargo run --bin uniffi-bindgen -- generate target\debug\elastik_ffi.dll --language python --out-dir target\bindings\python
```

## Python-Shaped Usage

Names can vary slightly by generated binding language. All examples assume an
open Engine:

```python
from elastik_ffi import (
    FfiAccessTier, FfiEngine, FfiEngineConfig, FfiError,
    FfiDeleteMetadata, FfiHeader, FfiPreconditions, FfiRepresentation,
    FfiSubscriptionNextKind,
)

engine = FfiEngine.open(FfiEngineConfig(
    data_root="/var/lib/elastik",
    hmac_key=b"0123456789abcdef0123456789abcdef",
    read_token=b"reader",
    write_token=b"writer",
    approve_token=b"admin",
    max_world_bytes=None,
    max_memory_bytes=None,
    max_storage_bytes=None,
    max_listen_connections=None,
    listen_replay_max=None,
    read_cache_max_entries=None,
))
```

`hmac_key` is the audit-chain HMAC key and must be at least 32 bytes. Short,
empty, or all-whitespace keys are rejected before the Engine opens.

### Handle

```python
summary = engine.config_summary()
assert summary.has_read_token is True

tier = engine.verify_token(b"reader")
assert tier == FfiAccessTier.READ

tier = engine.verify_token(b"wrong")
assert tier == FfiAccessTier.ANON
```

### CRUD

```python
none = FfiPreconditions(if_match=[], if_none_match=[])

# Replace (create or overwrite)
result = engine.replace("home/doc", FfiRepresentation(
    body=b"hello",
    content_type="text/plain",
    headers=[],
), none, FfiAccessTier.WRITE)
etag = result.etag

# Read
read = engine.read("home/doc", FfiAccessTier.READ)
assert read is not None
assert read.representation.body == b"hello"

# Append
engine.append("home/doc", b" world", none, FfiAccessTier.WRITE)

# Delete with audit metadata
engine.delete_with_metadata("home/doc", FfiDeleteMetadata(
    content_type="text/plain; charset=utf-8",
    headers=[FfiHeader(name="x-meta-author", value="ffi-example")],
), none, FfiAccessTier.APPROVE)

# Plain delete is the empty-metadata convenience wrapper.
engine.replace("home/plain-doc", FfiRepresentation(
    body=b"temporary",
    content_type="text/plain",
    headers=[],
), none, FfiAccessTier.WRITE)
engine.delete("home/plain-doc", none, FfiAccessTier.APPROVE)
```

### Subscription

```python
sub = engine.subscribe("home/*", FfiAccessTier.READ, None)

engine.replace("home/sub-doc", FfiRepresentation(
    body=b"update",
    content_type="text/plain",
    headers=[],
), none, FfiAccessTier.WRITE)

event = sub.next(5_000)  # blocks up to 5 seconds
assert event.kind == FfiSubscriptionNextKind.EVENT
assert event.event.path == "home/sub-doc"

# Deterministic cleanup (don't wait for GC)
sub.close()
```

### Introspection

```python
worlds = engine.worlds(FfiAccessTier.READ)       # list of canonical paths
usage  = engine.du(FfiAccessTier.READ)            # per-world byte usage
snap   = engine.df(FfiAccessTier.READ)            # aggregate storage/memory
pool   = engine.pool(FfiAccessTier.READ)          # cache and writer counters
engine.replace("home/audit-doc", FfiRepresentation(
    body=b"audited",
    content_type="text/plain",
    headers=[],
), none, FfiAccessTier.WRITE)
audit  = engine.audit_verify("home/audit-doc", FfiAccessTier.READ)

# When the host is done with the Engine.
engine.shutdown()
```

### Error Handling

Errors carry structured data, not flattened strings:

```python
try:
    engine = FfiEngine.open(bad_config)
except FfiError.InvalidSecret as e:
    print(e.message)
except FfiError.BuildDataRootLockHeld as e:
    holder = f" (last writer: PID {e.holder_pid})" if e.holder_pid else ""
    print(f"locked{holder}: {e.path}")
```

## Artifact CI

The artifact CI workflow builds and smokes native libraries plus generated
Python bindings for:

- Linux x64 (`libelastik_ffi.so`)
- Linux ARM64 (`libelastik_ffi.so`)
- macOS ARM64 (`libelastik_ffi.dylib`)
- Windows x64 (`elastik_ffi.dll`)

Tagged-release attachment and checksum integration live in the release workflow
stack layer after the CI artifact shape is validated.

## OpenWrt / MIPS

OpenWrt/MIPS is not part of the hosted FFI artifact matrix yet. It needs an
OpenWrt SDK or equivalent cross toolchain, Rust standard-library support for
the selected MIPS target, and a QEMU or hardware smoke path before it can be a
release artifact. See [OPENWRT.md](OPENWRT.md).
