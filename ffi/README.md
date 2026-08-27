# L5 FFI

`l5-ffi` is the UniFFI adapter for the L5 Engine.

This crate is deliberately not an HTTP binding. Its upstream is the Rust
`Engine` facade from `l5`; the HTTP adapter and this FFI crate are sibling
adapters. The Python SDK builds on this FFI crate rather than speaking a
wire protocol.

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
- `engine.dereference_timeline_coordinate()` — historical timeline reads return
  `Body`, `Expired`, `NonBodyEvent`, `MissingRow`, mismatch, unproven, or
  corruption outcomes without falling back to the current body; `Expired`
  carries the row content type, size, and HMAC proof
- `engine.worlds`, `du`, `df`, `pool`, `audit_verify` — typed introspection
- `engine.subscribe(pattern, tier, resume)` — synchronously opens the Engine's
  async subscription through the FFI runtime; `FfiSubscription.next(timeout_ms)`
  is the blocking receiver. `close()` releases the slot deterministically in
  garbage-collected languages and wakes a currently blocked `next()` instead
  of waiting for the timeout window
- subscription events expose Engine verbs (`Replace`, `Append`, `Delete`,
  `Format`), not HTTP method strings
- durable subject-delete events expose `delete_subject_generation`; the signed
  delete-subject proof in the delete ledger contains subject world, generation,
  seq, body-sha256, and row HMAC
- `engine.shutdown()` — orderly Engine shutdown (also called automatically on drop)
- structured `FfiError` enum with payloads for quota numbers, startup storage
  diagnostics, auth gate identity, and unknown newer-core variants — errors
  cross the FFI boundary without collapsing into strings

## Quick Start

Generate Python bindings from this directory (the repository root is not a
Cargo workspace):

```powershell
cargo build
cargo run --bin uniffi-bindgen -- generate target\debug\l5_ffi.dll --language python --out-dir target\bindings\python
```

## Python-Shaped Usage

Names can vary slightly by generated binding language. All examples assume an
open Engine:

```python
from l5_ffi import (
    FfiAccessTier, FfiEngine, FfiEngineConfig, FfiError,
    FfiDeleteMetadata, FfiHeader, FfiPreconditions, FfiRepresentation,
    FfiSubscriptionNextKind, FfiSubscriptionResume,
)

engine = FfiEngine.open(FfiEngineConfig(
    data_root="/var/lib/auditedb",
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
sub = engine.subscribe(
    "home/*",
    FfiAccessTier.READ,
    FfiSubscriptionResume(after_cursor=None),
)

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

`usage[i].bytes` and `snap.storage_used` are quota-bearing body bytes: current
durable bodies plus retained historical CAS bodies. The FFI records also expose
`current_body_bytes`, `retained_cas_body_bytes`, `audit_chain_events`, and the
matching aggregate `storage_*` gauges so hosts can distinguish live value bytes
from retained timeline bytes without parsing SQLite files.

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

- Linux x64 (`libl5_ffi.so`)
- Linux ARM64 (`libl5_ffi.so`)
- macOS ARM64 (`libl5_ffi.dylib`)
- Windows x64 (`l5_ffi.dll`)

Tagged-release attachment and checksum integration live in the release workflow
stack layer after the CI artifact shape is validated.
