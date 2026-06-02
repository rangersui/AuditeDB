# Elastik FFI

`elastik-ffi` is the UniFFI adapter for Elastik's protocol-neutral `Engine`.

This crate is deliberately not an HTTP binding. Its upstream is the Rust
`Engine` facade from `elastik-core`; HTTP, CoAP, SDK wire clients, and this FFI
crate are sibling adapters.

## Current Surface (Layer 2: Handle + Type Boundary)

- `FfiEngine.open(config)` — construct an Engine with an embedded Tokio runtime
- `engine.config_summary()` — non-secret configuration accepted by the adapter
- `engine.verify_token(token)` — check caller access tier without side effects
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

Names can vary slightly by generated binding language, but the current FFI
surface intentionally stays limited to handle construction, token verification,
configuration summary, shutdown, and typed errors.

```python
from elastik_ffi import FfiAccessTier, FfiEngine, FfiEngineConfig

# Open an Engine
engine = FfiEngine.open(FfiEngineConfig(
    data_root="/var/lib/elastik",
    hmac_key=b"my-secret-key",
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

# Inspect non-secret configuration
summary = engine.config_summary()
assert summary.has_read_token is True

# Verify a caller token
tier = engine.verify_token(b"reader")
assert tier == FfiAccessTier.READ

tier = engine.verify_token(b"wrong")
assert tier == FfiAccessTier.ANON

# Shutdown (also happens automatically when the object is collected)
engine.shutdown()
```

## Error Handling

Errors carry structured data, not flattened strings:

```python
from elastik_ffi import FfiEngine, FfiError

try:
    engine = FfiEngine.open(bad_config)
except FfiError.InvalidSecret as e:
    print(e.message)
except FfiError.BuildDataRootLockHeld as e:
    print(f"locked: {e.path}")
```

## Not Yet Bound

These Engine capabilities have FFI DTOs defined but are not yet wired:

- `read`, `replace`, `append`, `delete` — Engine verbs
- `worlds`, `du`, `df`, `pool`, `audit_verify(world)` — typed introspection
- `subscribe(pattern, tier, since) -> FfiSubscription` — change event receiver
- CI/release build matrix for `.so`, `.dylib`, `.dll`, and language bindings
