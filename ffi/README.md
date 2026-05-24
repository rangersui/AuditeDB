# Elastik FFI

`elastik-ffi` is the UniFFI adapter for Elastik's protocol-neutral `Engine`.

This crate is deliberately not an HTTP binding. Its upstream is the Rust
`Engine` facade from `elastik-core`; HTTP, CoAP, SDK wire clients, and this FFI
crate are sibling adapters.

Layer 1 of the FFI stack only proves the native library scaffold:

- `crate-type = ["lib", "cdylib"]`
- UniFFI scaffolding compiles
- exported smoke functions are available for binding generation

Because the repository root is not a Cargo workspace, run binding generation
from this directory:

```powershell
cargo build
cargo run --bin uniffi-bindgen -- generate target\debug\elastik_ffi.dll --language python --out-dir target\bindings\python
```

Later stacked PRs add the actual Engine-bound surface:

- Engine handle, config, DTOs, and typed errors
- `read`, `replace`, `append`, `delete`
- typed introspection (`worlds`, `du`, `df`, `pool`, `audit_verify(world)`)
- subscription receiver object
- CI/release build matrix for `.so`, `.dylib`, and `.dll`
