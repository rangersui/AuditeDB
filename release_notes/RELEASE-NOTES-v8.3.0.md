# AuditeDB v8.3.0 - audit key seal

v8.3.0 is a minor release for the v8 Engine line.

This release tightens the audit-chain key boundary. The unstable Rust Engine
builder and shipped adapters now require audit HMAC keys to be at least 32
bytes, so short keys cannot enter the audit chain by accident.

## Highlights

- **Audit HMAC keys are type-sealed.** `EngineBuilder::key` now accepts an
  `AuditHmacKey` proof type instead of generic secret bytes.
- **Short audit keys fail loudly.** The HTTP binary, FFI layer, Rust Engine
  builder, and Python launcher reject audit-chain HMAC keys shorter than 32
  bytes.
- **Secret containers stay generic.** `SecretBytes` remains a zeroing byte
  container; only `AuditHmacKey` carries the audit-chain strength policy.
- **Boundary tests added.** The test suite pins empty, whitespace, short,
  31-byte, and 32-byte audit key cases.

## Compatibility notes

- This is a breaking change for the unstable Rust Engine builder API:
  `EngineBuilder::key` requires `AuditHmacKey`.
- HTTP, CoAP, SSE, MQTT, JavaScript SDK, and FFI protocol shapes are not
  intentionally changed by this release.
- The Rust library package remains `elastik-core`.
- The server binary package remains `elastik-bin`, and still produces the
  `elastik-core` executable.
- The Python package remains `elastik`.
- The JavaScript packages remain `@elastikjs/client` and
  `@elastikjs/core-*`.
- Environment variables remain `ELASTIK_*`.

## Migration notes

- Audit-chain HMAC keys shorter than 32 bytes are rejected at startup and by
  the Rust Engine builder. Chains created with shorter keys cannot be opened by
  this release; that does not mean the data is silently corrupted, only that
  the chain is bound to the old key policy. Keep those data roots on a build
  that accepted the old key, or reinitialize the data with a 32-byte-or-longer
  key. A rekey tool is not available yet; rekeying an existing chain means
  rebuilding the chain with a new HMAC key. Rekey tooling is tracked in #323.
- Generate a fresh key with at least 32 random bytes. Hex-encoded 32-byte
  output, such as `python -c "import secrets; print(secrets.token_hex(32))"`,
  is acceptable because it provides 64 ASCII bytes of key material.

## Operational notes

- CI and tag release jobs run `tools/version_consistency_check.py`, which fails
  if Rust manifests, Cargo locks, Python metadata, JavaScript package metadata,
  npm companion metadata, active docs, release notes, or the tag version drift.

## Packages

These are the planned v8.3.0 release artifacts. The release workflow validates
the version surface against the tag before publishing.

- Rust library crate: `elastik-core` `8.3.0`
- Repository Rust server binary package: `elastik-bin` `8.3.0`,
  producing the `elastik-core` executable
- Repository FFI Cargo package and GitHub Release assets: `elastik-ffi` `8.3.0`
- Python SDK: `elastik` `8.3.0`
- JavaScript SDK: `@elastikjs/client` `8.3.0`
- npm binary companions:
  - `@elastikjs/core-linux-x64` `8.3.0`
  - `@elastikjs/core-linux-arm64` `8.3.0`
  - `@elastikjs/core-darwin-arm64` `8.3.0`
  - `@elastikjs/core-win32-x64` `8.3.0`
- GitHub Release core assets:
  - `elastik-core-linux-x64.zip`
  - `elastik-core-linux-arm64.zip`
  - `elastik-core-darwin-arm64.zip`
  - `elastik-core-win32-x64.zip`
- GitHub Release FFI assets:
  - `elastik-ffi-linux-x64.zip`
  - `elastik-ffi-linux-arm64.zip`
  - `elastik-ffi-darwin-arm64.zip`
  - `elastik-ffi-win32-x64.zip`
