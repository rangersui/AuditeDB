# Elastik v8.2.0 - supply-chain refresh

v8.2.0 is a minor release for the v8 Engine line.

This release republishes the v8 packages after the dependency supply-chain
refresh that landed after v8.1.0. The goal is boring but important: new
installs should resolve to manifests and lockfiles that already contain the
audited dependency updates, rather than asking users to install an older crate
and rediscover the same upgrade path locally.

## Highlights

- **Rust dependency floor refreshed.** The core, binary, and FFI Cargo surfaces
  now ship with the post-v8.1.0 supply-chain lock state.
- **SQLite path updated.** `rusqlite` is now on the 0.40 line across the Rust
  packages, with the bundled SQLite blind spot documented and checked by the
  supply-chain workflow.
- **HMAC/SHA stack updated.** `hmac` moved to 0.13 and `sha2` moved to 0.11.
  The HMAC code imports `KeyInit` explicitly and keeps the RFC 4231 known-vector
  test as a sentinel.
- **HTTP adapter stack updated.** The binary adapter now uses axum 0.8 route
  syntax. The wildcard route migration keeps world-path canonicalization
  unchanged.
- **Release versions are aligned.** Rust, Python, JavaScript, npm companion
  packages, docs examples, and lockfiles all move from 8.1.0 to 8.2.0 together.

## Compatibility notes

- The Rust library package remains `elastik-core`.
- The server binary package remains `elastik-bin`, and still produces the
  `elastik-core` executable.
- The public Rust `Engine` API remains behind `unstable-engine`.
- HTTP, CoAP, SSE, MQTT, Python SDK, and JavaScript SDK protocol shapes are not
  intentionally changed by this release.
- Existing `elastik-core = { version = "8", ... }` Cargo manifests will be able
  to resolve to 8.2.0 after the crate is published.

## Operational notes

- `cargo add elastik-core` will report 8.2.0 after crates.io publication.
- CI and tag release jobs run `tools/version_consistency_check.py`, which fails
  if Rust manifests, Cargo locks, Python metadata, JavaScript package metadata,
  npm companion metadata, active docs, release notes, or the tag version drift.
- The supply-chain workflow continues to run RustSec, cargo-deny, duplicate
  dependency warnings, and the repository supply-chain scanner.

## Packages

These are the planned v8.2.0 release artifacts. The release workflow validates
the version surface against the tag before publishing.

- Rust library crate: `elastik-core` `8.2.0`
- Repository Rust server binary package: `elastik-bin` `8.2.0`,
  producing the `elastik-core` executable
- Repository FFI Cargo package and GitHub Release assets: `elastik-ffi` `8.2.0`
- Python SDK: `elastik` `8.2.0`
- JavaScript SDK: `@elastikjs/client` `8.2.0`
- npm binary companions:
  - `@elastikjs/core-linux-x64` `8.2.0`
  - `@elastikjs/core-linux-arm64` `8.2.0`
  - `@elastikjs/core-darwin-arm64` `8.2.0`
  - `@elastikjs/core-win32-x64` `8.2.0`
- GitHub Release core assets:
  - `elastik-core-linux-x64.zip`
  - `elastik-core-linux-arm64.zip`
  - `elastik-core-darwin-arm64.zip`
  - `elastik-core-win32-x64.zip`
- GitHub Release FFI assets:
  - `elastik-ffi-linux-x64.zip`
  - `elastik-ffi-linux-arm64.zip`
  - `elastik-ffi-darwin-x64.zip`
  - `elastik-ffi-darwin-arm64.zip`
  - `elastik-ffi-win32-x64.zip`
