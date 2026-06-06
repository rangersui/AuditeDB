# AuditeDB v8.2.1 - public rebrand and docs cleanup

v8.2.1 is a patch release for the v8 Engine line.

This release publishes the public project rename from Elastik to AuditeDB while
keeping the engine, package, binary, import, and environment surfaces stable.
The product is AuditeDB; the engine remains the Elastik L5 Engine.

## Highlights

- **Public rebrand to AuditeDB.** README, repository metadata, SDK docs,
  issue templates, prompts, and wiki pages now use AuditeDB as the product
  name.
- **Engine identity retained.** `elastik-core`, `elastik-bin`, `elastik`,
  `@elastikjs/*`, and `ELASTIK_*` names remain unchanged.
- **README first screen simplified.** The README now opens with the plain
  model: a filesystem-backed flat key-value store with an audit trail,
  embeddable as a library or runnable through the `elastik-core` HTTP server.
- **Release notes moved.** Historical release notes now live under
  `release_notes/`, and the release consistency checker reads from that
  directory.

## Compatibility notes

- The Rust library package remains `elastik-core`.
- The server binary package remains `elastik-bin`, and still produces the
  `elastik-core` executable.
- The Python package remains `elastik`.
- The JavaScript packages remain `@elastikjs/client` and
  `@elastikjs/core-*`.
- Environment variables remain `ELASTIK_*`.
- HTTP, CoAP, SSE, MQTT, Python SDK, JavaScript SDK, FFI, and Rust Engine
  protocol/API shapes are not intentionally changed by this release.

## Operational notes

- GitHub repository metadata now points at `rangersui/AuditeDB`.
- Operators using PyPI Trusted Publishing should update the trusted publisher
  repository identity after the GitHub repository rename.
- CI and tag release jobs run `tools/version_consistency_check.py`, which fails
  if Rust manifests, Cargo locks, Python metadata, JavaScript package metadata,
  npm companion metadata, active docs, release notes, or the tag version drift.

## Packages

These are the planned v8.2.1 release artifacts. The release workflow validates
the version surface against the tag before publishing.

- Rust library crate: `elastik-core` `8.2.1`
- Repository Rust server binary package: `elastik-bin` `8.2.1`,
  producing the `elastik-core` executable
- Repository FFI Cargo package and GitHub Release assets: `elastik-ffi` `8.2.1`
- Python SDK: `elastik` `8.2.1`
- JavaScript SDK: `@elastikjs/client` `8.2.1`
- npm binary companions:
  - `@elastikjs/core-linux-x64` `8.2.1`
  - `@elastikjs/core-linux-arm64` `8.2.1`
  - `@elastikjs/core-darwin-arm64` `8.2.1`
  - `@elastikjs/core-win32-x64` `8.2.1`
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
