# Elastik v8.1.0 - MQTT, FFI, and the binary split

v8.1.0 is a minor release for the v8 Engine line.

This is not a patch-sized change. Since v8.0.1, Elastik has gained a separate
server binary package in the repository, an MQTT adapter, a UniFFI adapter, and
release infrastructure for native FFI artifacts. The public Rust `Engine` API
remains behind `unstable-engine`; the intended change is capability growth and
adapter separation, not a stable Engine API break.

## Highlights

- **Binary package split completed.** The protocol-neutral library remains in
  `core/` as package `elastik-core`. The server runtime now lives in `bin/` as
  package `elastik-bin`, while the deployed executable is still named
  `elastik-core`.
- **Core is now visibly protocol-neutral.** HTTP, CoAP, MQTT, SSE, env-var
  parsing, routing, response rendering, and server shutdown live on the binary
  side. The library keeps paths, bytes, ETags, auth tiers, HMAC audit chains,
  storage, subscriptions, and typed introspection.
- **MQTT 3.1.1 adapter added.** The binary can expose an MQTT-shaped storage
  adapter with inbound QoS 0/1/2 publish flows, subscription fanout, retained
  replay, per-session limits, pre-auth connection limits, duplicate
  `client_id` replacement, and read-gated MQTT metrics.
- **MQTT retain maps to Elastik storage tiers.** Non-retained publishes route to
  transient `tmp/` worlds. Retained publishes route to durable audited `home/`
  worlds and are replayed on subscribe within explicit message, byte, and scan
  caps. MQTT remains a storage adapter, not a full broker replacement.
- **UniFFI FFI adapter added.** `ffi/` builds a `cdylib`/`lib` adapter over the
  Engine facade with handle construction, token verification, read/replace/
  append/delete, delete metadata, typed introspection, blocking subscription
  receive, explicit subscription close, structured errors, and shutdown.
- **Native FFI artifact pipeline added.** CI and release workflows now build and
  smoke native FFI libraries plus generated Python UniFFI bindings for Linux
  x64, Linux ARM64, macOS x64, macOS ARM64, and Windows x64.
- **Release assets are checked harder.** The release workflow now verifies
  binary and FFI manifest versions against the tag, smokes FFI and npm install
  paths, publishes checksum manifests, and checks that GitHub Release, npm, and
  PyPI artifacts contain matching `elastik-core` bytes.
- **Tests now prove the public boundary.** Server-side tests were migrated away
  from private core fields and helper shortcuts. The binary adapter now drives
  fixtures through public `Engine` APIs, which makes the core/bin boundary
  harder to accidentally violate.
- **CI moved with the platform.** GitHub Actions and runner targets were updated
  for the newer hosted stack, including the `windows-2025-vs2026` runner label
  and newer major versions of checkout, Python setup, upload/download artifact,
  and related actions.
- **Documentation split tightened.** The root README is the Engine/library
  reference. HTTP, MQTT, CoAP, FFI, SDK, deployment, and architecture documents
  now describe their own adapter surfaces instead of leaking protocol details
  back into the Engine library.

## Migration steps

1. **Keep invoking the deployed binary as `elastik-core`.** The Cargo package
   that builds it is now named `elastik-bin`, but the executable name did not
   change. This split lets Cargo distinguish the repository's library package
   (`core/`, `elastik-core`) from the server adapter package (`bin/`,
   `elastik-bin`) while preserving the CLI and release asset name users already
   know.
2. **Update local build scripts from `core/target/...` to `bin/target/...` for
   server binaries.** The repository Makefile now builds and copies from
   `bin/target/release/elastik-core[.exe]`; any local scripts that scraped
   `core/target/release/elastik-core` need the same move.
3. **Use explicit Cargo manifests from the repository root.** `core/Cargo.toml`
   builds the library, `bin/Cargo.toml` builds the server adapters and
   executable, and `ffi/Cargo.toml` builds the UniFFI adapter.
4. **Treat protocol compatibility as wire compatibility.** Existing HTTP,
   CoAP, SSE, Python SDK, and JavaScript SDK clients should keep speaking the
   same protocol shapes as v8.0.1, but the internal crate layout and build paths
   changed.

## Bug fixes and hardening

- Closed a P2 ETag/precondition oracle edge so failed conditional writes do not
  leak more version information than the protocol requires.
- Hardened first DELETE/delete-ledger creation so concurrent first deletes
  create one valid `var/log/deletes` ledger rather than racing ledger setup.
- Tightened `/proc/df` world-count accounting and assertions so durable and
  memory world totals stay honest after the crate split.
- Added an explicit listen/error arm so stream errors are reported through the
  adapter path instead of being hidden behind a missing match case.
- Moved bin-side tests away from private core internals, which makes these bug
  fixes exercise the public Engine boundary instead of test-only shortcuts.

## MQTT notes

The MQTT adapter is intentionally scoped:

- It speaks MQTT 3.1.1.
- It requires clean sessions.
- It does not implement persistent sessions, Last Will, shared subscriptions,
  MQTT v5 properties, `+` single-level wildcards, or in-process TLS.
- TLS/mTLS should be terminated before exposing MQTT outside loopback.
- Outbound fanout is QoS 0 and may drop notifications for slow clients.
- DELETE events do not produce MQTT publishes.

Retained replay is fail-loud. If the adapter cannot prepare retained replay for
a filter, or if a replay cap is exceeded, that filter receives SUBACK Failure
instead of a false-success subscription with silently missing retained state.

## FFI notes

The FFI adapter is an Engine adapter, not an HTTP binding:

- FFI callers use Engine-shaped verbs and typed DTOs.
- FFI does not expose HTTP status codes, route names, or `/proc/*` paths.
- Access tiers are caller-supplied at the FFI boundary; token verification is
  available for host applications that want to derive tiers from configured
  token bytes.
- Representation headers remain opaque Engine metadata. The FFI adapter does
  not apply HTTP browser-policy filtering, though it normalizes header names and
  de-duplicates them before storage. Browser-facing header filtering remains the
  HTTP adapter's responsibility.
- `FfiSubscription.close()` releases Engine listen slots deterministically for
  garbage-collected language bindings.

OpenWrt/MIPS remains documented as a cross-toolchain boundary, not a hosted
release artifact. The hosted FFI artifact matrix covers Linux x64, Linux ARM64,
macOS x64, macOS ARM64, and Windows x64.

## Compatibility notes

- The `elastik-core` executable name remains unchanged.
- The Rust library package remains `elastik-core`.
- The server binary package is now `elastik-bin`, but it produces the
  `elastik-core` executable.
- Repository-root Cargo commands should use explicit manifests:

```bash
cargo build --manifest-path core/Cargo.toml --lib --no-default-features --features bundled-sqlite,unstable-engine
cargo build --manifest-path bin/Cargo.toml
cargo build --manifest-path ffi/Cargo.toml
```

- HTTP, CoAP, SSE, Python SDK, and JavaScript SDK surfaces are intended to keep
  the same protocol-level request, response, and event shapes as v8.0.1.
- The public Rust `Engine` API remains behind `unstable-engine`; that surface
  may still change before stabilization.
- MQTT and FFI are new surfaces in this release. Treat them as adapter
  foundations with explicit documented limits, not as promises that every
  broker or language-package feature already exists.

## Operational notes

- MQTT counters are exposed through read-gated HTTP introspection at
  `/proc/mqtt/metrics` when MQTT is enabled.
- The MQTT listener is disabled by setting `ELASTIK_MQTT_PORT=0`.
- `ELASTIK_MQTT_CONNECT_TIMEOUT_MS` and `ELASTIK_MQTT_MAX_PREAUTH_PER_IP`
  control the pre-auth socket window.
- `ELASTIK_MQTT_HOST` defaults to `ELASTIK_HOST`.
- `ELASTIK_MQTT_MAX_PACKET_BYTES` defaults to parsed
  `ELASTIK_MAX_WORLD_BYTES + 1024`.
- `ELASTIK_MQTT_MAX_CONNECTIONS` defaults to `1024` concurrent MQTT TCP
  sessions.
- `ELASTIK_MQTT_MAX_PENDING_QOS2_BYTES` bounds uncommitted QoS 2 payload
  memory per MQTT session.
- FFI release artifacts include a native library, generated Python binding, and
  a manifest containing the native library SHA-256.
- GitHub Release core binary assets intentionally omit macOS x64. The JavaScript
  SDK documents `darwin-x64` as intentionally out of the Rust release matrix,
  while FFI still builds macOS x64 native-library artifacts.
- `profile.release` remains the normal optimized release profile. The
  `profile.rut241` profile is a size-oriented release derivative for the RUT241
  / OpenWrt build path.

## Packages

These are the v8.1.0 release artifacts. The release workflow validates the Rust
manifests against the tag before publishing.

- Published Rust library crate: `elastik-core` `8.1.0`
- Repository Rust server binary package: `elastik-bin` `8.1.0`,
  producing the `elastik-core` executable
- Repository FFI Cargo package and GitHub Release assets: `elastik-ffi` `8.1.0`
- Python SDK: `elastik` `8.1.0`
- JavaScript SDK: `@elastikjs/client` `8.1.0`
- npm binary companions:
  - `@elastikjs/core-linux-x64` `8.1.0`
  - `@elastikjs/core-linux-arm64` `8.1.0`
  - `@elastikjs/core-darwin-arm64` `8.1.0`
  - `@elastikjs/core-win32-x64` `8.1.0`
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
