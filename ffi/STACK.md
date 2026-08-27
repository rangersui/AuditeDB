# UniFFI FFI Stack

FFI is an Engine adapter. It binds the protocol-neutral Rust `Engine`, not the
HTTP server, routes, status codes, or `/proc/*` paths.

## Layers

1. **Scaffold** (`feat/ffi-uniffi-scaffold`)
   - Add isolated `l5-ffi` crate.
   - Compile as `lib` + `cdylib`.
   - Add UniFFI scaffolding and smoke exports only.

2. **Handle + Type Boundary**
   - Add `FfiEngine` handle with an embedded Tokio runtime.
   - Add UniFFI DTOs for config, access tier, representation, read/write
     results, snapshots, audit verification, and errors.
   - Keep constructors and conversions Engine-bound.

3. **Engine Verbs + Introspection**
   - Bind `read`, `replace`, `append`, and `delete`.
   - Bind `delete_with_metadata` for adapters that need DELETE audit rows to
     preserve representation content-type and metadata headers. Plain
     `delete` intentionally records empty metadata, matching `Engine::delete`.
   - Bind typed introspection: `worlds`, `du`, `df`, `pool`,
     `audit_verify(world)`.
   - Do not expose `HEAD`, HTTP methods, HTTP responses, or `/proc/*` route
     names.

4. **Subscribe Receiver**
   - Bind `subscribe(pattern, tier, resume) -> FfiSubscription`.
   - Expose `next(timeout_ms) -> FfiSubscriptionNext` with typed `Event`,
     `Timeout`, `Lagged`, `Closed`, and `Unknown` states.
   - Translate core event method strings into Engine verbs
     (`Replace`/`Append`/`Delete`) before crossing the FFI boundary.
   - Let dropping the subscription object release the Engine slot; avoid a
     callback-first ABI.
   - Expose `close()` so garbage-collected language bindings can release the
     Engine slot deterministically instead of waiting for finalization.
   - Avoid callback-first FFI; language wrappers can build iterators or async
     streams on top of `next`.

5. **Artifact CI Matrix**
   - Build and smoke native FFI libraries plus generated Python UniFFI binding:
     - Linux x64 (`.so`)
     - Linux ARM64 (`.so`)
     - macOS ARM64 (`.dylib`)
     - Windows x64 (`.dll`)
   - Upload zipped CI artifacts containing the native library, generated
     `l5_ffi.py`, and a manifest with the native library hash.

6. **Release Integration**
   - Attach FFI artifacts to tagged releases once the CI artifact shape is
     validated.
   - Fail tagged releases if `ffi/Cargo.toml` does not match the tag version,
     so `ffi_version()` and attached native libraries cannot drift.
   - Add FFI packages to release checksum manifests.
   - Document OpenWrt/MIPS as a cross-toolchain target, not a guaranteed
     GitHub-hosted runner output.

7. **OpenWrt/MIPS Cross-Toolchain Boundary**
   - Keep MIPS out of the hosted artifact matrix until a real OpenWrt SDK,
     Rust standard-library support, and a QEMU or hardware smoke path exist.
   - Document the proof chain required before an OpenWrt `.so` can be attached
     to a release.
   - Do not treat Linux ARM64 as a proxy for MIPS; it proves the hosted ARM64
     runner only.

## Boundary Rules

Allowed:

- Engine verbs: `read`, `replace`, `append`, `delete`, `subscribe`
- Engine typed introspection: `worlds`, `du`, `df`, `pool`,
  `audit_verify(world)`
- Engine DTOs: representations, preconditions, ETags, change events, snapshots

Forbidden:

- HTTP method names as FFI verbs (`GET`, `HEAD`, `PUT`, `POST`, `DELETE`)
- `/proc/*` route names
- HTTP status codes as the public FFI result model
- server/router/handler types
- adapter-specific auth/header/pipeline concepts

## Header Persistence

The FFI adapter passes representation headers through to the Engine without
filtering. This is by design:

- The Engine treats headers as opaque metadata.
- Only the HTTP adapter applies a persistence allowlist because browsers
  interpret response headers as security directives.
- The HTTP read path applies an L1 hard-deny filter on output regardless of
  which adapter wrote the data.
- Non-browser consumers (FFI) treat headers as plain key-value
  metadata with no execution semantics.

FFI callers are responsible for the content they store. If an FFI-written
header is later served through the HTTP adapter, the HTTP output filter is the
safety net, not the FFI write path.

## Coverage Discipline

FFI should keep a strict coverage habit from layer 1 onward. The coverage goal
applies to hand-written library code and exported adapter behavior, not to
generated UniFFI scaffolding.

- Every hand-written `#[uniffi::export]` function must have a direct Rust test.
- Every Engine-bound export must cover success and failure paths.
- Every FFI error conversion must be tested so errors stay typed and are not
  collapsed into strings.
- `cargo llvm-cov --manifest-path ffi/Cargo.toml --lib --fail-under-lines 100`
  is the intended gate for hand-written library code.
- Generated UniFFI scaffolding, macro expansion, and the `uniffi-bindgen` CLI
  smoke entry are not part of the 100% line-coverage promise.
