# UniFFI FFI Stack

FFI is an Engine adapter. It binds the protocol-neutral Rust `Engine`, not the
HTTP server, routes, status codes, or `/proc/*` paths.

## Layers

1. **Scaffold** (`feat/ffi-uniffi-scaffold`)
   - Add isolated `elastik-ffi` crate.
   - Compile as `lib` + `cdylib`.
   - Add UniFFI scaffolding and smoke exports only.

2. **Handle + Type Boundary**
   - Add `FfiEngine` handle with an embedded Tokio runtime.
   - Add UniFFI DTOs for config, access tier, representation, read/write
     results, snapshots, audit verification, and errors.
   - Keep constructors and conversions Engine-bound.

3. **Engine Verbs + Introspection**
   - Bind `read`, `replace`, `append`, and `delete`.
   - Bind typed introspection: `worlds`, `du`, `df`, `pool`,
     `audit_verify(world)`.
   - Do not expose `HEAD`, HTTP methods, HTTP responses, or `/proc/*` route
     names.

4. **Subscribe Receiver**
   - Bind `subscribe(pattern, tier, since) -> FfiSubscription`.
   - Expose `next(timeout_ms) -> Option<ChangeEvent>` and `close`.
   - Avoid callback-first FFI; language wrappers can build iterators or async
     streams on top of `next`.

5. **Build + Distribution Matrix**
   - Add CI/release jobs for native FFI libraries:
     - `x86_64-unknown-linux-gnu`
     - `aarch64-unknown-linux-gnu`
     - `x86_64-apple-darwin`
     - `aarch64-apple-darwin`
     - `x86_64-pc-windows-msvc`
   - Document OpenWrt/MIPS as a cross-toolchain target, not a guaranteed
     GitHub-hosted runner output.
   - Generate and package language bindings after the Engine surface is stable.

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
