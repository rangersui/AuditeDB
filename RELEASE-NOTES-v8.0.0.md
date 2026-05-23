# Elastik v8.0.0 - Audi-ted L5 Storage Engine

v8.0.0 is the Engine release.

The codebase now has a real split between the protocol-neutral Rust library
and the HTTP/CoAP/SSE binary adapter. The library exposes the unstable
`Engine` facade for embedded Rust callers; the binary consumes that facade
instead of reaching through adapter shortcuts.

## Highlights

- **Audi-ted L5 positioning.** Elastik is now described as an Audi-ted L5
  storage engine: five Engine verbs, one HMAC audit chain, and a subscribe
  stream that listens to every mutation.
- **Protocol-neutral Engine API.** `Engine` now owns read, replace, append,
  delete, subscribe, and typed introspection surfaces.
- **Adapter boundary hardened.** HTTP, CoAP, SSE, env-var parsing, signal
  handling, response rendering, and wire-specific header policy live on the
  binary side.
- **Type-sealed inputs.** Public paths, subscribe patterns, `/proc` endpoints,
  credentials, and replay/shutdown subscription states now flow through
  opaque proof types instead of raw strings and booleans.
- **Typed introspection.** `/proc/worlds`, `/proc/du`, `/proc/df`, `/proc/pool`,
  and audit verification are backed by typed Engine snapshots, then rendered
  by the adapter.
- **Release metadata aligned.** Rust, Python, JavaScript, and platform npm
  binary packages all move to `8.0.0`.

## Compatibility notes

- The HTTP and CoAP binary surfaces are intended to remain wire-compatible
  with the v7 line.
- The public Rust `Engine` API remains behind `unstable-engine`; that surface
  may still change before stabilisation.
- Library-only builds can avoid the HTTP stack:

```bash
cargo build --lib --no-default-features --features bundled-sqlite,unstable-engine
```

## Packages

- Rust crate / binary: `elastik-core` `8.0.0`
- Python SDK: `elastik` `8.0.0`
- JavaScript SDK: `@elastikjs/client` `8.0.0`
- npm binary companions:
  - `@elastikjs/core-linux-x64` `8.0.0`
  - `@elastikjs/core-linux-arm64` `8.0.0`
  - `@elastikjs/core-darwin-arm64` `8.0.0`
  - `@elastikjs/core-win32-x64` `8.0.0`

