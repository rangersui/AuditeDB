# Elastik v8.0.1 - Read cache hardening

v8.0.1 is a patch release for the v8 Engine line.

## Highlights

- **Approximate-LRU read cache.** Cap-full read-cache misses now evict cold,
  idle slots instead of always falling back to transient reads.
- **No false 404 during cleanup.** Cache eviction now uses a distinct Evicted
  state, so readers retry instead of confusing cleanup with deletion.
- **Opening race closed.** Slot publication now keeps the inner write guard
  before the slot becomes visible, and defensive retry handling covers any
  future Opening-state regressions.
- **Bounded retry fallback.** Read-cache retry loops have a fixed budget and
  fall back to transient reads instead of spinning forever under pathological
  contention.
- **Read-cache metrics are visible and honest.** `/proc/pool` now exposes
  read-cache evictions, and hit/miss/capped counters are charged once per
  external read rather than once per internal retry.
- **Public Engine data structs sealed.** Unstable Engine output structs are
  now `#[non_exhaustive]`, so future introspection fields can be added without
  repeating the same semver trap.

## Compatibility notes

- The HTTP, CoAP, SSE, Python SDK, and JavaScript SDK surfaces remain intended
  to be wire-compatible with v8.0.0.
- The public Rust `Engine` API remains behind `unstable-engine`; that surface
  may still change before stabilisation.

## Packages

- Rust crate / binary: `elastik-core` `8.0.1`
- Python SDK: `elastik` `8.0.1`
- JavaScript SDK: `@elastikjs/client` `8.0.1`
- npm binary companions:
  - `@elastikjs/core-linux-x64` `8.0.1`
  - `@elastikjs/core-linux-arm64` `8.0.1`
  - `@elastikjs/core-darwin-arm64` `8.0.1`
  - `@elastikjs/core-win32-x64` `8.0.1`
