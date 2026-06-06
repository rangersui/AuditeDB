# Elastik v7.1.0 — SQLite Connection Pool

A performance and safety release. The HTTP grammar — six verbs, one HTTP
disk — is byte-identical to v7.0.0. What's new is **per-world cached
SQLite read connections** behind a **type-system-enforced safety
protocol**, plus a **cached audit-ledger writer** that takes 2-3 file
opens off every DELETE.

## Highlights

- **Read connection cache** at `Core::read_cache`. Hot worlds skip
  `Connection::open_with_flags` — bench measured **455.9 µs warm** on
  a stock laptop, gone after the first GET. Memory bound to ~250 KiB
  per cached entry via `PRAGMA cache_size=-200`; default cap 5000
  entries (~1.25 GiB worst case), tunable via
  `ELASTIK_READ_CACHE_MAX_ENTRIES`.
- **Ledger writer cache** at `Core::ledger`. Every DELETE used to open
  `var/log/deletes` 2-3 times (existence check + intent + commit). One
  cached connection now covers all of them. The per-world write lock at
  `var/log/deletes` is gone — the inner `StdMutex<Option<Connection>>`
  is the sole serializer.
- **`TrackedReadConnection` type seal**. The cache uses a `SlotState`
  state machine to track fd lifetime in the synchronization primitive,
  not in chance. The newtype's only constructor is module-private and
  reachable solely from `OpeningTransition::promote`. Durable
  representation reads (`world::read_with_hmac_via_conn`) and audit
  verification (`audit::verify_chain_via_conn`) — the two paths the
  cache layer drives — consume `&mut TrackedReadConnection`. Opening a
  bare `Connection` and running either function on it is a type error,
  confirmed adversarially: `error[E0603]: struct OpeningTransition is
  private`. Metadata-only reads (`world::metadata`, `body_len`,
  `sizes`, `open_existing`) stay on the per-request open path —
  they're either startup-time, `/proc/du`/`/proc/df` polling, or quick
  stat-style queries that don't enter the cached read flow.
- **`/proc/pool` observability**. Eight metrics with Prometheus-style
  `counter` / `snapshot` labels: cache entries, tombstones, hits,
  misses, capped, open-fails, max entries, ledger writer inits. DashMap
  walk + ledger Mutex snapshot run inside `spawn_blocking`.
- **Three new doctrines in `AGENTS.md`**:
  - *No fallback to unguarded paths* — when a guarded code path
    enforces a safety invariant, never add a fallback that bypasses it.
  - *Drain before remove* — for Arc-backed map resources, map removal
    is not cleanup; drain every cloned handle's active guard first.
  - *Physics, not policy* — when an invariant has been re-discovered
    via review three or more times, encode it in types so the bypass
    is uncompilable. (LOTO/poka-yoke industrial precedent referenced
    in the doctrine doc.)

User-facing API: unchanged. Drop-in replacement for v7.0.0.

## Bench-gated decision

The whole plan was conditional on real `open_existing` warm latency
exceeding 50 µs. Local bench (`#[cfg(test)] mod sqlite_bench_sketch`
in `core/src/world.rs`, run via `cargo test --release sqlite_bench_sketch
-- --ignored --nocapture`):

```text
open_existing_warm: 455.9 us/iter (10000 iters in 4.56s)
open_full_warm:    695.8 us/iter (10000 iters in 6.96s)
```

Both well above the 200 µs *ship-with-confidence* threshold. Final
landed surface: ~470 production lines in the new `read_cache.rs`
(plus 306 test lines), ~110 production lines in the new `ledger.rs`,
and the wiring across `state.rs` / `audit.rs` / `proc.rs` / handlers
detailed in the line-count table below. At 2000 GETs/sec on hot
worlds, the cache saves roughly 900 ms/sec of pure SQLite open
overhead.

## SlotState protocol — the safety side

The naive shape `DashMap<String, Mutex<Connection>>` has a race: DELETE
removes the map entry, but in-flight readers holding cloned `Arc`
handles continue using their cached fd. Linux: orphan inode (harmless).
Windows: file-in-use → DELETE 500.

Eleven review rounds (10 design + 1 implementation) built up the
protocol. From `core/src/read_cache.rs`:

- **Slot-before-open** — a reader installs `SlotState::Opening` via the
  DashMap Entry API *before* calling `Connection::open_with_flags`, and
  holds the slot's `RwLock` write guard for the duration of the open.
  DELETE's drain naturally waits behind that guard.
- **Tombstone protocol** — DELETE replaces the slot's state with
  `Tombstone` *inside* the write guard window via `mem::replace`. The
  previous `Ready(Mutex<Connection>)`'s Connection drops here, fd
  closes here. By the time `delete_world_blocking` runs, no fd is alive.
- **Drain-before-remove** — at-cap "transient" slots install `Opening`,
  read through the slot, then drain via the same `mem::replace` dance
  before removing the map entry. The cap controls *persistence*, not
  *registration*. (Closes a v8→v9 race where Phase-1 cache hits could
  clone the transient `Arc` and outlive the map removal.)
- **Type-system enforcement** — production code cannot construct
  `SlotState::Opening`, cannot reach `OpeningTransition::new`, cannot
  call `TrackedReadConnection::from_raw`. The bypass that motivated the
  whole design — *open a Connection, run SQL through it, skip
  SlotState* — does not compile from any production module. A single
  `#[cfg(test)] pub(crate) fn test_only_wrap_raw_connection` is the
  named, audit-grep-able test bypass.

The full design history — 1900-line plan, 57 design bugs found across
ten review rounds, plus 15 implementation findings closed — is
maintainer-internal. The arc in one sentence: each round protected
the visible ownership boundary but missed one layer deeper, until v10
moved the central invariant from runtime convention into the type
system. The two AGENTS.md doctrines (*Drain before remove*, *Physics,
not policy*) and the eight commits in the v7.1 cascade are the
distilled output.

## `/proc/pool`

```text
read_cache_entries 7 snapshot
read_cache_tombstones 0 snapshot
read_cache_hits 1842 counter
read_cache_misses 11 counter
read_cache_capped 0 counter
read_cache_open_fails 0 counter
read_cache_max_entries 5000 snapshot
ledger_writer_inits 1 counter
```

`read_cache_capped > 0` means the workload's hot working set exceeds
`ELASTIK_READ_CACHE_MAX_ENTRIES`; at-cap reads still complete correctly
via a transient slot but skip persistent caching. Raise the cap if hit
rate drops. `ledger_writer_inits` should equal `1` in steady state
(lazy-init on first DELETE); higher values surface re-init events that
would otherwise be invisible. Same auth gating as `/proc/df`: read
token if `ELASTIK_READ_TOKEN` is set, otherwise public.

## Compatibility

| Surface | v7.0.0 → v7.1.0 |
|---|---|
| HTTP grammar | identical |
| CoAP grammar | identical |
| Auth tiers | identical |
| Audit chain | identical (same HMAC, same canonical headers, same chain shape; v7.0 worlds remain readable; no migrator) |
| Env vars | existing unchanged; one new optional: `ELASTIK_READ_CACHE_MAX_ENTRIES` (default 5000) |
| `/proc/*` | adds `/proc/pool` (read-gated like `/proc/df`); existing endpoints unchanged |
| SDKs | Python (`elastik`) and JS (`@elastikjs/client`) bumped to 7.1.0 to match; no API changes |

There is no migration step. Stop the old binary, start the new binary,
point it at the same `ELASTIK_DATA`. The cache populates lazily on
first read per world. The ledger writer stays cold until the first
DELETE.

## Bug fixes

- DELETE → GET race window on Windows where the cached fd held the
  database file. SlotState's `mem::replace` inside the write guard
  closes the fd before `delete_world_blocking` runs.
- `audit::verify_chain` (admin endpoint `/proc/audit/{world}/verify`)
  used to open a fresh `Connection` outside SlotState — the only
  remaining path that bypassed the type seal. Routed through
  `Core::cached_verify_chain` so DELETE drains in-flight verifies via
  the same protocol.

## Internal architecture (for archivists)

The v7.1 cascade in PR order:

| PR | Branch | What it shipped |
|---|---|---|
| #117 | `docs/agents-no-fallback-drain-physics-bench` | Three AGENTS.md doctrines + bench sketch |
| #118 | `feat/sqlite-pool-ledger-writer-cache` | `Core::ledger` cache; remove redundant world lock; Bug 16 race test |
| #119 | `feat/sqlite-pool-read-cache` | `read_cache.rs` + `TrackedReadConnection` + Bug 58 verify-via-slot + LedgerWriter extraction |
| #120 | `feat/sqlite-pool-proc-and-config` | `/proc/pool` + `ELASTIK_READ_CACHE_MAX_ENTRIES` + README + `.env.example` |
| #121 | `release/v7.1-sqlite-pool-cascade` | Cherry-pick re-target onto master after the stacked-base squash quirk |

Production-line state at v7.1.0:

```text
core/src/state.rs           468         (was 377 at v7.0.0; +91 for cache wiring)
core/src/read_cache.rs      469 prod    (new; 306 test lines)
core/src/ledger.rs          109         (new)
core/src/proc.rs            388         (was ~315; +73 for /proc/pool)
core/src/audit.rs           483         (verify_chain_via_conn extraction)
core/src/handler.rs         406         (was 395; +11 for clear_tombstone wiring)
core/src/handler/delete.rs  260         (was 308; -48, ledger writer cache + tombstone protocol)
core/src/handler/post.rs    168         (+3 for clear_tombstone)
```

`pipeline.rs` (the v7.0.0 acknowledged overage at 536 lines) is
untouched. Two files (`read_cache.rs` and `state.rs`) sit under the
500-line ceiling for production code; `read_cache.rs`'s test block at
the bottom is 306 lines, which AGENTS.md exempts from the budget.

The cascade reached `master` via PR #121 because the stack-base squash
pattern (each PR's base was the previous PR's branch, not master) made
GitHub's auto-rebase route the squash commits into the predecessor
branches instead of master. Cherry-picking the three squash commits
onto a fresh `release/v7.1-sqlite-pool-cascade` branch and merging that
single PR resolved the topology.

## Roadmap (not in 7.1.0)

- **PR 4e** (post-7.1): merge `execute_get` + `execute_head` →
  `execute_read(BodyMode::{Full, HeadersOnly})`. Architectural symmetry
  with `Phase::ExecutedRead`. Stays inside `handler.rs`.
- **PR 4f** (post-7.1): merge `execute_put` + `execute_post` →
  `execute_write(WriteMode::{Replace, Append})`. Folds
  `handler/post.rs` into `handler.rs`.
- **v7.2 candidate**: LRU eviction for cap pressure. The current cap +
  transient-slot dance is correct and memory-bounded — LRU becomes a
  pure performance optimization for at-cap working sets, not a
  correctness fix. Bench numbers via `/proc/pool` decide whether it's
  worth doing.

## Install

```bash
# Rust
cargo install elastik-core

# Python
pip install --upgrade elastik

# JavaScript
npm install @elastikjs/client@7.1.0
```

## Thanks

Solo-maintained by Ranger Chen with AI co-authoring. Eleven review
rounds — ten of design, one of implementation — across two AI
reviewers (Codex P1/P2/P3 findings + a separate adversarial reviewer).
The type seal at `core/src/read_cache.rs:75-159` is the round-eleven
reviewer (Codex) tightening `pub(crate)` to module-private after the
implementation already shipped — making the bypass code physically
uncompilable rather than merely "ugly to write."

The principle that emerged: **the rules in AGENTS.md describe physics
when the type system can carry them, and policy when it can't.** The
v7.1 cascade is the first elastik subsystem where the central
invariant lives in the compiler, not in convention.
