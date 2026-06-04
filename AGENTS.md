# Agent Instructions

## 500-line hard limits

PR economics inverted when AI became the reviewer:

- **Human reviewer**: 10 small PRs = 10 context switches → prefers big PRs.
- **AI reviewer**: 1 big PR > context window → prefers small PRs.

This codebase optimizes for the AI reviewer. The 500-line ceiling is the
forcing function that makes that work.

Direct consequence: **each commit is a PR**. Continuous integration's
real form when the reviewer is an AI is "every mergeable change ships
on its own". 30 minutes of coding → commit → PR → AI review → merge →
next. No batching. No save-up-for-Friday-review meeting. Human
programmers find this annoying; AI co-authors thrive on it.

### The two budgets

- **No `.rs` source file exceeds 500 lines** of *production* code.
- **No PR diff exceeds 500 lines** of *production* code.
- Both limits derive from one constraint: AI co-authors (Codex,
  Copilot, Claude) cannot reliably hold more than ~500 lines of context
  at once. Past that they hallucinate, contradict prior parts of the
  same file/PR, or silently skim.
- **Test code does not count toward either budget.** `#[cfg(test)] mod
  tests { ... }`, `#[tokio::test]` blocks, and integration tests under
  `tests/` are stereotyped: each test is independently legible, and a
  reviewer scans them top-to-bottom rather than holding the whole
  module in working memory. A 200-line production module with 600
  lines of tests is one self-contained reviewable unit, not a budget
  violation. (Reference precedent in this codebase:
  `sdk/tests/e2e_blackbox.py` is several thousand lines and reviewed
  one assertion at a time without trouble.)
- **Slight overage of the production budget is acceptable when the
  maintainer has read the change in full and explicitly signed off.**
  The budget is "AI working memory", not arithmetic — 510-550 lines
  with a human in the loop is fine, 1500 lines is never fine. The
  hard ceiling is "an AI agent can still hold the whole production
  surface at once"; exact threshold is judgment.
- Exceeding the production budget without sign-off requires splitting
  before review.

#### How to count

For most files: total `wc -l` minus the `#[cfg(test)] mod tests { ... }`
block. The block is contiguous and at the bottom of the file by
convention, so a quick `grep -n '^#\[cfg(test)\]' core/src/foo.rs`
gives the start line; the file's total minus that line number is
the production count (off by one or two for the trailing brace —
fine, the rule is judgment, not arithmetic).

When the production count is non-obvious or close to the limit,
paste it into the PR description so reviewers don't have to
re-derive it. For files with both inline `#[cfg(test)]` snippets
and a bottom `mod tests`, sum the production code by reading.

### Diff-only review

Reviewers see only the diff, never the surrounding file. This is the
optimal use of an AI context window: don't reload context that didn't
change.

Concrete consequence: **cascading PRs are the natural form, not a
workaround**. PR N's base branch is PR N-1, not master. Each PR's diff
is one self-contained increment. The reviewer never sees PR 0's lock
change while reviewing PR 4's pipeline extraction; only the pipeline
extraction.

```
master
└─ PR 0 (10 lines)
    └─ PR 1 (300 lines, base = PR 0)
        └─ PR 2 (150 lines, base = PR 1)
            └─ PR 3 (300 lines, base = PR 2)
                └─ PR 4 (500 lines, base = PR 3)
```

Without cascading, PR 4's diff = PR 0 + 1 + 2 + 3 + 4 = 1260 lines = AI
loses the thread. With cascading each PR is an independent 500-line
review.

### Cascade stack depth: 3-4 levels max

Cascading is not free. To review PR N a reviewer (human or AI) has
to first mentally accept PR 0 → PR 1 → ... → PR N-1, then read PR N's
diff against that imagined state. **Each level adds one item to the
mental stack.** Past 3-4 levels the stack overflows for the same
reason a single 1500-line PR overflows: working memory runs out.

The cascade form does not eliminate the budget; it changes what the
budget is spent on. Per-PR diff stays at 500 lines, but cumulative
stack-depth context is bounded too.

**The rule**:

- **Soft cap: 3 levels**. Comfortable.
- **Hard cap: 4 levels**. Acceptable when the bottom levels are
  small or trivial (e.g., one-line `chore/visibility-fix`).
- **Above 4: stop adding new PRs. Drain the stack first.**

**Draining**:

1. Merge the **bottom** of the stack (the level closest to master,
   typically the first-written PR) into master.
2. The level above it now has its base auto-redirected to master and
   becomes depth 1.
3. Keep merging upward until the stack is shallow enough.
4. Then resume opening new PRs.

```
Before drain:
  master → PR 0 → PR 1 → PR 2 → PR 3 → PR 4 → PR 5
                                              (depth 6, blown)

After merging PR 0, 1, 2:
  master(includes 0/1/2) → PR 3 → PR 4 → PR 5
                                              (depth 3, fits)
```

This is why the merge order matches the cascade order: oldest /
deepest-base first. Trying to merge a higher-up PR while a lower-down
PR is still open creates a divergent base that GitHub will not
auto-redirect cleanly.

### Pure-mv PRs

A PR that mechanically moves N lines from one file to another counts
cognitive surface as **insertions**, not total churn. Deletions are
byte-identical to insertions and verifiable by comparison; reviewers do
not re-read them as new logic. PR description must declare "pure mv"
explicitly so reviewers prioritize structural verification over
line-count arithmetic.

## Architecture Invariants

These are not preferences. They are the contract every change must keep.

- **Per-world locking, not global.** Writes to different worlds run concurrently;
  writes to the same world serialize through `Core::acquire_world_lock(world)`.
  No new global write mutex. Counters touched on the write path
  (`storage_body_bytes`, `durable_world_count`) must use `fetch_update` /
  `fetch_add` / `fetch_sub` so cross-world writers stay coherent.
- **Mechanism, not policy.** Core provides primitives — token tiers, path
  scopes, HMAC chain, change events, ETag/CAS, byte storage. Business logic
  (validation, transactional flows, schema evolution) lives in reactors and
  SDK code, not in core. Adding policy to core is a Phoenix violation.
- **Audit chains fail loud before write.** Durable writes must verify the
  existing HMAC chain before mutating bytes or appending an event. A missing
  audit table, unreadable previous HMAC, broken HMAC, dropped row, schema
  mismatch, or startup verification failure is a stop condition, never a
  reason to recreate tables or begin a fresh chain. Enforce this as
  mechanism: production append paths take a verified audit transaction type,
  not a raw SQLite transaction.
- **FSM pipeline is the contract for new verbs.** Every new HTTP verb on
  `/<world>` is one `pub(crate) async fn execute_*` exported through
  `bin/src/server/handler.rs`. Implementations live in
  `bin/src/server/handler.rs` (dispatcher + light verbs) or
  `bin/src/server/handler/<verb>.rs` (heavy verbs with their own audit / lock
  dance, e.g. `delete`). Use the
  unified primitives `execute_read` / `execute_write` for verbs
  that fit; structurally distinct verbs (multi-step audit,
  heterogeneous lock ordering) get their own file. Each `execute_*`
  returns either `Phase::ExecutedRead(Response)` (read verbs),
  `Phase::CommittedWrite(Response)` (write verbs), or
  `Phase::Error { resp, reason }`. The pipeline driver
  (`pipeline::run`) handles authentication, path canonicalization,
  validation, dispatch, error logging, and response return. Verb
  handlers do everything else.
- **Authentication vs authorization split.** The driver does
  *authentication only* — parses the `Authorization` header into an
  `auth::Tier` and stamps it onto `Phase::Authenticated`. The driver
  does **not** check whether that tier is sufficient for the
  requested verb + path. *Authorization* lives inside each
  `execute_*` because the gate is verb-and-path-specific
  (`PUT /home/` needs `Write`, `PUT /etc/` needs `WriteApprove`,
  `GET` needs `Read`, `DELETE` needs `Delete`). Hardcoding all
  permutations into a driver-side phase would either duplicate
  `can_read` / `can_write` / `can_delete` logic or require a new
  `Phase::Authorized` variant per verb — both worse than letting
  the verb gate itself.
- **Audit + notify ordering lives inside the verb handler**, not in
  the driver. The lesson reviewer consensus extracted from DELETE's
  intent / commit two-step. The FSM models the request envelope, not
  the storage transaction inside it. `CommittedWrite` means "this
  write is durably committed *and* its audit chain entry is signed
  *and* notify has fired" — a single observable boundary instead of
  three driver-level phases.
- **`ErrorReason` vocabulary is closed.** New error kinds add a
  variant to the `pipeline::ErrorReason` enum; arbitrary strings are
  forbidden. The one exception, `PathInvalid(&'static str)`, carries
  a closed set of reasons from `validate_world_name`. Strings as
  error reasons turn into log soup; an enum forces a fixed
  vocabulary the trace code, the metrics layer, and the SDK can all
  match on.
- **Cascade audit failures must be visible.** When an intent / commit
  dance hits a double failure (commit append fails AND the
  subsequent failure-event append also fails — e.g. persistent
  DiskFull), trace must surface BOTH failures via aux lines, not
  elide the second. PR 0's `delete_commit_failed` event closed the
  chain ambiguity *when the event itself can be written*; the trace
  closes the remaining ambiguity *when even the event-of-failure
  cannot be written*. `eprintln!` warnings stay (PR 0 contract) so
  operators reading stderr without trace enabled still see both
  failures.

## No fallback to unguarded paths

When a code path exists to enforce a safety invariant
(e.g., SlotState tracking fd lifetime, tombstone protocol,
HMAC audit chain), never add a fallback that bypasses it.

If the guarded path cannot run (cap reached, resource
exhausted, timeout), the correct responses are:

1. Run the guarded path with reduced retention (e.g.,
   track the fd but don't cache the connection)
2. Return an error (500, 503, 429)
3. Queue and retry

Never:

- Fall back to the pre-guard behavior ("today's code path")
- Skip the guard for "graceful degradation"
- Add a fast path that avoids the safety mechanism

The pre-guard behavior is the bug the guard was built to fix.
Falling back to it reintroduces the bug under a different
trigger condition.

### Drain before remove

For Arc-backed resources, map removal is not cleanup. A map entry is
only the rendezvous point. Any task that already cloned the Arc can
still hold a guard, a file descriptor, a SQLite snapshot, or some other
live resource outside the map.

The order is mandatory:

```
drain -> close fd -> remove
drain -> close fd -> remove
drain -> close fd -> remove
drain -> close fd -> remove
drain -> close fd -> remove
drain -> close fd -> remove
drain -> close fd -> remove
drain -> close fd -> remove
drain -> close fd -> remove
drain -> close fd -> remove
```

No exceptions. The rule applies to every cleanup path:

- DELETE removing a world
- transient slot cleanup after an at-cap read
- LRU eviction of an old read slot
- shutdown closing cached connections
- any future map-backed resource with Arc clones

Never remove first and trust that "this path is temporary" or "this is
just a cap fallback" or "LRU is different." Arc does not care why the
reference exists. If someone holds it, someone holds it. Their fd does
not disappear because the map entry did.

Correct cleanup:

```
1. Drain every active guard on the shared resource.
2. Close/drop the fd or equivalent live resource while the drain still holds.
3. Remove the map entry only after no cloned handle can keep the resource alive.
```

### LOTO is the precedent

Industrial safety has run this exact play for decades: Lockout /
Tagout (LOTO).

```
LOTO                    elastik
---------------------------------------------
high-voltage line   =   the world's .db file
energizing the line =   DELETE removing the file
maintenance worker  =   reader holding a Connection
worker's lock       =   Opening slot (with my Arc as the key)
direct tool use     =   Ready (cached connection reused)
"DO NOT ENERGIZE"   =   Tombstone
wait for all locks  =   drain via inner.write().await
                        before delete_world_blocking runs

LOTO rule:
-> one worker, one lock, with the worker's name on it
-> only that worker can remove their lock
-> the line stays dead until every lock is removed
-> NEVER enter the equipment without locking it out

= SlotState protocol
```

The LOTO rules are written in blood. Each line maps directly to a
fallback anti-pattern:

```
"no time to lock out"              -> killed
"just a quick look, skip the lock" -> killed
"ran out of locks, share one"      -> killed
"fall back to no-lock mode"        -> killed

no lock available? wait. get a temporary lock. report up.
never enter unguarded equipment.
```

The "ran out of locks" case is the cap fallthrough exactly. The v6 /
v7 cap fallback was the equivalent of "we ran out of LOTO padlocks, so
this maintenance team just won't lock out for the next shift." The fix
isn't fewer locks; it's a temporary lock from the supply room: install
it, work, return it. SlotState is the lock; the cap controls how many
persist in the rack, not whether you carry one onto the equipment.
v8's transient slot is the temporary-lock checkout.

### Origin

sqlite-connection-pool v6 Bug 42. A cache cap fell back to
`world::read_with_hmac` (the pre-SlotState path), reintroducing
the v1 fd race that five rounds of review had closed. Seven
rounds to learn: safety mechanisms don't have off switches.

LOTO took the industry decades and a body count. elastik took seven
review rounds and 47 bugs. Same lesson, smaller blast radius, but the
same reason this rule has its own section in the agent manual: every
"just this once, fall back" is the bug that re-energizes the line.

## Physics, not policy

The rules above ("No fallback to unguarded paths", "Drain before
remove") are policy. Policy depends on every future contributor —
human or AI — reading the rule, remembering it, and applying it
correctly. Policy fails probabilistically: the larger the codebase,
the more contributors, the more bugs slip through review.

Type-system enforcement is physics. The compiler refuses to build
the bug. The wall has no window; nobody climbs through.

When you can prevent a class of bug by making that bug uncompilable,
do that instead of writing a rule. The rules become unnecessary and
review becomes redundant — both are net wins.

### The pattern

When an invariant says "X must always go through Y first", make Y
the only constructor of the type X consumes.

Example (sqlite read path, v10):

```rust
// Only OpeningTransition::promote can build this.
// No public ::new(), no public ::from_raw().
pub(crate) struct TrackedReadConnection(rusqlite::Connection);

mod opening {
    use super::*;
    impl TrackedReadConnection {
        // Visible only inside this module. The only call site is
        // OpeningTransition::promote below.
        pub(super) fn from_raw(conn: rusqlite::Connection) -> Self {
            TrackedReadConnection(conn)
        }
    }

    impl OpeningTransition<'_> {
        pub fn promote(self, conn: rusqlite::Connection) {
            let tracked = TrackedReadConnection::from_raw(conn);
            // ... mem::replace SlotState::Ready(StdMutex::new(tracked)) ...
        }
    }
}

// Every read function takes the tracked type:
pub(crate) fn read_with_hmac_via_conn(
    conn: &mut TrackedReadConnection,
) -> rusqlite::Result<...> { ... }

// world::read_with_hmac (the bare per-request open + SQL bypass)
// IS DELETED. There is no public read entry point that takes a
// raw rusqlite::Connection.
```

A future contributor (or AI co-author) wanting to "just open the
file directly" gets a `rusqlite::Connection` from
`Connection::open_with_flags`. Every read function in `world.rs`
demands `&mut TrackedReadConnection`. The contributor cannot
construct one without going through `OpeningTransition`, which is
only reachable from inside the slot-before-open dance, which only
runs inside the SlotState protocol.

The bypass code does not compile. AGENTS.md does not need to forbid
it. Reviewers do not need to catch it. It is physically unwritable.

### When to encode an invariant in types

- **The invariant has been re-discovered via review three or more
  times.** That's the signal: the rule is non-obvious enough that
  policy alone keeps failing. SlotState gating was re-discovered in
  v6 (Bug 42), v7 (cap-fallthrough closure), v8 (transient slot),
  and v9 (drain before remove). Four rounds of "we forgot this
  layer." Type encoding turns the rule into the only writable shape.
- **The invariant is structural, not workload-dependent.** "Reads
  must hold the slot's read guard" is structural — types can express
  it. "Don't call this more than 100 times per second" is
  workload-dependent — types can't express rates.
- **The cost is one newtype + a couple of constrained signatures.**
  Type encoding pays for itself when it removes a class of bugs and
  costs <50 lines of plumbing.

### When not to bother

- The invariant only matters in one place. A `debug_assert!` or a
  100-line review of one function is cheaper than a newtype that
  ripples through downstream signatures.
- The invariant leaks lifetimes everywhere. Self-referential structs,
  unwieldy `<'a>` parameters propagating through the codebase, or
  `unsafe` workarounds — the ergonomic cost outweighs the safety
  win. Use a `RefCell`-like runtime guard instead.
- The invariant is for one release and the surface is moving fast.
  Type encoding is best for invariants that are *contracts*, not
  scaffolding.

### Industrial precedent

Manufacturing calls this **poka-yoke** (mistake-proofing): plug
shapes that only fit the right socket; nuclear control rods that
can't be inserted backwards; medical IV connectors that physically
cannot connect to the wrong tubing. The principle is the same —
make the wrong action geometrically impossible, not just procedurally
forbidden.

LOTO is policy: workers must lock out before entering. Poka-yoke is
physics: the equipment has no openable panel until power is killed
upstream. Both have their place; physics is stronger when you can
afford the geometry.

### Origin

sqlite-connection-pool v9 → v10. Nine review rounds wrote the rule
"no bypass to unguarded paths." v10 made the rule
unenforceable-by-policy by removing the policy layer entirely: the
bypass code does not compile. Review caught the rule violations;
types prevent the rule violations from existing.

The graduation from runtime guards to compile-time guards is the
last fence on this chase. Future Arc-backed resources (plugin
worlds, sidecar caches, FastCGI connection pools) get the same
treatment up front.

## Endpoint Change Checklist

Every new binary-adapter route should pass the same small checklist before review:

- Blocking: filesystem or SQLite work that can outlive a quick metadata read
  runs through `spawn_blocking`, not directly on a Tokio worker.
- Explicit errors: expected failures use `?` or explicit mapping into HTTP
  status codes; helpers must not silently turn storage errors into empty data.
- Phoenix schema: do not add legacy or forward-compatibility fallbacks for old
  on-disk worlds. If persisted data violates the current schema, fail loudly as
  storage corruption; do not migrate, coerce, or silently reinterpret it.
- Auth: read paths go through `can_read`; write/delete paths go through
  `can_write` or `can_delete`.
- Notification: mutations call `notify` after the externally visible fact they
  report has actually happened. Later bookkeeping failure must not suppress an
  event for a physical state change that clients can already observe.
- Audit: durable writes and deletes enter the HMAC chain; read-only `/proc/*`
  paths do not pretend to be audit events.
- Headers: any replayed persisted headers pass through the denylist on output,
  not only on input.
- Resource bounds: route-local queues, scans, buffers, and response bodies have
  an explicit cap or an explicit "management endpoint" rationale.
- Storage semantics: write paths enforce world size / memory / durable quota
  and map storage exhaustion to `507 Insufficient Storage`.
- Docs: README and `.env.example` describe the same path, env var, status code,
  and output shape as the implementation.
- Tests: add at least one happy path and one error/denied/overload path.

## Rust Core PR Review Checklist

When reviewing Rust core changes, look for recurring boundary mistakes before
looking for style issues:

- Async boundary: any filesystem walk, SQLite open/query loop, retry sleep, or
  quota scan on a request path must either be tiny and documented or run through
  `spawn_blocking`. This applies to helpers called by handlers, not just the
  handler body.
- Error propagation: storage helpers must return `Result` and use `?`; never
  turn `prepare` / `query_map` / row iteration failures into empty metadata,
  empty headers, or default values that later enter the audit chain.
- Phoenix data layout: current schema is the contract. Do not preserve
  compatibility with pre-Phoenix worlds, SQLite dynamic typing accidents, or
  future schema guesses. `body` is BLOB; TEXT in that column is corruption and
  should surface as a storage error, not be coerced into bytes.
- Expected failures: disk full, SQLite full, body too large, overload, and
  auth failure are protocol states, not panics. Map them to `507`, `413`, `503`,
  or `401/403` as appropriate. Do not `expect()` on storage operations that can
  fail in production.
- Audit semantics: durable mutations must record the correct fact. Use
  intent/commit events when the action has phases; do not sign an intent as a
  completed fact. Metadata used for audit hashing must come from successful
  reads only.
- Notification semantics: `notify` reports externally visible state, not audit
  bookkeeping success. If a mutation has phases, emit only after the physical
  fact has happened; use separate event types if callers need pending/failure
  visibility. For delete, distinguish `delete_intent`, `delete_commit`, and
  best-effort `delete_commit_failed` rather than overloading intent-only with
  multiple meanings.
- Constant-time posture: HMACs, audit hashes, token-like values, and anything
  used to prove integrity should use `auth::ct_eq` or equivalent constant-time
  comparison. Empty or whitespace-only integrity keys must fail at startup.
- Header semantics: persisted headers are checked on input and checked again
  before replay. Any Rust denylist change must keep Python SDK exact entries
  and prefix rules in parity.
- Path semantics: if core rejects a path form, SDK clients should reject it
  before network I/O too. Include encoded dot segments, empty segments,
  namespace roots, and reserved `/proc/*` exceptions in tests.
- Cross-surface parity: when a status or limit changes in HTTP, check CoAP
  mappings, Python SDK path/proc allowlists, JS SDK assumptions, README, and
  `.env.example`.
- Resource caps: every new long-lived connection, queue, replay ring, datagram
  in-flight set, or management scan needs a configured cap, an explicit
  overload response, and a regression test for the saturated path.
- `/proc/*` discipline: proc endpoints are read-gated introspection, not worlds.
  They should not emit audit events, replay user headers, or trigger listen
  notifications. If they scan durable state, treat them as blocking work.
- Review evidence: before saying a Rust PR is ready, run or cite the relevant
  manifest checks. For Engine/library changes, use
  `cargo fmt --manifest-path core/Cargo.toml -- --check`,
  `cargo clippy --manifest-path core/Cargo.toml -- -D warnings`, and
  `cargo test --manifest-path core/Cargo.toml`. For binary-adapter changes,
  add `cargo fmt --manifest-path bin/Cargo.toml -- --check`,
  `cargo clippy --manifest-path bin/Cargo.toml --all-targets -- -D warnings`,
  and `cargo test --manifest-path bin/Cargo.toml`. Also run the SDK smoke tests
  touched by the change, `python tools/header_policy_scan.py --offline` when
  header policy is involved, and `git diff --check`.
