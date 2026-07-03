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
  violation. Large scenario tests remain acceptable when each assertion is
  independently legible and production code stays reviewable.
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

### Commit-level review

Review the smallest coherent change that can stand on its own. A commit should
have one reason to exist, a clear revert boundary, and validation evidence that
matches its risk. When a mechanical rename, generated binding refresh, or
archive cleanup exceeds the normal diff budget, say that explicitly in the
commit message or review note so reviewers know to verify mechanics rather than
read it as new logic.

Do not use history shape as a substitute for correctness. Linear commits are
preferred for solo maintenance; split only when it helps review or rollback.

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
  elide the second. The `delete_commit_failed` event closes the chain
  ambiguity *when the event itself can be written*; the trace closes
  the remaining ambiguity *when even the event-of-failure cannot be
  written*. `eprintln!` warnings stay as an operator contract so
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
LOTO                    auditedb
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

LOTO took the industry decades and a body count. auditedb took seven
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

## Sealed-Type Boundary Rules

Three enforcement rules that make the "physics, not policy" doctrine
concrete at API boundaries. These are review-blocking, not advisory.

### Type Seal Policy

This section takes precedence over the older "when not to bother"
ergonomics guidance above whenever the value is proof-bearing. If a
new or touched API accepts, returns, stores, or forwards a domain,
security, authority, resource-lifetime, or storage-layout value, the
proof travels with the value. Ergonomics can choose runtime vs
compile-time enforcement only for invariants that do not carry such a
proof.

New and touched internal APIs MUST consume validated/sealed types
(`ValidatedWorldPath`, `SecretBytes`, `AuditHmacKey`,
`TrackedReadConnection`, …) whenever the value carries domain,
security, authority, resource-lifetime, or storage-layout meaning.
Existing unsealed APIs are debt, not precedent: a PR may leave
unrelated legacy debt alone, but it may not spread it to new call
sites.

Raw primitives (`&str`, `&[u8]`, `u64`) are permitted only in four
places:

1. Parse/validation constructors that mint the sealed type.
2. The final intended primitive sink that binds to OS / SQLite /
   FFI / wire APIs. "Final" is not enough: the sink must be the
   operation the seal exists to permit. Binding a validated world path
   into a SQL query is a sink; logging a secret or returning it over a
   response body is exfiltration, not a boundary exception.
3. Plain mechanical values whose primitive form is the domain
   (counts, lengths, byte offsets, durations) and carries no missing
   proof. The examples are not blanket permission: a quota, generation,
   TTL, cursor, or offset that carries authority or storage identity
   needs a type.
4. Opaque payload bytes whose primitive form is the stored data
   (`&[u8]`, `Bytes`, `Vec<u8>`). Payload helpers may hash, copy, or
   transform bytes. The path/key/secret/cursor describing those bytes
   still needs its own seal.

"SQLite boundary" means the final bind/unbind expression, not any
helper that happens to run near SQL. `world_db(data, world: &str)` is
not a boundary; `params![world.as_str()]` at the call site may be.

If a non-boundary proof-bearing raw value seems unavoidable, the fix is
a sealed type or a narrower final-boundary wrapper that accepts the
sealed type and unwraps it only inside the boundary expression. A
PR-description waiver or naming convention is not a type seal.

**Origin:** the core/ path audit found `ValidatedWorldPath` reaches the
public Engine API, then gets unwrapped before lower storage helpers:
`world.rs` internals (`open`/`world_db`/`metadata`) all take `&str`, so
the seal is strong at the facade and thin near the side effect. The
proof must reach the side-effect site, the way `TrackedReadConnection`
carries it all the way to SQL.

### FFI Boundary Rule

FFI exports lower through generated ABI / FFI-shaped types — that is
physics, not a style choice.

After crossing back into Rust, FFI code may do only boundary work on
raw values: null checks, length checks, `CStr` / slice construction,
UTF-8 decoding, ownership conversion, and calls to validators. Before
dispatching to any non-boundary Rust function/method or any engine/core
operation, it MUST re-seal into validated types. If no seal exists for
a new/touched domain-security-resource value, creating that seal is
part of the change. Existing unsealed FFI values such as raw numeric
resume cursors are debt, not precedent: touching that path must either
seal it or keep the raw value trapped at the boundary. A proof-bearing
raw `String`/`Vec<u8>`/`u64` that reaches any non-boundary helper on
the Rust side of an FFI entry is a review-blocking defect. Opaque
payload bytes may remain raw payloads.

**Origin:** the v8.3.0 HMAC key seal (#322): `ffi` re-seals HMAC
secrets at the boundary via `AuditHmacKey::new` and maps rejections to
`FfiError::InvalidSecret` with the reason intact. Raw payload bytes
remain payload bytes; raw HMAC secrets do not. Existing raw token and
cursor paths are debt covered by this rule, not proof that the boundary
is safe.

### Error Handling Policy

Reason-erasing calls on validation results are BANNED outside
`#[cfg(test)]`: `.ok()`, `.unwrap_or(..)`, `.unwrap_or_default()`,
`.unwrap_or_else(..)`, `filter_map(Result::ok)`, and broad
`map_err(|_| ...)` conversions that discard the validator's reason.
Validation errors MUST propagate with their reason.

A validator that returns `Err("must be at least 32 bytes; got 16")`
exists for exactly one reader: the operator who set the value. Eating
the error with `.ok()` converts "your key is too short" into
"no key configured" — a worse lie than a crash.

For validation-bearing types, lossy or coercive constructors must be
boundary-only and named as such (`from_wire_lossy`, `canonicalize_*`,
etc.). Internal protected paths use fail-loud constructors (`try_new`,
`parse`, `validate`) or already-sealed values. Silent coercion plus
silent filtering is how a typo'd subscribe pattern becomes a
subscription that never fires and never errors.

**Origin:** the v8.3.0 HMAC key seal (#322): the `bin` env parser had
to become `Result<Option<AuditHmacKey>, InvalidHmacKey>` instead of an
optional raw byte parser, so short-key rejections reached the operator.
This rule keeps validation paths from drifting back toward "absence,"
"invalid," and "silently ignored" all meaning the same thing.

## Panic Discipline

Unsafe is a compiler wall, not a review preference. Production crates
default to `#![deny(unsafe_code)]`; any exception must be local,
documented, and treated as a boundary crossing. Adapter crates that do
not own an audited unsafe boundary, including `bin` and `ffi`, also carry
CI `-D unsafe_code` gates.

Production crates carry
`#![deny(clippy::unwrap_used, clippy::expect_used)]` at the crate root
(tests get a module-level `allow`). Reviewers enforce that the crate-root
lint wall stays present and that new or touched production code does not
add a naked `unwrap` / `expect`.

A new production `unwrap`/`expect` requires a local lint suppressor with
a nearby `Invariant:` or `Poison means` comment; CI enforces that with
`tools/panic_discipline_scan.py`. The suppressor must name the exact
panic lint (`clippy::unwrap_used` or `clippy::expect_used`); group
suppressors such as `clippy::all` or `clippy::restriction` are not valid
panic-discipline escapes. That escape is only for impossible states inside
this codebase, never for validation, IO, config, storage, FFI, auth,
audit, or user-controlled input.
Expected failures are protocol states (`507`/`413`/`503`/`401`), never
panics. Panics are reserved for invariant violations that indicate a bug
in *this* codebase, and even those prefer typed `InternalInvariant`
errors at public boundaries.

**Origin:** the core/ audit found that most `unwrap`/`expect` use was
test-only, while production relied on review discipline. The lint gate is
now part of the crate root contract; this rule prevents new debt and keeps
local suppressors narrow, documented, and auditable.

## Security Constants Cite Their Standard

New and touched security-relevant constants — key lengths, hash output
sizes, nonce sizes, iteration counts, length prefixes,
security-meaningful timeouts — carry a doc comment citing the governing
standard when one determines the value. When the value is local policy
or capacity engineering, cite the local threat model or design invariant
instead. Existing bare constants are debt, not precedent.

A bare `const MIN_KEY: usize = 32;` is magic: a reviewer cannot evaluate
whether 32 is right, and a future "simplifier" can lower it without
tripping anything but vibes. `/// RFC 2104: HMAC keys SHOULD be at least
the hash output length (SHA-256 = 32 bytes)` makes the constant
falsifiable — wrong values now contradict a citation, not a feeling.

**Origin:** `MIN_HMAC_KEY_BYTES = 32` (#322), grounded in RFC 2104. The
domain-separation framing in `hmac_field` carries the same obligation
when a standard governs the choice; operational caps carry local
rationale instead.

## Design First

Behavior-level changes — new semantics, new wire contracts, storage format
changes, new subsystems — get a `PLAN-*.md` design document reviewed to
convergence BEFORE the first implementation line. Code-level changes
(bug fixes within existing semantics, refactors, doc sync) do not.

Every behavior-level plan carries a **Precondition Challenge** section:

- hidden assumptions in the proposal;
- each assumption classified as physics or policy;
- policy assumptions either dissolved or explicitly kept with rationale;
- residual physics after the policy assumptions are removed;
- the smallest counterexample that would falsify the proposed frame.

This is mandatory for listen/resume, CAS, storage-history, auth, audit,
wire-contract, and delete semantics. A plan that says "given X cannot
exist" must prove X is physics. If X is only current implementation
policy, the plan either dissolves it or states why the policy is being
kept. Do not optimize inside a false premise.

Changing a plan is usually much cheaper than changing code. The design
review's job is to ask "should this machine exist, and is its frame
right?" — questions a code review structurally cannot ask, because by
then the frame is poured concrete.

Design review exists to catch frame errors before implementation. Keep
those fights in the plan while the code is still cheap to change.

## Implementation Change Discipline

Behavior-level implementation follows the reviewed plan as small,
revertible commits. A commit has one concern, a clear rollback boundary,
and a validation command that matches its risk. If a change is too large
to review in one pass, split by behaviour, boundary, or generated-vs-hand
written work. Do not split merely to make history look tidy.

Commit messages or review notes record:

- exact plan section implemented, when a plan exists;
- production-line diff size when it is near or over the normal budget;
- tests or checks run;
- review ledger for substantive changes: reviewer lenses used,
  QA/enforcement pass, confirmed blocker findings, and the fresh pass
  that cleared them.

Do not use a new commit to bury unresolved blocker findings from the
previous one. Fix them, record the validation, then continue.

## Review Gate

Substantive behavior, security, storage, FFI, release, or architecture changes
need independent review before being called ready. Use subagents when they add
real independence: one reviewer for the change semantics, one for naming/docs or
release drift when relevant, and one QA/enforcement pass against this file and
active skills. Mechanical generated changes may use a narrower QA pass, but the
verification command must still be recorded.

Confirmed blocker findings stop the change. Fix them, then run a fresh pass
over the current tree. Minor notes can be fixed immediately or recorded as
follow-up.

## Endpoint Change Checklist

Every new binary-adapter route should pass the same small checklist before review:

- Blocking: filesystem or SQLite work that can outlive a quick metadata read
  must cross an explicit blocking boundary. Production SQLite execution
  helpers require `&mut BlockingSqlite`; raw `spawn_blocking` is a scheduler
  tool, not the safety seal.
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
  quota scan on a request path must either be tiny and documented or cross an
  explicit blocking boundary. SQLite helpers that execute production SQL require
  `&mut BlockingSqlite`; adapters should await Engine methods instead of
  calling raw SQLite helpers. This applies to helpers called by handlers, not
  just the handler body.
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
  before replay. Any Rust denylist change must keep adapter and SDK behaviour in parity.
- Path semantics: if core rejects a path form, SDK clients should reject it
  before network I/O too. Include encoded dot segments, empty segments,
  namespace roots, and reserved `/proc/*` exceptions in tests.
- Cross-surface parity: when a status or limit changes in HTTP, check CoAP
  mappings, Python SDK behaviour, README, and `.env.example`.
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
  and `cargo test --manifest-path bin/Cargo.toml`. Also run the Python L5 smoke test when SDK/FFI packaging is involved and `git diff --check`.
