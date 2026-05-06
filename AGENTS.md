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

- **No `.rs` source file exceeds 500 lines.**
- **No PR diff exceeds 500 lines.**
- Both limits derive from one constraint: AI co-authors (Codex,
  Copilot, Claude) cannot reliably hold more than ~500 lines of context
  at once. Past that they hallucinate, contradict prior parts of the
  same file/PR, or silently skim.
- **Slight overage is acceptable when the maintainer has read the
  change in full and explicitly signed off.** The budget is "AI working
  memory", not arithmetic — 510-550 lines with a human in the loop is
  fine, 1500 lines is never fine. The hard ceiling is "an AI agent can
  still hold the whole thing at once"; exact threshold is judgment.
- Exceeding either limit without sign-off requires splitting before
  review.

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

### Grandfather clause

Existing oversized files (`core/src/main.rs` in particular) are allowed
only for:

- Safety fixes (P0/P1 concurrency, correctness, security)
- Extraction PRs that move code OUT into new sub-500-line modules

Net-new feature code MUST land in a new sub-500-line module, even if the
natural home would have been the legacy file. The clause retires when the
FSM pipeline extraction (PR 4 of the v7 sequence) lands.

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

## Endpoint Change Checklist

Every new core route should pass the same small checklist before review:

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
- Cross-surface parity: when a status or limit changes in HTTP, check SCoAP
  mappings, Python SDK path/proc allowlists, JS SDK assumptions, README, and
  `.env.example`.
- Resource caps: every new long-lived connection, queue, replay ring, datagram
  in-flight set, or management scan needs a configured cap, an explicit
  overload response, and a regression test for the saturated path.
- `/proc/*` discipline: proc endpoints are read-gated introspection, not worlds.
  They should not emit audit events, replay user headers, or trigger listen
  notifications. If they scan durable state, treat them as blocking work.
- Review evidence: before saying a Rust core PR is ready, run or cite
  `cargo fmt --manifest-path core/Cargo.toml -- --check`,
  `cargo clippy --manifest-path core/Cargo.toml -- -D warnings`,
  `cargo test --manifest-path core/Cargo.toml`, the SDK smoke tests touched by
  the change, `python tools/header_policy_scan.py --offline` when header policy
  is involved, and `git diff --check`.
