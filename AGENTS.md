# Agent Instructions

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
