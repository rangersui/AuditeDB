# HTTP Timeline Dereference Local Completion Audit

This is a local-only completion audit for
`PLAN-http-timeline-dereference.md`. It audits the implementation through
`stack/22r102-local-completion-audit` and records the local evidence available
while GitHub PR/check evidence is unavailable.

Remote PR creation and remote CI are intentionally out of scope for this file.

## Implementation Order

| Plan item | Local evidence | Verdict |
|---|---|---|
| 1. Core resolver result separates pre-proof failures from verified-address outcomes. | `core/src/audit/timeline_dereference.rs` defines `TimelineDereference` plus sealed `VerifiedGenerationMismatch`, `VerifiedBodyHashMismatch`, `VerifiedNonBodyEvent`, and `VerifiedMissingRow`. Compile-fail doctests reject direct construction. | Covered |
| 2. Resolver accepts `TimelineCoordinate`, verifies audit rows, and only then mints `TimelineAddress`; no delete-ledger `Gone` reuse. | `core/src/world_read_ops.rs` requires `ReadPermit`; `core/src/audit/timeline_dereference.rs` verifies generation, row class, body hash, and retained CAS before `TimelineDereference::Body`. Missing subjects stay `UnprovenCoordinate`. | Covered |
| 3. HTTP query reaches the FSM; `OPTIONS` short-circuits before query decoding. | `bin/src/server/route.rs` passes raw query into `pipeline::run`; `bin/src/server/pipeline.rs` classifies timeline mode after path validation. Route tests prove timeline-looking and malformed `OPTIONS` still return ordinary route `OPTIONS`. | Covered |
| 4. Classifier decodes ordered pairs, enforces caps, detects duplicates after decoding, and emits closed errors. | `bin/src/server/pipeline/query.rs` owns `MAX_RAW_QUERY_BYTES`, decoded-key classification, duplicate detection, pair cap, and `TimelineQueryError`. Query tests cover malformed, duplicate, encoded, memory-world, non-integer, overflow, unrelated-query, and cap cases. | Covered |
| 5. GET/HEAD timeline mode uses a dedicated branch, `spawn_blocking`, and typed status mapping. | `bin/src/server/handler/timeline.rs` runs dereference inside `tokio::task::spawn_blocking` and maps every `TimelineDereference` outcome to closed `ErrorReason` variants. Pipeline tests cover success, error parity, method wall, auth, missing/unproven, delete-ledger non-scan, and corrupt-row mapping. | Covered |
| 6. SDK helpers are added only after the raw HTTP route is proven. | The stack history places SDK helper work after HTTP timeline dereference wiring. Current SDK helpers require `TimelineCoordinate`, build the query-mode URL, verify proof headers and body hash, and are covered by `sdk/tests/test_tools.py` plus SDK blackbox checks. | Covered |

## Endpoint Checklist

| Gate | Local evidence |
|---|---|
| Happy GET and HEAD dereference. | `pipeline_timeline_get_returns_historical_body_and_proof_headers`; `pipeline_timeline_head_returns_headers_without_body`. |
| Malformed query coverage. | `bin/src/server/pipeline/query.rs` tests cover missing fields, duplicate mode/fields, unknown fields, malformed percent escapes, duplicate-after-decoding, encoded timeline keys, non-integer and overflowing seq, non-positive seq, memory-world coordinates, unrelated query compatibility, and raw-query cap. |
| Route topology. | `route.rs` tests keep `/timeline/foo` as an ordinary world and keep `/`, `/listen/*`, `/proc/*`, `/proc/audit/*`, and reserved `/proc/{*reserved}` ahead of the catchall. |
| `OPTIONS` no dereference. | `world_handler_options_ignores_timeline_and_malformed_query` and `world_handler_options_ignores_malformed_timeline_query`. |
| Method wall. | `pipeline_timeline_method_wall_prevents_current_mutation` covers `PUT`, `POST`, `DELETE`, and `PATCH` timeline-mode requests. |
| Conditional/range ignored for timeline v1. | Timeline success tests send `Range`, `If-Range`, and `If-None-Match` and assert no `ETag`, no `Accept-Ranges`, no `Content-Range`, no monitor `Link`, and full historical body. |
| Proof-state coverage. | Core resolver tests cover generation mismatch after chain verification, body-hash mismatch, non-body event, missing row, corrupt row, and historical body. HTTP tests cover 404/409/500 mappings and keep deleted worlds unproven. |
| Auth coverage. | `pipeline_timeline_get_honors_read_token_gate`; v1 stays aligned with existing `401` read-token behaviour rather than adding a new `403` split. |
| HEAD absence/error parity. | `pipeline_timeline_head_errors_have_no_body` and `pipeline_timeline_query_errors_are_closed_and_head_empty`. |
| Blocking boundary. | `handler/timeline.rs` wraps SQLite/audit dereference work in `spawn_blocking`. |
| Header policy. | Timeline response tests prove single trusted `X-Timeline-*` headers and suppress `ETag`, `Accept-Ranges`, `Content-Range`, and monitor `Link`; `header_policy_scan.py --offline` reports no Rust/Python denylist drift. |
| Resource caps. | `MAX_RAW_QUERY_BYTES`, decoded pair cap, and saturated-path tests are in `pipeline/query.rs`. V1 delete-ledger scans are explicitly absent from the dereference path. |
| Closed error vocabulary. | Timeline parse and dereference failures map through `pipeline::ErrorReason`, not ad hoc trace strings. |
| README / API docs parity. | `bin/src/server/http/README.md` documents query mode, statuses, proof headers, no current ETag/range/monitor headers, and filtered persisted metadata. |
| `.env.example` parity. | No new timeline environment variable exists; prior `.env.example` trace wording drift was fixed in the ledgered stack. |

## Local Validation Snapshot

The final local sweep observed these checks on the same worktree lineage:

- `cargo fmt --manifest-path core\Cargo.toml -- --check`
- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo fmt --manifest-path ffi\Cargo.toml -- --check`
- `cargo clippy --locked --manifest-path core\Cargo.toml --all-targets -- -D warnings`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --all-targets -- -D warnings`
- `cargo test --locked --manifest-path core\Cargo.toml`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo test --locked --manifest-path ffi\Cargo.toml`
- `python tools\version_consistency_check.py`
- `python tools\panic_discipline_scan.py core bin ffi`
- `python tools\header_policy_scan.py --offline`
- `python sdk\tests\test_tools.py`
- `python -m py_compile sdk\src\elastik\sdk.py sdk\src\elastik\__init__.py sdk\src\elastik\testing.py sdk\src\elastik\reactor.py`
- `python sdk\tests\e2e_blackbox.py`

Observed results included:

- core: 209 passed, 2 ignored; doctests: 17 passed.
- bin: 157 passed.
- ffi: 25 passed.
- SDK tools: pass.
- SDK blackbox: 249 checks passed.

## Review State

Fresh local subagent review of `stack/22r102-local-completion-audit` is recorded
in `STACK-22-CASCADE-REPAIR-LEDGER.md`. The first review round found this audit
lacked current-layer review evidence and had over-strong local-vs-remote
wording; both findings were accepted and repaired in the current layer before
the final clearing round.

The remaining unproven item is not an implementation gap: remote PR creation
and GitHub CI were not attempted because the current operating mode is
local-only.
