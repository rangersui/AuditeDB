# Stack 22 Cascade Repair Ledger

This ledger records the repair of the forked Stack 22 cascade. The goal is
topology repair, not new product scope: keep every reviewed branch alive, expose
the hidden base as PR #359, and propagate lower-layer safety fixes upward by
merge commits only.

## Current Boundary

- #330 through #335 have been merged into `master` with merge commits.
- `master` has the same tree as the former `stack/21-cas-schema` base.
- #359 is based on `master` and keeps
  `stack/22r19-audit-verify-world-target` as the first visible Stack 22 layer.
- #336 through #357 remain draft and depend on the #359 head branch chain.

## Exception Scope

AGENTS.md normally caps open cascade depth at 3-4 layers. This repair is under
the Stack repair exception because the user explicitly authorised an unlimited
repair cascade for an already-existing fork.

The exception waives stack depth only. It does not waive:

- type-seal requirements for internal APIs;
- no-rebase/no-squash stack handling;
- subagent QA before advancing;
- local validation;
- keeping dependent stack branches alive while PRs still use them as bases.

## Repairs Applied

- `22r19`: audit verification now opens existing worlds through
  `ValidatedWorldPath`, verifies inside a transaction, checks the live body in
  the same transaction, and returns `VerifiedAuditTx` bound to the verified
  world.
- `22r19`: retained body audit append now rejects a retained CAS body whose
  target does not match the verified audit transaction world.
- `22r19`: read-cache DB path construction uses
  `world::validated_world_db(data, world)` before any raw string cache key is
  used for metrics or DashMap lookup.
- `22r19`: HTTP `Last-Event-ID` parsing now rejects invalid/non-decimal values
  with 400 instead of silently treating them as no replay cursor.
- `22r19`: added this repair ledger so PR #359 is self-contained enough to
  explain the stack-topology exception.
- `22r20..22r41`: propagated the repaired lower layers upward by merge cascade,
  without rebasing or squashing.

Merge conflicts resolved during this repair:

- `22r20`: preserved generation-aware HMAC verification while switching world
  verification to transaction scope.
- `22r27`: preserved `AppendedBodyAuditRow` timeline-address output while
  adding the retained-target-vs-verified-world check.
- `22r28`, `22r33`, `22r34`: merged audit module export sets after type-seal
  and module-split changes.
- `22r35`: preserved the read-cache module split and kept sealed DB path
  construction in `read_cache/state_machine.rs`.
- `22r41`: merged this ledger with the earlier QA ledger instead of picking one
  side and losing process evidence.

## Validation Evidence

Run on `stack/22r19-audit-verify-world-target` before the upward cascade:

- `cargo fmt --manifest-path core/Cargo.toml -- --check`
- `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path core/Cargo.toml`
- `cargo fmt --manifest-path bin/Cargo.toml -- --check`
- `cargo clippy --manifest-path bin/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path bin/Cargo.toml`
- version consistency
- Rust supply-chain quick audit
- Python SDK smoke
- header policy scanner self-test
- whitespace check

Observed lower-layer results:

- core: 157 passed, 2 ignored; doc tests 5 passed.
- bin: 109 passed.
- version consistency: 8.3.0 ok.
- SDK tools: pass.
- header policy scanner: no drift.
- pre-push hook: all local gates passed before pushing #359.

Required before marking upper stack layers ready:

- GitHub CI green for #359 after the pushed repair.

Completed after the current cascade:

- top-of-stack local validation after the current `22r41` merge commit;
- subagent QA rerun on the repaired artifact until no P0-P3 findings remained.

Final local validation on `stack/22r41-sdk-timeline-coordinate`:

- `cargo fmt --manifest-path core/Cargo.toml -- --check`
- `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path core/Cargo.toml`
- `cargo fmt --manifest-path bin/Cargo.toml -- --check`
- `cargo clippy --manifest-path bin/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path bin/Cargo.toml`
- `cargo fmt --manifest-path ffi/Cargo.toml -- --check`
- `cargo clippy --manifest-path ffi/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path ffi/Cargo.toml`
- `python sdk/tests/test_tools.py`
- `python sdk/tests/e2e_blackbox.py`
- `git diff --check`
- adjacent branch ancestry check from `22r19` through `22r41`
- stale verifier grep across stack refs:
  `git grep -n 'verify_world_connection' <branch> -- core/src`

Observed local results before the follow-up cursor audit:

- core: 197 passed, 2 ignored; doc tests 17 passed.
- bin: 149 passed.
- ffi: 23 passed; doc tests 0 passed/0 failed.
- SDK tools: pass.
- SDK e2e blackbox: 248 checks passed.
- ancestry check: ok.
- stale `verify_world_connection`: no matches in stack refs.

## Review Ledger

Historical repair review rounds before this cascade included these independent
approvals and findings:

- Hegel, QA enforcement/Locke/Sagan: AGENTS/process QA approve, no P0-P3
  findings after the stack-depth and ledger fixes.
- Dalton, Sagan/Dirac: ledger wording QA approve, no P0-P3 findings after the
  overclaim and stale-evidence wording fixes.
- Aquinas the 2nd, Popper/precondition: approve, no P0-P2 findings on missing
  CAS body semantics and `OPTIONS` query handling.
- Bacon the 2nd, Noether/Mencius: approve, no P0-P2 findings on type seals and
  coordinate proof boundaries.
- Ramanujan the 2nd, Euclid/HTTP topology: approve, no P0-P2 findings on HTTP
  timeline query walls.
- Faraday the 2nd, QA/enforcement: code approve, but process remained gated on
  #359 review before #336+ could leave draft.
- Banach the 2nd, Popper/Bacon: approve, no P0-P3 findings for the earlier
  #359 CI repair.
- Noether the 2nd, Mencius/Noether: approve with a P3 read-cache path-seal
  hygiene finding. This repair preserves the fix by using
  `world::validated_world_db(...)`.
- Nietzsche the 2nd, Ramanujan/Poincare: approve, no P0-P2 findings; noted
  duplicate patch-id history as the intentional cost of no-rebase/no-squash.

Final QA round after the current cascade:

- Sagan the 2nd, type-seal/invariant conservation: APPROVE, no P0-P3 findings.
- Anscombe the 2nd, AGENTS/stack process QA: APPROVE, no P0-P3 findings.
- Zeno the 2nd, precondition/HTTP semantics: found one P3 in
  `Last-Event-ID` parsing. Fixed at `22r19` by using `HeaderMap::get_all`,
  rejecting duplicates, rejecting empty/non-ASCII-decimal values, and removing
  trimming. Targeted listen tests passed. Zeno re-reviewed and APPROVED with no
  P0-P3 findings.

Follow-up QA round after reopening the repaired stack:

- Popper the 2nd, process/CI QA: BLOCK for upper-stack advancement. #359 was
  green, but #344-#350 still had failing checks from stack layers that were not
  independently compilable.
- Fermat the 2nd, protocol/precondition QA: BLOCK. Found P1 stale/ahead
  `Last-Event-ID` handling: a pre-restart cursor could become the live floor
  and silently suppress new live events after the engine counter reset. Also
  found P3 non-canonical decimal aliases such as `00042`.
- Mencius the 2nd, type-seal/invariant QA: BLOCK on the same P3 canonical
  cursor issue; no P0-P2 type-seal findings after the earlier repair.

Fixes added after that round:

- `SubscriptionRecvError::CursorAhead { since, newest }` now distinguishes a
  cursor from another process id space from ordinary ring-buffer lag.
- `replay_after` checks `last_issued_event_id` under the event-log lock and
  queues `CursorAhead` with live floor `0` instead of trusting the client
  cursor.
- SSE renders `CursorAhead` as a `reset` event with `id: newest`, rebasing
  browser `Last-Event-ID` state into the current process id space.
- `Last-Event-ID` parsing now requires canonical decimal round-trip; `0` is
  accepted, while `00` and `00042` are rejected.
- Stack-local compile break in #344 was fixed by preserving
  `ValidatedWorldPath` at the read-cache call site and by making the matching
  test call `Core::read_world(&subject)`.

Validation after those fixes on `stack/22r41-sdk-timeline-coordinate`:

- focused core cursor tests: `replay_after*` plus
  `engine_subscription_with_stale_cursor_signals_then_streams_live` passed.
- focused bin cursor tests: `last_event_id` plus `sse_reset_event` passed.
- `cargo fmt --manifest-path core/Cargo.toml --check`
- `cargo fmt --manifest-path bin/Cargo.toml --check`
- `cargo fmt --manifest-path ffi/Cargo.toml --check`
- `cargo test --manifest-path core/Cargo.toml`: 199 passed, 2 ignored; doc
  tests 17 passed.
- `cargo test --manifest-path bin/Cargo.toml`: 150 passed.
- `cargo test --manifest-path ffi/Cargo.toml`: 23 passed; doc tests 0
  passed/0 failed.
- `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
  -D clippy::undocumented_unsafe_blocks`
- `cargo clippy --manifest-path bin/Cargo.toml -- -D warnings`
- `cargo clippy --manifest-path ffi/Cargo.toml -- -D warnings`
- `python sdk/tests/e2e_blackbox.py`: 248 checks passed.
- `python sdk/tests/test_tools.py`: pass.
- `python -m compileall -q sdk/src sdk/tests`: pass.
- `python tools/version_consistency_check.py`: 8.3.0 ok.
- `python tools/audit_chain_verify.py --self-test`: ok.
- `python tools/header_policy_scan.py --self-test` and
  `python tools/header_policy_scan.py --offline`: no drift.

This ledger does not claim GitHub CI is green. The live source of truth after
push is GitHub CI, especially #359.
