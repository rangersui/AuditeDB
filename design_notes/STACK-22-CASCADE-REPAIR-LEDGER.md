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

Still required after the current cascade:

- top-of-stack local validation after the current `22r41` merge commit;
- subagent QA rerun on the repaired artifact until no P0-P3 findings remain.

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

Additional QA round after the cursor repair:

- Huygens the 2nd, Popper/Bacon: BLOCK. Found P2 FFI cursor-ahead handling:
  `SubscriptionRecvError::CursorAhead` was explicit but mapped to terminal
  `Unknown`, so an FFI subscriber using a stale cursor would lose the live
  stream after the first reset signal.
- Hume the 2nd, Mencius/Noether: BLOCK. Confirmed the same P2 and found P3
  tombstone lifecycle APIs still accepted raw `&str` world names.
- Gauss the 2nd, process/CI QA: PENDING, no current-head bad checks after
  deduping stale cancelled checks; live CI remained pending.

Fixes added after that round:

- FFI now exposes `FfiSubscriptionNextKind::CursorAhead` plus `since` and
  `newest` fields on `FfiSubscriptionNext`.
- FFI treats `CursorAhead` as non-terminal, so the subscription pump remains
  live and later matching writes are still delivered.
- Core tombstone lifecycle APIs now require `&ValidatedWorldPath` at the
  `Core` and `ReadCache` boundaries.
- The stack-local timeline read-cache tombstone test was repaired at its
  first introducing layer (`22r22`) instead of only at the tip.

Focused validation after those fixes:

- `cargo fmt --manifest-path core/Cargo.toml --check`
- `cargo fmt --manifest-path ffi/Cargo.toml --check`
- `cargo test --manifest-path core/Cargo.toml read_cache -- --nocapture`:
  24 passed.
- `cargo test --manifest-path core/Cargo.toml tombstone -- --nocapture`:
  4 passed.
- `cargo test --manifest-path ffi/Cargo.toml
  subscription_next_reports_cursor_ahead_then_keeps_live_stream_open --
  --nocapture`: 1 passed.
- `cargo test --manifest-path ffi/Cargo.toml subscription_next --
  --nocapture`: 4 passed.

Full local validation after those fixes on `stack/22r41-sdk-timeline-coordinate`:

- `cargo fmt --manifest-path core/Cargo.toml --check`
- `cargo fmt --manifest-path bin/Cargo.toml --check`
- `cargo fmt --manifest-path ffi/Cargo.toml --check`
- `cargo test --manifest-path core/Cargo.toml`: 199 passed, 2 ignored; doc
  tests 17 passed.
- `cargo test --manifest-path bin/Cargo.toml`: 150 passed.
- `cargo test --manifest-path ffi/Cargo.toml`: 24 passed; doc tests 0
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
- `python tools/header_policy_scan.py --self-test`: ok.
- `python tools/header_policy_scan.py --offline --report
  header-policy-report.md`: no drift; temporary report removed.
- `git diff --check`: pass.

Additional QA round after pushing those fixes:

- Lorentz the 2nd, Popper/Bacon: BLOCK. Confirmed FFI cursor repair was clean,
  but found P3 `Core::delete_world_blocking(&str)` still left the physical
  delete helper unsealed.
- Poincare the 2nd, Mencius/Noether: BLOCK. Found the same P3 and also found
  P3 `#[cfg(test)] pub(crate) fn write_world(...)` did not carry the
  `test_only_` bypass name.
- Godel the 2nd, process QA: PENDING. Current-head CI was pending with no
  current failures; ledger and stack topology were honest but not converged.

Fixes added after that round:

- `Core::delete_world_blocking` now requires `&ValidatedWorldPath`, and
  `delete_ops` passes the delete permit's sealed world into the physical delete
  step.
- The direct test fixture writer is now named `test_only_write_world`, and
  upper stack delete tests were updated at their first introducing layer
  (`22r28`).

Focused validation after those fixes:

- source scan for `delete_world_blocking(&self, world: &str)`,
  `delete_world_blocking(world_name)`, `pub(crate) fn write_world`, and
  `.write_world(`: no matches.
- `cargo fmt --manifest-path core/Cargo.toml --check`
- `cargo test --manifest-path core/Cargo.toml delete_ops -- --nocapture`:
  6 passed.
- `cargo test --manifest-path core/Cargo.toml store -- --nocapture`: 5 passed.

Full local validation after those fixes on `stack/22r41-sdk-timeline-coordinate`:

- `cargo fmt --manifest-path core/Cargo.toml --check`
- `cargo fmt --manifest-path bin/Cargo.toml --check`
- `cargo fmt --manifest-path ffi/Cargo.toml --check`
- `cargo test --manifest-path core/Cargo.toml`: 199 passed, 2 ignored; doc
  tests 17 passed.
- `cargo test --manifest-path bin/Cargo.toml`: 150 passed.
- `cargo test --manifest-path ffi/Cargo.toml`: 24 passed; doc tests 0
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
- `python tools/header_policy_scan.py --self-test`: ok.
- `python tools/header_policy_scan.py --offline --report
  header-policy-report.md`: no drift; temporary report removed.
- `git diff --check`: pass.

Additional QA round after reopening the repaired physical-delete layer:

- Planck the 2nd, type-seal QA: BLOCK. Confirmed the prior
  `Core::delete_world_blocking` fix, but found P3 raw physical delete helper
  exposure in `world::delete` / `world/files.rs` and P3 raw subscription resume
  cursors across Core/FFI.
- Nash the 2nd, AGENTS/stack process QA: BLOCK/PENDING. Confirmed the fork
  repair direction, but required the stack to keep low-layer fixes in the
  branch chain and to rerun QA after the cascade. Live GitHub CI remained a
  post-push source of truth, not a local claim.

Fixes added after that round:

- `world/files.rs::delete` now requires `&ValidatedWorldPath`.
- `world.rs` no longer publicly re-exports the physical delete helper as a raw
  world-name API.
- `Core::delete_world_blocking` calls the sealed `world::delete(&data, &world)`
  path.
- `SubscriptionResume` is now the Core proof type for subscription replay
  state, with `none()` and `after_event_id(...)` constructors.
- `Engine::subscribe`, `EngineOps::subscribe`, `open_subscription`, replay
  internals, HTTP listen, and FFI subscription entrypoints no longer pass raw
  `Option<u64>` cursors across the Core boundary.
- FFI exposes `FfiSubscriptionResume` instead of a raw `since` argument.
- Stack-local raw subscribe test call sites were repaired at their first
  affected layers (`22r27` and `22r40`).
- A follow-up clippy hygiene fix moved `SubscriptionResume` out of CoAP's
  production imports and kept its use test-local.

Full local validation after those fixes on
`stack/22r41-sdk-timeline-coordinate`:

- adjacent branch ancestry check from `22r19` through `22r41`: pass.
- source contract scan for raw physical-delete and raw subscribe-resume shapes:
  no matches.
- `cargo fmt --manifest-path core/Cargo.toml --check`
- `cargo fmt --manifest-path bin/Cargo.toml --check`
- `cargo fmt --manifest-path ffi/Cargo.toml --check`
- `cargo test --manifest-path core/Cargo.toml`: 199 passed, 2 ignored; doc
  tests 17 passed.
- `cargo test --manifest-path bin/Cargo.toml`: 150 passed.
- `cargo test --manifest-path ffi/Cargo.toml`: 24 passed; doc tests 0
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
- `python tools/header_policy_scan.py --self-test`: ok.
- `python tools/header_policy_scan.py --offline --report
  header-policy-report.md`: no drift; temporary report removed.
- `git diff --check`: pass.

This ledger still does not claim GitHub CI is green. The live source of truth
after push remains GitHub CI.

## Post-Push CI Addendum

After pushing the reopened QA fixes, live GitHub CI found two stack-local
compile/smoke failures:

- #342 / `22r26`: FFI artifact smoke still called
  `engine.subscribe("home/*", e.FfiAccessTier.READ, None)` after the FFI
  boundary changed to `FfiSubscriptionResume`.
- #352 / `22r36`: the SSE mismatch test still passed raw `None` to
  `Engine::subscribe` after the Core boundary changed to `SubscriptionResume`.

Fixes landed at the lowest affected layers:

- `22r19`: `.github/workflows/ffi-artifacts.yml` and
  `.github/workflows/release.yml` now pass
  `e.FfiSubscriptionResume(after_event_id=None)` in their smoke scripts.
- `22r29`: `sse_change_event_drops_mismatched_timeline_address` now passes
  `SubscriptionResume::none()`.

Focused validation:

- `22r29`: `cargo test --manifest-path bin/Cargo.toml --no-run` passed.
- `22r36`: `cargo test --manifest-path bin/Cargo.toml --no-run` passed.
- Stack-wide source scans found no raw subscribe-resume shapes in Core/bin/FFI
  code and no old workflow smoke call.
- Adjacent branch ancestry from `22r19` through `22r41`: pass.
- Pre-push fast gates passed before the repair branches were pushed again.

This addendum still does not claim GitHub CI is green. The live source of truth
after push remains GitHub CI.

## FFI Dereference + Opaque Cursor Addendum

Active skills checked in this round:

- `stacked-pr`
- `rust-type-seal-enforcement`
- `http-type-seal-review`
- `precondition-problem`
- `monte-carlo-review`
- `assign-scientist-reviewers`
- `delegation-doctrine`

Fresh review round after the local cascade repair:

- Wegener the 2nd, Mencius/Locke type-seal review: CLEAN. Verified that raw
  FFI timeline coordinate fields stop at the adapter boundary, are immediately
  converted with `TimelineCoordinate::from_wire_parts`, then pass through
  read auth, `ReadPermit`, read-cache tracking, audit-chain verification, and
  proof-bearing `TimelineDereference` outcomes. No P0-P3 authority leaks.
- Turing the 2nd, Popper/Bacon falsification review: BLOCK. Found P1 SDK
  blackbox still accepted integer-only SSE ids; P2 FFI dereference test read
  the coordinate before overwriting the world; P3 FFI invalid-coordinate test
  covered only the memory-world case. Also noted that decimal
  `Last-Event-ID` is still intentionally accepted as a legacy resume input,
  so the correct claim is: newly emitted SSE ids are opaque `epoch:seq`
  cursors, while legacy decimal resume input remains compatibility syntax and
  is treated as a foreign/stale cursor by core replay planning.
- Cicero the 3rd, AGENTS/skills process QA: BLOCK. Found that the current
  local head lacked ledger evidence for `f7fbf67` and the latest validation.
  Found no code/process P2 apart from stale ledger evidence.
- Kierkegaard the 2nd, Noether/Poincare topology review: local graph clean.
  Confirmed `22r19` through `22r41` form a contiguous merge cascade and
  `22r41` contains local `22r40`, `f11d172`, and `f7fbf67`. Noted that origin
  is stale until the local cascade is pushed, and that the local-only
  `stack/22r42-sdk-reactor-timeline-plan` pointer should not be pushed as part
  of this repair.

Fixes added after that round:

- `22r40`: `4996418 Strengthen FFI timeline dereference tests`
  moves the FFI historical dereference assertion after a later append to the
  same world, so a current-body fallback would fail, and expands raw coordinate
  rejection coverage to memory worlds, uppercase generation, zero sequence, and
  malformed body hash.
- `22r41`: `c99ffbe Require opaque SSE cursor ids in SDK blackbox`
  makes the SDK blackbox reject integer-only emitted SSE ids. Legacy decimal
  `Last-Event-ID` input remains intentionally covered by bin/core tests as
  compatibility, but emitted ids must be `epoch:seq`.
- Local topology: the stale checked-out
  `stack/22r42-sdk-reactor-timeline-plan` pointer was renamed to
  `wip/sdk-reactor-timeline-plan` after confirming its committed head is fully
  contained in `stack/22r41-sdk-timeline-coordinate`. Its dirty worktree files
  were preserved and are not part of this stack push.

Full local validation after those fixes on
`stack/22r41-sdk-timeline-coordinate`:

- `cargo test --manifest-path core/Cargo.toml --features unstable-engine`:
  201 passed, 2 ignored; doc tests 17 passed.
- `cargo test --manifest-path bin/Cargo.toml --features unstable-engine`:
  150 passed.
- `cargo test --manifest-path ffi/Cargo.toml`: 25 passed; doc tests 0
  passed/0 failed.
- `python sdk/tests/test_tools.py`: pass.
- `python sdk/tests/e2e_blackbox.py`: 249 checks passed with a real release
  build, including opaque cursor replay and historical timeline reads after
  overwrite.

This addendum still does not claim GitHub CI is green. The local cascade is
ahead of origin until pushed, and GitHub CI remains the post-push source of
truth.

## Canonical SSE Cursor Addendum

Timestamp: 2026-06-15 00:43 +10:00.

Active skills checked in this round:

- `stacked-pr`
- `rust-type-seal-enforcement`
- `http-type-seal-review`
- `precondition-problem`
- `monte-carlo-review`
- `assign-scientist-reviewers`
- `delegation-doctrine`

Fresh review after the first post-push cascade found one real P2:

- Poincare the 3rd, Mencius/Popper precondition review: BLOCK. The SDK
  blackbox helper no longer treated the entire SSE id as an integer, but it
  still used Python `int(seq)` as the sequence parser. That accepted strings
  such as `+42`, `0042`, whitespace-padded values, and negative-looking values
  that the Rust contract rejects. The source-of-truth contract is
  `<32 lowercase hex epoch>:<canonical decimal event id>`.
- Hooke the 3rd, Hypatia/Locke QA: BLOCK. The ledger did not yet record a
  fresh zero-P0-P2 round after the latest fixes, which violates the stack
  repair evidence rule in `AGENTS.md`.
- Faraday the 3rd, Poincare topology review: CLEAN P0-P2 for the first
  cascade graph.

Fixes added after that round:

- `22r19`: `d039199 sdk: enforce canonical SSE cursor in blackbox`
  tightens the SDK blackbox helper to require a 32-character lowercase hex
  epoch, a non-empty ASCII-digit sequence, canonical decimal rendering, and
  `u64` range. The test now parses the emitted id before replay and passes the
  original opaque cursor string as `Last-Event-ID`.
- `22r20` through `22r41`: the `d039199` repair was propagated upward by merge
  cascade. No rebase or squash was used. The final pushed `22r41` head after
  the second cascade is `314d089`.

Local validation after the canonical cursor fix:

- On `22r19`, `python sdk/tests/e2e_blackbox.py --no-build`: 234 checks passed.
- On `22r41`, `python -m py_compile sdk/tests/e2e_blackbox.py`: passed.
- On `22r41`, `git diff --check`: passed.
- On `22r41`, `python sdk/tests/e2e_blackbox.py --no-build`: 249 checks
  passed.
- Pre-push fast gates passed while pushing `22r19` and again while pushing the
  second `22r20` through `22r41` cascade.

Post-push state at the time this addendum was written:

- `22r19`: `d039199`.
- `22r41`: `314d089`.
- GitHub CI had restarted and was still pending; this addendum does not claim
  remote CI is green.
- A fresh independent review round was started against `d039199`/`314d089`.

Fresh review outcome:

- Hume the 3rd, Mencius/Popper precondition review: the previous SDK blackbox
  P2 is fixed. Hume raised a new disputed P2 because HTTP still accepts bare
  decimal `Last-Event-ID`.
- Mendel the 3rd, Heisenberg/Locke verifier: FALSE POSITIVE. Newly emitted
  SSE ids are canonical opaque `epoch:seq` cursors, while bare decimal
  `Last-Event-ID` is an intentional legacy input syntax. Core maps it to
  `SubscriptionResume::legacy_event_id`, whose replay plan is foreign/stale,
  not current-process replay.
- Franklin the 3rd, Popper/Bacon verifier: FALSE POSITIVE. Targeted tests
  passed for canonical cursor parsing, legacy decimal foreign replay, stale
  cursor reset, HTTP parse acceptance of current cursor plus legacy decimal,
  non-canonical rejection, and SSE reset rebasing.
- Confucius the 3rd, Poincare topology review: CLEAN P0-P2. Confirmed
  `d039199` is an ancestor of every `22r20` through `22r41`, adjacent branches
  remain merge-cascade contiguous, local refs match origin, and top head is
  `314d089`.
- Leibniz the 3rd, Bacon/Sagan evidence review: no P0-P2 findings. P3 only:
  remote CI was still pending, and the ledger addendum was local evidence until
  committed.
- Schrodinger the 3rd, Hypatia/Locke QA: BLOCK at the time of review because
  this fresh zero-P0-P2 outcome was not yet recorded and the ledger file was
  still dirty.

P3 fixed after that round:

- `sdk-js/README.md` no longer shows an emitted SSE event id as `"42"`. The
  event-shape example now uses `"0123456789abcdef0123456789abcdef:42"` for the
  `id` field and keeps `"42"` only as the timeline sequence.

The final substantive review state after adjudication is zero confirmed P0-P2.
Remote GitHub CI remains the live post-push source of truth.
