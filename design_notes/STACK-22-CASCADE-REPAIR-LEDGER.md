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
  cascade. No rebase or squash was used. The final `22r41` merge head after
  the second cascade was `314d089`; the later ledger closeout commit was
  `6e8536a`.

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
- `22r41` merge cascade head: `314d089`.
- `22r41` ledger closeout commit: `6e8536a`.
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

## 2026-06-27 Continuation: 22r70 -> 22r71

The active stack remains under the repair/continuation exception. The user has
explicitly authorised an unlimited stacked-PR continuation for this already
deep stack and will review the final result rather than each intermediate
layer. This does not waive the per-layer requirements: each layer still needs a
small diff, local validation, fresh subagent QA, and no confirmed P0-P2 before
it is considered ready.

Current base before this layer:

- Branch: `stack/22r70-ci-lock-rustdoc`
- Head: `1f5d721 ci: lock rustdoc dependencies`
- Local depth over `master` at the start of `22r71`: 25 commits

Layer under review:

- Branch: `stack/22r71-query-percent-fail-loud`
- Plan section: `PLAN-http-timeline-dereference.md` section 3, query
  classification before dispatch.
- Scope: one parser contract fix in `bin/src/server/pipeline/query.rs`.
- Current `query.rs` diff after the seq-parse reason fix: +39/-51 total.
- Production file size after the change: 213 lines before `#[cfg(test)]`.
- Runtime behaviour: non-`OPTIONS` query parsing now decodes every ordered
  query key and value before classification. Malformed percent encoding can no
  longer downgrade to `Current`. `OPTIONS` still bypasses query decoding in the
  route handler.
- Active skills checked for this layer: `stacked-pr`,
  `rust-type-seal-enforcement`, `http-type-seal-review`,
  `monte-carlo-review`, `assign-scientist-reviewers`, and
  `delegation-doctrine`.

Validation run locally on `stack/22r71-query-percent-fail-loud`:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline::query --all-features`
  - observed: 26 passed
- `cargo test --locked --manifest-path bin\Cargo.toml --all-features`
  - observed: 201 passed
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-features --all-targets -- -D warnings -D clippy::unwrap_used -D clippy::expect_used`
- `git diff --check`

Fresh QA round:

- Aquinas / Popper: clean P0-P2. Independently verified malformed percent
  decoding, encoded timeline keys, unrelated well-formed current-query
  compatibility, and `OPTIONS` bypass. Also ran
  `cargo test --manifest-path bin/Cargo.toml query --quiet`; observed 30
  passed in that subagent workspace.
- Hegel the 2nd / Mencius: clean P0-P2. Confirmed raw query strings remain at
  the parser boundary, `TimelineCoordinate::from_wire_parts` is the only
  timeline-coordinate minting path, and validation reasons are preserved rather
  than erased.
- Wegener the 2nd / QA-Enforcement: found two process P2 items before this
  addendum: stale deep-stack exception evidence and missing durable validation
  evidence. Code scope, line budget, test shape, docs/env scope, panic posture,
  and reason propagation were otherwise clean.

Disposition:

- The validation evidence and current stack-depth exception evidence are now
  recorded here.
- Because this addendum changes only the process ledger, a fresh enforcement
  round must confirm the P2s are closed before the layer is committed.

Second fresh QA round:

- Meitner the 2nd / Popper: clean P0-P2. Static diff review found no
  counterexample for malformed-percent fallthrough, `OPTIONS` decoding,
  encoded timeline keys, or unrelated well-formed current-query compatibility.
- Kant the 2nd / Mencius: found one P2. The ledger wording overclaimed
  validation-reason preservation because `timeline-seq` parse failures still
  collapsed every `ParseIntError` into one query error.
- Copernicus the 2nd / QA-Enforcement: clean P0-P2 for process evidence before
  the seq-parse repair. P3 only: the "unlimited stacked-PR continuation"
  wording is broad but not blocking because this addendum preserves per-layer
  requirements.

Fix after second round:

- `timeline-seq` parsing now classifies integer syntax failures separately
  from integer overflow. This removes the broad reason-erasing parse mapping
  without changing the HTTP wall: both remain typed bad timeline-query errors.

Because the seq-parse repair changes production code, another fresh round must
confirm P0-P2 are clear before this layer is committed.

Post-fix validation run locally on the current `22r71` worktree:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `git diff --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline::query --all-features`
  - observed: 26 passed
- `cargo test --locked --manifest-path bin\Cargo.toml --all-features`
  - observed: 201 passed
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-features --all-targets -- -D warnings -D clippy::unwrap_used -D clippy::expect_used`

Final fresh QA round after the seq-parse repair:

- Poincare the 2nd / Popper: clean P0-P2. Confirmed decoded key/value parsing,
  malformed-percent `400`, `OPTIONS` bypass, encoded timeline keys,
  well-formed unrelated `Current`, and seq syntax-vs-overflow split. Ran
  focused query, `world_handler_options`, and `pipeline_timeline` tests plus
  `git diff --check`.
- Goodall the 2nd / Mencius: clean P0-P2. Confirmed the previous broad
  parse-reason P2 is fixed, the wildcard `IntErrorKind` fallback remains
  fail-closed and typed, `TimelineCoordinate::from_wire_parts` remains the
  coordinate seal, and `ErrorReason::TimelineQuery(other)` preserves the typed
  query error.
- Dirac the 2nd / QA-Enforcement: P2 before this closeout only because this
  final post-fix validation and zero-P0-P2 review round was not yet recorded in
  the durable ledger. Code scope and query behaviour were otherwise clean.

Final disposition for this layer:

- The final fresh code review round is zero confirmed P0-P2.
- The process P2 from Dirac the 2nd is closed by this addendum: it records the
  post-fix validation evidence and the final fresh zero-P0-P2 round.
- This layer is ready to commit as the next stacked PR layer once a final local
  `git diff --check` confirms the ledger edit itself is clean.

## 2026-06-27 Continuation: 22r71 -> 22r72

Layer: `stack/22r72-ffi-bindgen-unwrap-deny`

Plan section implemented: AGENTS.md Panic Discipline and Sealed-Type Boundary
Rules. The change closes the remaining Rust crate-root gap for the FFI
bindgen helper.

Scope:

- Add crate-level `#![deny(clippy::unwrap_used, clippy::expect_used)]` to
  `ffi/src/bin/uniffi-bindgen.rs`.
- Add CI doctrine lint coverage for FFI production binaries with
  `cargo clippy --locked --bins`.
- Add CI doctrine lint coverage for the binary adapter with all features
  enabled, including the non-default `mqtt` production feature.
- Use `--bins` for binary adapter doctrine lints so future
  `bin/src/bin/*.rs` production roots are covered too.
- Disable implicit binary auto-discovery for the library-only core crate with
  `autobins = false`.
- Add `tools/panic_discipline_scan.py` and CI wiring so production
  `#[allow(clippy::unwrap_used|expect_used)]` exceptions must carry a nearby
  invariant comment.
- Add unwrap/expect doctrine flags to the core `--all-targets` clippy step so
  future explicit core targets are covered.
- No runtime behaviour, ABI, SDK, storage, auth, audit, or wire contract
  change.

Trigger:

- Mencius the 2nd found that `ffi/Cargo.toml` declares an extra binary crate
  root, `src/bin/uniffi-bindgen.rs`. `ffi/src/lib.rs` was already sealed, but
  the bindgen binary was not covered by the FFI `--lib` doctrine lint.
- Averroes the 2nd found that a CI lint targeting only `--bin uniffi-bindgen`
  would miss future `ffi/src/bin/*.rs` targets because Cargo auto-discovers
  binaries.
- Chandrasekhar the 2nd found that `bin`'s doctrine lint covered default and
  minimal features, but not the non-default production `mqtt` feature.
- Mill the 2nd found that the repaired binary adapter lint still named only
  `--bin elastik-core`, so a future `bin/src/bin/*.rs` target could escape
  the doctrine lint.
- Pauli the 2nd found that a future `core/src/bin/*.rs` target could be
  auto-discovered by Cargo and would not inherit the library crate-root deny.
- Godel the 2nd found two more gaps before the final repair: a future explicit
  core `[[bin]]` would not be covered by core `--lib` doctrine lints, and local
  production `#[allow]` attributes can override `deny` unless the repository
  separately enforces documented exceptions.
- Beauvoir the 2nd and Dewey the 2nd found that the first scanner was too
  line-oriented: a comment containing `cfg(test)`, a multiline `#[allow(...)]`,
  or a `cfg_attr(not(test), allow(...))` could evade the documentation check.
- Bacon the 2nd found that `#[allow(clippy::restriction)]` suppresses
  `unwrap_used` and `expect_used`, and that `#[expect(clippy::unwrap_used)]`
  is also a suppressor form. The scanner initially checked only exact
  `allow(clippy::unwrap_used|expect_used)` spellings.
- Gauss the 2nd, Darwin the 2nd, and Socrates the 2nd found that
  `cfg_attr(feature = "...", allow(...))` and `cfg_attr(not(test), allow(...))`
  could still hide production suppressors because suppressor detection only
  matched direct `allow(...)` / `expect(...)` attribute heads.
- Peirce the 2nd found three final scanner gaps: spaced lint paths such as
  `clippy :: unwrap_used`, multiline attribute blocks containing `]` inside
  string literals, and macro-body suppressors such as `#[allow($lint)]`.
- Aristotle the 2nd and James the 2nd found the final parser/scope gaps:
  comments inside attribute tokens, `]` inside attribute comments, and a single
  documented module/function-level suppressor could still hide later bare
  unwrap/expect calls.

Active skills checked for this layer: `stacked-pr`,
`rust-type-seal-enforcement`, `monte-carlo-review`,
`assign-scientist-reviewers`, and `delegation-doctrine`.

Validation run locally on `stack/22r72-ffi-bindgen-unwrap-deny`:

- `cargo fmt --manifest-path ffi\Cargo.toml -- --check`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --bin uniffi-bindgen -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks`
- `git diff --check`

Precondition design review was not required for this layer: it changes no
runtime semantics or wire/storage contract. It only tightens compile-time and
CI lint enforcement for existing Rust targets and production feature coverage.

Fresh QA round before final repair:

- Averroes the 2nd / Popper: found P2. The first CI repair linted only
  `--bin uniffi-bindgen`; a future `ffi/src/bin/other.rs` would be
  auto-discovered by Cargo and miss the doctrine lint.
- Chandrasekhar the 2nd / Mencius: found P1. `bin` has a non-default
  production `mqtt` feature, but CI did not run the binary production doctrine
  lint with `mqtt` enabled.
- Bohr the 2nd / QA-Enforcement: found P2 before closeout. The ledger did not
  yet record a final zero-P0-P2 fresh round.

Fixes applied after that round:

- FFI binary doctrine lint now uses `--bins`, covering current and future
  FFI production binaries.
- Binary adapter doctrine lints now use `--bins` for default, minimal, and
  all-features runs. The all-features run covers MQTT production code; the
  `--bins` target selection covers future binary roots.
- The core package now sets `autobins = false`, so the library crate cannot
  grow an implicit binary root by file placement alone.
- Core `--all-targets` clippy now also denies unwrap/expect, so an explicit
  future core target is covered by the normal CI path.
- Production lint exceptions are checked by `tools/panic_discipline_scan.py`:
  test-module allows are accepted; production allows require a nearby
  `Invariant:` or `Poison means` comment.
- The scanner now parses attribute blocks, including multiline attributes and
  crate-level attributes, and treats only real `#[cfg(test)]` /
  `#[cfg_attr(test, ...)]` attributes as test-only.
- The scanner now treats `allow` and `expect` attributes for
  `clippy::unwrap_used`, `clippy::expect_used`, `clippy::restriction`, and
  `clippy::all` as relevant suppressors. `deny` attributes are not flagged.
- Group suppressors such as `clippy::restriction` and `clippy::all` are hard
  failures for panic discipline. They are detected because they can cover
  unwrap/expect, but they cannot be documented into production; only exact
  `clippy::unwrap_used` / `clippy::expect_used` suppressors are valid local
  escapes.
- The scanner now detects suppressor operations inside `cfg_attr(...)` too.
  Only exact test-only forms such as `#[cfg_attr(test, allow(...))]` are
  exempt; feature-gated or `not(test)` suppressors require invariant
  documentation like any other production suppressor.
- The scanner now normalises lint paths around `::`, ignores bracket-like
  characters inside string and raw-string literals while collecting attribute
  blocks, and treats macro lint metavariables as relevant suppressors.
- The scanner now ignores line/block comments while collecting and matching
  attribute tokens, and rejects production suppressors attached to crate,
  module, function, impl, type, and other item scope. Documented suppressors
  must be local to the statement or block that needs them.
- The scanner now detects item-scope suppressors from a token window rather
  than one physical line. This catches split and spaced visibility forms such
  as `pub` newline `fn`, `pub(crate) fn`, and `pub /*comment*/ (crate) fn`.
- The scanner now checks source-level `.unwrap()` / `.expect()` calls, not only
  lint suppressor attributes. A naked call hidden behind an uncompiled feature
  branch now fails the scanner unless it is inside exact test-only code or
  covered by a documented local lint suppressor.
- The scanner now treats Rust lifetimes such as `Transaction<'_>` as lifetimes,
  not char literals, so test-module and item-range parsing does not stop early.
- The scanner now rejects documented `macro_rules!` item suppressors; the item
  regex handles `macro_rules!` without relying on a trailing word boundary after
  `!`.
- The scanner no longer trusts filenames such as `tests.rs` or
  `test_support.rs` as proof of test-only status. External module files are
  exempt only when the parent module declaration is under exact `#[cfg(test)]`,
  including `#[path = "..."]` modules.
- The scanner now treats suppressor attributes containing macro metavariables
  such as `$lint` as hard failures. They cannot be documented into production,
  because the generated lint could suppress unwrap/expect while hiding the
  generated call from source scanning.
- The scanner now also rejects `unwrap_err` / `expect_err` and UFCS forms such
  as `Option::unwrap(v)` / `Result::expect_err(r, ...)`, so inactive feature
  branches cannot dodge the source-level panic-call search by avoiding method
  syntax.
- UFCS detection now covers turbofish and angle-qualified forms such as
  `Option::<u8>::unwrap(v)`, `<Option<u8>>::unwrap(v)`, and
  `Result::<u8, ()>::unwrap_err(r)`, plus raw identifier method calls such as
  `x.r#unwrap()`.
- The scanner now recognises `macro_rules !` with whitespace before `!` as an
  item-scope macro definition and rejects unwrap/expect suppressors attached to
  it.
- The scanner now collects inline attributes as well as line-start attributes,
  so macro bodies such as `{ #[allow($lint)] fn f() {} }` are rejected by the
  same macro-metavariable rule.
- Inline attribute normalisation means same-line item suppressors such as
  `#[allow(...)] fn f(...)` and same-line test modules such as
  `#[cfg(test)] mod tests { ... }` are scanned using the same rules as
  multi-line attributes.
- The tokenizer now preserves raw-string length correctly when crossing raw
  string closing delimiters, preventing later attribute offsets from drifting.
- External `#[cfg(test)]` module files are no longer exempt when the same file
  is also included by a production `mod` declaration. Test proof is attached to
  the module occurrence, not permanently to the file path.
- CI scans crate directories (`core`, `bin`, `ffi`) rather than only `src`
  directories, so future package-root Rust files such as `build.rs` are covered
  by the same panic-discipline rule.
- CI now runs no-`unstable-engine` doctrine lint shapes for core and bin, and
  the bin/FFI all-target clippy jobs also deny unwrap/expect. That covers
  examples/tests/current and future target roots at the normal clippy layer.

Post-fix validation run locally:

- `cargo fmt --manifest-path ffi\Cargo.toml -- --check`
- `cargo fmt --manifest-path core\Cargo.toml -- --check`
- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `python -m py_compile tools\panic_discipline_scan.py`
- `python tools\panic_discipline_scan.py core bin ffi`
- Scanner probe: comment-faked `cfg(test)`, multiline `#[allow(...)]`, and
  `#[cfg_attr(not(test), allow(...))]` are rejected; real `#[cfg(test)]` and
  documented `Invariant:` allows are accepted.
- Scanner probe: undocumented `#[allow(clippy::restriction)]`,
  `#[expect(clippy::unwrap_used)]`, and multiline `#[allow(clippy::all)]`
  suppressors are rejected; documented group suppressors are also rejected,
  while real test `expect` attributes are accepted.
- Scanner probe: `cfg_attr(feature = "unstable-engine", allow(...))` and
  `cfg_attr(not(test), allow(...))` are rejected; exact
  `cfg_attr(test, allow(...))` is accepted. `#[allow(warnings)]` was tested
  separately with Clippy and does not suppress the command-line
  `-D clippy::unwrap_used` gate.
- Scanner probe: `#[allow(clippy :: unwrap_used)]`, a multiline
  `cfg_attr(..., doc = "]", allow(...))`, and `#[allow($lint)]` inside a macro
  body are rejected; `$lint` macro-metavariable suppressors are never
  documentable production escapes.
- Scanner probe: `#[allow(/*comment*/ ...)]`, `#[allow(... // ] ...)]`,
  documented module-level suppressors, and documented function-level
  suppressors are rejected. Local documented block suppressors and test-module
  suppressors remain accepted.
- Scanner probe: documented item-level suppressors split across `pub` newline
  `fn`, `pub(crate) fn`, and `pub /*comment*/ (crate) fn` are rejected.
- Scanner probe: documented `macro_rules!` item suppressors are rejected.
- Scanner probe: a package-root `build.rs` naked unwrap is rejected when
  scanning the parent crate directory.
- Scanner probe: a naked unwrap hidden behind
  `#[cfg(all(feature = "mqtt", not(feature = "multi-thread")))]` is rejected
  source-wide, independent of the active Cargo feature shape.
- Scanner probe: exact test-module suppressors still cover test code containing
  lifetime syntax such as `Transaction<'_>`.
- Scanner probe: bare `tests.rs`, `test_support.rs`, and
  `examples/tests.rs` files with naked unwraps are rejected unless included by
  an exact `#[cfg(test)]` parent module.
- Scanner probe: `#[cfg(test)] #[path = "handler/tests.rs"] mod tests;` and
  `#[cfg(test)] mod test_support;` parent declarations exempt those external
  files without trusting their basenames.
- Scanner probe: documented `#[allow($lint)]` inside a macro body is rejected
  as an unprovable macro-generated suppressor.
- Scanner probe: `Option::unwrap(v)`, `Result::unwrap_err(r)`, and method
  `expect_err(...)` forms are rejected even when hidden behind inactive feature
  cfgs.
- Scanner probe: `Option::<u8>::unwrap(v)`, `<Option<u8>>::unwrap(v)`,
  `Result::<u8, ()>::unwrap_err(r)`, and `v.r#unwrap()` are rejected.
- Scanner probe: multiline UFCS forms such as `Option::<` newline `u8`
  newline `>::unwrap(v)` and `<Option<` newline `u8` newline `>>::unwrap(v)`
  are rejected.
- Scanner probe: array and const-generic UFCS forms such as
  `Option::<[u8; 1]>::unwrap(v)` and `<Option<[u8; 1]>>::unwrap(v)` are
  rejected.
- Scanner probe: braced const-generic UFCS forms such as
  `Option::<[u8; { N }]>::unwrap(x)` are rejected.
- Scanner probe: `macro_rules !` item suppressors with whitespace before `!`
  are rejected.
- Scanner probe: inline `#[allow($lint)]` attributes inside macro bodies are
  rejected, not only attributes beginning a physical source line.
- Scanner probe: same-line item suppressors
  `#[allow(clippy::unwrap_used)] fn hidden(...)` are rejected as broad
  item-scope suppressors.
- Scanner probe: same-line exact test modules
  `#[cfg(test)] mod tests { ... }` and same-line parent path modules
  `#[cfg(test)] #[path = "test_support.rs"] mod test_support;` are accepted.
- Scanner probe: a file included by both production `mod shared;` and
  `#[cfg(test)] #[path = "shared.rs"] mod shared_test;` is treated as
  production-included and rejected if it carries naked or broadly-suppressed
  unwrap/expect.
- Scanner probe: a transitive test-only module tree
  `#[cfg(test)] mod tests;` -> `tests.rs` -> `tests/child.rs` is accepted when
  no production module reaches the child.
- Scanner probe: inline test-only module trees such as
  `#[cfg(test)] mod tests { mod child; }` -> `tests/child.rs` are accepted when
  no production module reaches the child.
- Scanner probe: split-visibility test modules such as `#[cfg(test)]`
  newline `pub(crate)` newline `mod tests;` are accepted as test-only.
- Scanner probe: the same transitive child is rejected once a production
  module also includes it, so test-only context does not launder production
  code.
- Scanner probe: documented local `#[allow(clippy::restriction)]` and
  `#[allow(clippy::all)]` suppressors are rejected; group suppressors cannot be
  used as panic-discipline escapes.
- Scanner probe: `#[allow(clippy::expect_used)]` does not cover `unwrap()`,
  and `#[allow(clippy::unwrap_used)]` does not cover `expect()`; documented
  suppressor ranges are bound to the exact panic method family they suppress.
- `cargo clippy --locked --manifest-path core\Cargo.toml --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path core\Cargo.toml --lib --no-default-features --features bundled-sqlite,unstable-engine -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path core\Cargo.toml --lib --no-default-features --features bundled-sqlite -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path core\Cargo.toml --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks -D clippy::unwrap_used -D clippy::expect_used`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --bins -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --bins -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --bins --all-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --bins --no-default-features --features bundled-sqlite,unstable-engine -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --bins --no-default-features --features bundled-sqlite -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --lib --no-default-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --bins --no-default-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D clippy::unwrap_used -D clippy::expect_used`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks -D clippy::unwrap_used -D clippy::expect_used`
- `git diff --check`

Adjudication before final round:

- Godel the 2nd's explicit core-target finding was accepted and fixed by the
  core `--all-targets` doctrine flags plus `autobins = false`.
- Godel the 2nd's local-allow finding was accepted as a documentation
  enforcement gap, not as a requirement to `forbid`: AGENTS.md intentionally
  permits local production allows only for documented impossible states. The
  new scanner makes undocumented production allows fail CI.
- Beauvoir the 2nd and Dewey the 2nd's scanner-parser findings were accepted
  and fixed by block-based Rust attribute collection plus a stricter real
  `cfg(test)` exemption.
- Bacon the 2nd's group-lint and `expect` suppressor findings were accepted
  and fixed by scanning suppressor operations and group lints, while leaving
  crate-root `deny` attributes outside the scanner's failure set.
- Gauss/Darwin/Socrates' `cfg_attr` suppressor findings were accepted and
  fixed by scanning suppressor operations anywhere inside an attribute block
  while keeping the test-only exemption exact.
- Peirce's final scanner findings were accepted and fixed by lint-path
  normalisation, bracket-aware attribute collection, and `$lint` detection.
- Aristotle/James' parser and broad-scope findings were accepted and fixed by
  comment-aware attribute tokenisation plus an item-scope suppressor ban.
- Anscombe/Volta's final feature-shape and macro findings were accepted and
  fixed by source-level naked-call scanning, the `macro_rules!` regex fix,
  no-`unstable-engine` doctrine lint jobs, and unwrap/expect denial on bin/FFI
  all-target clippy jobs.
- Parfit/Carver's basename-trust and macro-metavariable findings were accepted
  and fixed by parent-cfg external module discovery and a hard ban on `$` lint
  suppressors.
- Faraday/Hooke's UFCS, unwrap_err/expect_err, macro layout, inline-attribute,
  and dual-include findings were accepted and fixed by broadening panic-call
  detection, recognising spaced `macro_rules !`, collecting inline attributes,
  and distinguishing test-only external modules from files also included by
  production modules.
- Ampere/Einstein's final scanner findings were accepted and fixed by covering
  turbofish/angle-qualified UFCS, raw identifier calls, same-line item
  suppressors, same-line exact test modules, and the raw-string token length
  drift that could misalign later attributes.
- Raman/Franklin's multiline-UFCS and transitive-test-module findings were
  accepted and fixed by allowing newlines inside type-path panic-call matching
  and computing module context as a graph closure from production roots and
  exact test-only roots.
- Sagan's exact-suppressor finding was accepted and fixed by making
  `clippy::restriction` / `clippy::all` hard failures. Panic-discipline escapes
  now must name `clippy::unwrap_used` or `clippy::expect_used` exactly.
- Boole/Schrodinger/Kepler's final exactness findings were accepted and fixed
  by structurally matching braced const-generic UFCS calls, binding documented
  suppressor ranges to the exact unwrap/expect lint they name, and preserving
  inline test-module child declarations during module graph discovery.

Line budget sign-off:

- Staged implementation surface exceeds the nominal 500-line production budget
  because `tools/panic_discipline_scan.py` is a new source scanner rather than a
  small local Rust edit. The overage is intentional and contained: the scanner
  is a CI enforcement tool, not runtime storage/auth/audit behaviour. The Rust
  production edits are crate-root lint walls and target-shape wiring:
  `bin/src/main.rs`, `ffi/src/lib.rs`, `ffi/src/bin/uniffi-bindgen.rs`, and the
  one-line `core/Cargo.toml` target-shape guard. Splitting the scanner into
  multiple PRs would create weaker intermediate CI states, so this layer keeps
  the enforcement physics atomic. Codex read the scanner in full during this
  final pass and signs off the overage as the implementation maintainer for
  this stack layer; the user authorised continuing the stack to completion and
  reviewing the final result rather than every intermediate slice.

FFI no-default validation note:

- CI includes `ffi --lib --no-default-features` and `ffi --bins
  --no-default-features` doctrine lints. `ffi/Cargo.toml` currently has no
  package features and still depends on `elastik-core` with
  `unstable-engine`; these commands are currently equivalent to the default
  FFI package shape but are kept as future-proof target wiring.

Final QA is recorded below after fresh reviewers inspect this latest repair.

Final QA repair addendum:

- Helmholtz the 2nd / QA-Enforcement found no P0/P1/P2 implementation issue
  and requested only final closeout plus `git diff --cached --check` evidence.
- Fermat the 2nd / Popper found two P1 scanner bypasses: function-item panic
  calls such as `Option::unwrap` and macro method-ident calls such as
  `call_method!(v, unwrap)`. Both were accepted and fixed by adding path-item
  detection and macro invocation ident scanning to
  `tools/panic_discipline_scan.py`.
- Cicero the 2nd / Mencius found a P2 unsafe-code physics gap: `bin` and `ffi`
  denied unwrap/expect but did not carry their own `unsafe_code` wall. This was
  accepted and fixed by adding crate-root `#![deny(unsafe_code)]` to
  `bin/src/main.rs`, `ffi/src/lib.rs`, and `ffi/src/bin/uniffi-bindgen.rs`,
  plus explicit CI `-D unsafe_code` gates for bin/FFI clippy jobs.

Additional validation after those repairs:

- Scanner probe: `values.into_iter().map(Option::unwrap).collect()` is
  rejected.
- Scanner probe: `call_method!(v, unwrap)` where a macro body calls
  `$v.$method()` is rejected.
- Scanner probe: `values.into_iter().map(Result::unwrap_err).collect()` is
  rejected.
- Scanner probe: a documented local `#[allow(clippy::unwrap_used)]` around
  `Option::unwrap(v)` is accepted.
- `python -m py_compile tools\panic_discipline_scan.py`
- `python tools\panic_discipline_scan.py core bin ffi`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::undocumented_unsafe_blocks -D clippy::unwrap_used -D clippy::expect_used`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --bins -- -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --bins --all-features -- -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --bins --no-default-features --features bundled-sqlite,unstable-engine -- -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --bins --no-default-features --features bundled-sqlite -- -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --lib -- -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --bins -- -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --lib --no-default-features -- -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --bins --no-default-features -- -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout`

Final closeout after read-only QA rerun:

- Popper rerun result: no remaining P0/P1/P2 findings for the prior
  function-item and macro-ident bypass class. The scanner now rejects
  `Option::unwrap` / `Result::unwrap_err` path items and panic method names
  passed inside macro invocation bodies.
- Mencius rerun result: no remaining unsafe-code physics gap for this layer.
  `bin` and `ffi` now carry crate-root `unsafe_code` denies and CI also passes
  `-D unsafe_code` for their clippy jobs.
- QA-Enforcement rerun result: no scope, residue, AGENTS, or staged-diff issue
  remains after this closeout. The staged surface is still intentionally one
  atomic CI enforcement layer.

Fresh final validation:

- `python -m py_compile tools\panic_discipline_scan.py`
- `python tools\panic_discipline_scan.py core bin ffi`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::undocumented_unsafe_blocks -D clippy::unwrap_used -D clippy::expect_used`
- `git diff --check`
- `git diff --cached --check`

## 22r75: Timeline HEAD corrupt parity

- Branch: `stack/22r75-timeline-head-corrupt-test`
- Commit: `c602f69 bin: cover timeline HEAD corrupt parity`
- Base: `stack/22r74-bin-no-default-test-hygiene`
- Scope: test-only coverage for
  `design_notes/PLAN-http-timeline-dereference.md` HEAD error parity.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer extends `pipeline_timeline_head_errors_have_no_body` to cover the
`TimelineDereference::Corrupt` 500 branch, not only 400/404/409 outcomes. The
test creates a delete-ledger row, builds a timeline coordinate against
`/var/log/deletes`, proves GET returns `500` with `timeline corruption\n`, then
proves HEAD returns the same status and headers with an empty body.

Confirmed and fixed review findings:

- Archimedes the 2nd / Popper found P1: the first attempt deleted
  `cas_bodies`, which triggered generic audit/storage failure rather than
  `TimelineDereference::Corrupt`. Fixed by targeting a verified
  `var/log/deletes` metadata row whose event target differs from the request
  world.
- Archimedes the 2nd / Popper found P2: the first attempt asserted only status
  and empty body, not GET/HEAD header parity. Fixed by comparing the full HEAD
  header map with the GET header map for the same corrupt coordinate.

Fresh post-fix review:

- Noether the 2nd / Popper: clean P0-P3. Confirmed the test reaches
  `match_body_row_target_first` -> `TargetMismatch` ->
  `TimelineDereference::Corrupt`, and the asserted GET body distinguishes it
  from the generic storage-error branch.
- Lagrange the 2nd / QA-Enforcement: clean P0-P3. Confirmed the layer is a
  small test-only stacked change and the new unwraps stay inside the test
  module's panic-lint allow.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_head_errors_have_no_body -- --nocapture`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --no-default-features --all-targets -- -D warnings`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`
- `git diff --cached --check`

## 22r76: Timeline ordinary-query wall

- Branch: `stack/22r76-timeline-ordinary-query-wall`
- Commit: `2ae6831 bin: cover timeline ordinary-query wall`
- Base: `stack/22r75-timeline-head-corrupt-test`
- Scope: test-only coverage for
  `design_notes/PLAN-http-timeline-dereference.md` Counterexample O and the
  endpoint checklist rule that timeline mode must not ignore ordinary query
  fields.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer extends `pipeline_timeline_query_errors_are_closed_and_head_empty`.
It first writes a real current body at `home/timeline/errors`, then sends two
timeline-looking requests that also carry an ordinary `x=1` query field:

- `x=1` after the timeline coordinate fields;
- `x=1` before the timeline mode field.

Both requests must return `400` with
`UnsupportedTimelineQueryField`. This proves the route does not fall through
to the current read path and does not leak the current body when a timeline
request is malformed by extra ordinary query state.

Confirmed and fixed review findings:

- Descartes the 2nd / Popper found P3 in the first version: it covered only
  `x=1` after timeline fields and asserted only `400` plus "not current",
  not the exact closed error reason. Fixed by covering both ordinary-field
  orderings and asserting the exact
  `bad request: invalid timeline query: UnsupportedTimelineQueryField\n`
  response body.

Fresh post-fix review:

- Descartes the 2nd / Popper: clean P0-P3. Confirmed the prior P3 is fully
  closed and the test proves no current-body fallthrough for the plan gap.
- Zeno the 2nd / QA-Enforcement: clean P0-P3. Confirmed the layer remains a
  one-file test-only stacked change with no production unwrap/expect/unsafe
  additions and sufficient local validation.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_query_errors_are_closed_and_head_empty -- --nocapture`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`

## 22r77: Timeline query world identity wall

- Branch: `stack/22r77-timeline-world-query-wall`
- Commit: `a88ea45 bin: reject timeline query world identity`
- Base: `stack/22r76-timeline-ordinary-query-wall`
- Scope: test-only route-level coverage for
  `design_notes/PLAN-http-timeline-dereference.md` Counterexample C:
  `timeline-world` must never be accepted as a second world identity.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer adds `pipeline_timeline_query_rejects_query_world_identity`. The
test writes an old historical body for `home/timeline/world-query`, writes a
new current body, then sends a timeline query for the path world that also
includes `timeline-world=home/timeline/other`. The expected result is `400`
with `TimelineWorldComesFromPath`. This proves the HTTP route rejects the
query identity before current-read fallback or timeline dispatch.

Fresh review:

- Lovelace the 2nd / Popper: clean P0-P3. Confirmed this closes
  Counterexample C at route level and exercises the full `run()` pipeline, not
  only the parser unit.
- Herschel the 2nd / QA-Enforcement: clean P0-P3. Confirmed the layer is
  test-only, introduces no production unwrap/expect/unsafe, preserves stacked
  minimality, and has sufficient local validation.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_query_rejects_query_world_identity -- --nocapture`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`


## 22r78: Reserved route topology

- Branch: `stack/22r78-route-topology-owned-prefixes`
- Commit: `d90d872 bin: cover reserved route topology`
- Base: `stack/22r77-timeline-world-query-wall`
- Scope: test-only full-app coverage for the route-topology checklist in
  `design_notes/PLAN-http-timeline-dereference.md`.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/route.rs` under the existing `#[cfg(test)]` module.

The layer adds `reserved_routes_keep_ownership_ahead_of_world_catchall`. It
uses `build_app(state)` so the real axum route table is exercised. The test
proves:

- `/` is still owned by `root_hint`;
- `/listen/*` is still owned by the listen handler, checked via finite
  `OPTIONS` and `listen::ALLOW`;
- `/proc/version` is still owned by the concrete proc handler;
- `/proc/{*reserved}` is still owned by the reserved proc handler, checked via
  finite `OPTIONS` and `PROC_ALLOW`.

Together with existing full-app tests for `/timeline/foo` as an ordinary
`home/timeline/foo` world and `/proc/audit/*` as proc audit verification, this
closes the route-topology checklist without adding any `/timeline/*` route.

Fresh review:

- Nash the 2nd / Popper: clean P0-P3. Confirmed the test genuinely closes the
  stated route-topology gap and, together with existing `/timeline/foo` and
  `/proc/audit/*` tests, satisfies the checklist.
- McClintock the 2nd / QA-Enforcement: clean P0-P3. Confirmed the layer is
  test-only, introduces no production unwrap/expect/unsafe, preserves stacked
  minimality, and has sufficient local validation.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml reserved_routes_keep_ownership_ahead_of_world_catchall -- --nocapture`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`

## 22r79: Timeline memory-world wall

- Branch: `stack/22r79-timeline-memory-world-wall`
- Commit: `0b8ac69 bin: reject timeline on memory worlds`
- Base: `stack/22r78-route-topology-owned-prefixes`
- Scope: test-only route-level coverage for
  `design_notes/PLAN-http-timeline-dereference.md` Counterexample U:
  timeline coordinates are durable-world coordinates only.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer extends `pipeline_timeline_query_errors_are_closed_and_head_empty`.
For each memory prefix (`tmp`, `dev`, `sys`), the test writes a current
memory-world body, then sends a full timeline query through `pipeline::run`.
Each case must return `400` with
`InvalidTimelineCoordinate(MemoryWorld)`. This proves timeline-looking memory
world requests do not fall through to current memory read semantics.

Confirmed and fixed review findings:

- Laplace the 2nd / Popper found P3 in the first version: only `tmp/` was
  covered at route level. Fixed by looping over all memory prefixes
  implemented by `store::is_memory_world`: `tmp`, `dev`, and `sys`.

Fresh post-fix review:

- Laplace the 2nd / Popper: clean P0-P3. Confirmed the prior P3 is closed and
  durable-only timeline mode is route-level proven for every memory namespace.
- Gibbs the 2nd / QA-Enforcement: clean P0-P3. Confirmed the layer remains
  test-only, introduces no production unwrap/expect/unsafe, preserves stacked
  minimality, and has sufficient local validation.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_query_errors_are_closed_and_head_empty -- --nocapture`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`

## 22r80: Missing timeline world stays unproven

- Branch: `stack/22r80-timeline-unproven-not-gone`
- Commit: `110c637 bin: keep missing timeline worlds unproven`
- Base: `stack/22r79-timeline-memory-world-wall`
- Scope: test-only route-level coverage for
  `design_notes/PLAN-http-timeline-dereference.md` Counterexample F:
  physical absence is not delete proof.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer adds `pipeline_timeline_missing_world_is_unproven_not_gone`. It sends
a valid timeline-shaped GET to a durable world whose SQLite file has never
existed. The expected response is `404` with
`timeline coordinate not proven\n`, not the ordinary current-read
`world not found\n` body and not `410 Gone`. This proves the request enters
timeline mode and that missing files do not mint delete facts.

Fresh review:

- Halley the 2nd / Popper: clean P0-P3. Confirmed this closes Counterexample F
  at route level and the exact body proves timeline mode rather than ordinary
  current-read absence.
- Sartre the 2nd / QA-Enforcement: clean P0-P3. Confirmed the layer is
  test-only, introduces no production unwrap/expect/unsafe or reason-erasing
  constructor, preserves stacked minimality, and has sufficient local
  validation.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_missing_world_is_unproven_not_gone -- --nocapture`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`

## 22r81: Duplicate timeline mode wall

- Branch: `stack/22r81-timeline-duplicate-mode-wall`
- Commit: `a16bed6 bin: reject duplicate timeline mode`
- Base: `stack/22r80-timeline-unproven-not-gone`
- Scope: test-only route-level coverage for
  `design_notes/PLAN-http-timeline-dereference.md` Counterexample N:
  duplicate `timeline` mode parameters must not collapse through a map parser.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer extends `pipeline_timeline_query_errors_are_closed_and_head_empty`
with a full `pipeline::run` request containing `timeline=1&timeline=0` plus a
complete coordinate. The response must be `400` with
`DuplicateTimelineMode`. The current-body sentinel already present in the test
would catch current-read fallthrough; the exact error body also catches both
"first value wins" and "last value wins" map-collapse regressions.

Fresh review:

- Euler the 2nd / Popper: clean P0-P3. Confirmed this closes Counterexample N
  at route level and the exact body rules out both duplicate-collapse
  directions and current-read fallthrough.
- Hume the 2nd / QA-Enforcement: clean P0-P3. Confirmed the layer is minimal,
  test-only, introduces no production unwrap/expect/unsafe, preserves stacked
  minimality, and has sufficient local validation.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_query_errors_are_closed_and_head_empty -- --nocapture`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`

## 22r82: Timeline missing-row wire distinction

- Branch: `stack/22r82-timeline-missing-row-wire`
- Commit: `85c124b bin: distinguish missing timeline rows`
- Base: `stack/22r81-timeline-duplicate-mode-wall`
- Scope: test-only route-level coverage for
  `design_notes/PLAN-http-timeline-dereference.md` Counterexample G:
  an existing durable world with a valid generation/hash but missing event row
  must not collapse into the missing-world/unproven-coordinate response.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer extends `pipeline_timeline_head_errors_have_no_body`. It first writes
the durable world and captures a real timeline address, then asks for the same
generation and body hash at sequence `99`. GET must return `404` with
`timeline row not found\n`; HEAD on the same coordinate must still return
`404` with an empty body. The previous 22r80 test remains the separate proof
that a missing durable file returns `timeline coordinate not proven\n`.

Fresh review:

- Ohm the 2nd / Popper: clean P0-P3. Confirmed the valid address stem plus
  absent sequence proves MissingRow, not UnprovenCoordinate, and noted that the
  GET-before-HEAD cache warming does not affect response-body suppression.
- Hubble the 2nd / Mencius + QA-Enforcement: clean P0-P3. Confirmed the layer
  is test-only, introduces no production unwrap/expect/unsafe, changes no
  internal API or type-seal boundary, and keeps route-level HTTP walls explicit.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_head_errors_have_no_body -- --nocapture`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`

## 22r83: Timeline generation-mismatch wire body

- Branch: `stack/22r83-timeline-generation-wire`
- Commit: `2e9c217 bin: assert timeline generation mismatch body`
- Base: `stack/22r82-timeline-missing-row-wire`
- Scope: test-only route-level coverage for
  `design_notes/PLAN-http-timeline-dereference.md` Counterexample I:
  generation mismatch must be decided before row/hash lookup and must map to a
  distinct `409` wire body.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer extends `pipeline_timeline_head_errors_have_no_body`. It reuses a
real durable timeline address, changes only the generation, and sends GET
before the existing HEAD assertion. GET must return `409` with
`timeline generation mismatch\n`; HEAD on the same coordinate still returns
`409` with an empty body. This distinguishes GenMismatch from the neighbouring
`409` BodyHashMismatch branch, which HEAD alone cannot prove.

Fresh review:

- Heisenberg the 2nd / Popper: clean P0-P3. Confirmed the assertion is not
  redundant with HEAD because HEAD suppresses the body and both GenMismatch and
  BodyHashMismatch use `409`.
- Jason the 2nd / Mencius + QA-Enforcement: clean P0-P3. Confirmed the layer
  is test-only, adds no production API surface, introduces no production
  unwrap/expect/unsafe, and touches no type-seal boundary.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_head_errors_have_no_body -- --nocapture`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`

## 22r84: Timeline body-hash-mismatch wire body

- Branch: `stack/22r84-timeline-bodyhash-wire`
- Commit: `6dc51d8 bin: assert timeline body hash mismatch body`
- Base: `stack/22r83-timeline-generation-wire`
- Scope: test-only route-level coverage for
  `design_notes/PLAN-http-timeline-dereference.md` Counterexample H:
  an existing row with a different body hash must map to the distinct
  BodyHashMismatch `409` body rather than MissingRow, GenMismatch, or Corrupt.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer extends `pipeline_timeline_head_errors_have_no_body`. It reuses a
real durable timeline address, preserves the generation and sequence, and
changes only the body SHA-256. GET must return `409` with
`timeline body sha256 mismatch\n`; HEAD on the same coordinate still returns
`409` with an empty body. This pins the neighbouring `409` branch that 22r83
left distinguishable only through core tests and handler code.

Fresh review:

- Hypatia the 2nd / Popper: clean P0-P3. Confirmed the test is not redundant
  because it proves the HTTP wire body for BodyHashMismatch rather than the
  lower-level enum branch.
- Bernoulli the 2nd / Mencius + QA-Enforcement: clean P0-P3. Confirmed the
  layer is test-only, changes no production API, introduces no production
  unwrap/expect/unsafe, and preserves type-seal discipline.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_head_errors_have_no_body -- --nocapture`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`

## 22r85: Timeline HTTP status docs

- Branch: `stack/22r85-timeline-doc-statuses`
- Commit: `d84c47e docs: document timeline HTTP statuses`
- Base: `stack/22r84-timeline-bodyhash-wire`
- Scope: docs-only parity for
  `design_notes/PLAN-http-timeline-dereference.md` section 8: the HTTP adapter
  README now documents the timeline query mode statuses, proof-header output
  shape, `HEAD` body suppression, and the no-current-body fallback rule.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/http/README.md`.

The layer extends the `/listen/*` timeline section with a closed status table
for timeline-looking HTTP requests. It documents `204` policy-free `OPTIONS`,
historical `GET` and `HEAD` `200` responses, timeline query `400` failures,
read-token `401`, timeline-method `405`, raw-query-cap `414`, resolver `409`
and `404` distinctions, and storage/internal `500` / `503` / `507` failures.
It also states that `HEAD` timeline failures keep status and headers while
returning no body, and that failed historical dereference never falls back to
the current world body.

Fresh review:

- Rawls the 2nd / Sagan + Heisenberg initially found two P3 documentation
  drift issues: the table omitted policy-free `OPTIONS` `204`, and the `400`
  row omitted the `EngineError::InvalidMetadata` mapping. Both were fixed, and
  the re-review returned clean P0-P3.
- Ptolemy the 3rd / Bacon + Mencius + QA-Enforcement: clean P0-P3. Confirmed
  the layer is docs-only, the status table matches `timeline_mode.rs`,
  `timeline.rs`, and `route.rs`, and no code/type-seal/unsafe/unwrap surface
  changed.

Validation:

- `git status --short --branch`
- `git diff --name-status`
- `git diff --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml timeline -- --nocapture`
- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `python tools\panic_discipline_scan.py core bin ffi`

## 22r86: Timeline namespace pair cap proof

- Branch: `stack/22r86-timeline-pair-cap-test`
- Commit: `67a24ca bin: prove timeline namespace pair cap`
- Base: `stack/22r85-timeline-doc-statuses`
- Scope: closes Hooke the 3rd's PLAN section 8 P2 that the decoded-pair cap
  had no test evidence. The layer adds parser and full-pipeline coverage for
  saturated timeline-control namespace queries.
- Production diff: small parser guard only in `bin/src/server/pipeline/query.rs`.
  Test coverage is in `bin/src/server/pipeline/query.rs` and
  `bin/src/server/pipeline.rs`; `PLAN-http-timeline-dereference.md` was
  clarified to match the reviewed cap semantics.

The parser now counts decoded pairs once a timeline control key has appeared.
Ordinary query strings with no timeline-looking key remain `Current`. Small
timeline-control mistakes keep their specific `400` reasons, including
`UnsupportedTimelineQueryField` for one extra ordinary field and
`TimelineWorldComesFromPath` for `timeline-world`. Saturated
timeline-control namespace requests return `TooManyTimelineFields`, and the
full `pipeline::run` test proves that response is a `400` rather than current
body fallthrough.

Fresh review:

- Singer the 3rd / Popper + Poincare: clean P0-P3. Confirmed the cap path does
  not regress current-query compatibility, specific small-error reasons, or the
  full pipeline no-fallthrough rule.
- Hegel the 3rd / Bacon + Mencius + QA-Enforcement initially found P3
  PLAN/implementation drift because the first version increased the cap without
  updating PLAN wording. The PLAN was clarified to distinguish small semantic
  errors from saturated namespace floods, and the re-review returned clean
  P0-P3.

Validation:

- `cargo test --locked --manifest-path bin\Cargo.toml timeline_namespace_pair_cap_is_enforced_after_control_key -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_query_errors_are_closed_and_head_empty -- --nocapture`
- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `git diff --check`
- `cargo test --locked --manifest-path bin\Cargo.toml timeline -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `python tools\panic_discipline_scan.py core bin ffi`

## 22r87: Timeline HEAD error header parity

- Branch: `stack/22r87-timeline-head-header-parity`
- Commit: `485209d bin: assert timeline HEAD error headers`
- Base: `stack/22r86-timeline-pair-cap-test`
- Scope: closes Hooke the 3rd's PLAN section 8 P2 that HEAD error parity had
  body/status evidence but incomplete header equality proof for `400`, `404`,
  and `409` timeline failures.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer strengthens `pipeline_timeline_head_errors_have_no_body` and
`pipeline_timeline_query_errors_are_closed_and_head_empty` by cloning GET
headers before consuming the response body, then asserting that HEAD on the
same failing coordinate/query returns identical headers and an empty body. The
covered cases are `400` malformed timeline query, `404` MissingRow, both `409`
branches, and the existing `500` corrupt branch.

Fresh review:

- Russell the 3rd / Popper + Noether: clean P0-P3. Confirmed the layer covers
  `400`, `404`, both `409` variants, and the existing `500` corrupt branch,
  and that GET headers are cloned before response-body consumption.
- Lagrange the 3rd / Bacon + Mencius + QA-Enforcement: clean P0-P3. Confirmed
  the layer is test-only, adds no production unwrap/expect/unsafe or type-seal
  bypass, and requires a ledger entry.

Validation:

- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_head_errors_have_no_body -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_query_errors_are_closed_and_head_empty -- --nocapture`
- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `git diff --check`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `python tools\panic_discipline_scan.py core bin ffi`

## 22r88: Timeline non-body event wire proof

- Branch: `stack/22r88-timeline-nonbody-event-wire`
- Commit: `5e5f699 bin: cover timeline non-body event wire`
- Base: `stack/22r87-timeline-head-header-parity`
- Scope: closes Hooke the 3rd's PLAN section 8 P2 that
  `TimelineDereference::NonBodyEvent` had core resolver coverage and handler
  mapping but no full HTTP endpoint proof.
- Production diff: 0 lines. The changed Rust source is test-only under
  `#[cfg(test)]`; `bin` gained direct `hmac` and `sha2` dev-dependency edges so
  the endpoint fixture can sign a valid audit row with the same algorithm as
  core. The lockfile diff only adds those root dev-dependency edges.

The layer adds a full pipeline `GET`/`HEAD` proof for a durable world whose
first audit row is rewritten into a signed non-body `delete_intent` event. The
fixture uses the server test HMAC key, the same HMAC field labels/order as
core (`prev`, `type`, `target`, `gen`, `body-sha256`, `size`,
`content-type`, `meta-sha256`), clears CAS retention state so audit
verification remains intact, and keeps the event target equal to the request
world. The request therefore reaches the resolver's `NonBodyEvent` branch
instead of corruption, missing-row, body-hash mismatch, or unproven-coordinate
branches. The HTTP proof asserts `GET` returns `404` with
`timeline event has no body\n`, and `HEAD` returns the same headers with an
empty body.

Fresh review:

- Dewey the 3rd / Popper + Noether: clean P0-P3. Confirmed HMAC/meta parity
  with core, generation and audit-chain verification before row
  classification, target-first non-body classification, CAS retention clearing,
  full `pipeline::run` coverage, and `TimelineDereference::NonBodyEvent` handler
  mapping to `404`.
- Gauss the 3rd / Carson + Bacon + Mencius + QA-Enforcement: clean P0-P3.
  Confirmed `hmac` and `sha2` are direct `bin` dev-dependencies only, both were
  already present through `elastik-core`, the lockfile diff only adds root
  edges, no production code path changed, and `TEST_HMAC_KEY` is exposed only
  through the `#[cfg(test)]` server test-support module.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_head_errors_have_no_body -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml timeline -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`

## 22r89: Timeline proof-header ownership

- Branch: `stack/22r89-timeline-proof-header-spoof`
- Commit: `06967f1 bin: prove timeline proof header ownership`
- Base: `stack/22r88-timeline-nonbody-event-wire`
- Scope: closes the remaining PLAN section 8 / Counterexample Q proof gap that
  persisted metadata must not spoof or duplicate any trusted `X-Timeline-*`
  proof header.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer strengthens `pipeline_timeline_get_returns_historical_body_and_proof_headers`.
The historical event metadata now tries to persist all four trusted proof
headers: `x-timeline-world`, `x-timeline-generation`, `x-timeline-seq`, and
`x-timeline-body-sha256`. The test asserts the historical response contains
exactly one value for each proof header, and that the values match the verified
timeline address rather than the persisted spoofed metadata. The same test
continues to prove ordinary allowed metadata (`content-language`) survives and
that historical success responses suppress current-read headers: `ETag`,
`Accept-Ranges`, `Content-Range`, and `Link`.

Fresh review:

- Aquinas the 3rd / Sagan + Noether: clean P0-P3. Confirmed all four spoofed
  persisted proof headers are seeded, every response proof header is asserted
  single-valued and core-minted, ordinary metadata still survives, current-read
  headers remain suppressed, metadata replay filters hard-denied names before
  proof headers are appended, and duplicate leakage would be observable because
  response construction appends duplicate values rather than overwriting.
- Mill the 3rd / Bacon + Mencius + QA-Enforcement: clean P0-P3. Confirmed the
  layer is test-only, no new public API or unsafe is introduced, no raw proof
  bypass is added, and the new unwraps remain inside the existing test-module
  allowance.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_get_returns_historical_body_and_proof_headers -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml timeline -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `python tools\panic_discipline_scan.py core bin ffi`
- `python tools\header_policy_scan.py --offline`
- `git diff --check`

## 22r90: Deleted timeline worlds stay unproven

- Branch: `stack/22r90-timeline-deleted-unproven`
- Commit: `1e36457 bin: prove deleted timeline worlds stay unproven`
- Base: `stack/22r89-timeline-proof-header-spoof`
- Scope: closes the PLAN section 8 / Counterexamples F, K, and L proof gap
  that v1 must not scan `var/log/deletes` or emit `Gone` for a deleted subject
  world without a bounded delete-proof lookup.
- Production diff: 0 lines. The only changed file is
  `bin/src/server/pipeline.rs` under the existing `#[cfg(test)]` module.

The layer strengthens `pipeline_timeline_missing_world_is_unproven_not_gone`.
It now covers both an ordinary never-created missing durable world and a
durable world that was created, produced a real timeline address, then was
deleted with a real `var/log/deletes` ledger present. The deleted-world request
uses the old captured coordinate and still receives `404` with
`timeline coordinate not proven\n`, proving the HTTP timeline path does not
fall back to current reads, does not infer `Gone` from physical absence, and
does not scan the delete ledger in v1.

Fresh review:

- Volta the 3rd / Popper + Poincare: clean P0-P3. Confirmed the case is not
  merely never-created, uses a real deleted world and real delete ledger,
  enters the timeline route, avoids current-read fallback, does not reference
  `var/log/deletes` in the dereference path, and maps the missing/deleted
  subject to `UnprovenCoordinate` / `404`.
- Franklin the 3rd / Bacon + Mencius + QA-Enforcement: clean P0-P3. Confirmed
  the layer is test-only, adds no public API or unsafe, adds no raw proof
  bypass, and the new unwrap is inside the existing test-module allowance.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_missing_world_is_unproven_not_gone -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml timeline -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `python tools\panic_discipline_scan.py core bin ffi`
- `git diff --check`

## 22r91: Timeline blocking-boundary evidence

- Branch: `stack/22r91-timeline-spawn-blocking-evidence`
- Commit: `8227cfa bin: document timeline blocking boundary`
- Base: `stack/22r90-timeline-deleted-unproven`
- Scope: closes the PLAN section 7/8 evidence item that HTTP timeline
  dereference must run SQLite / filesystem / read-cache work through
  `spawn_blocking` at the binary adapter boundary.
- Production diff: comment-only. The only changed file is
  `bin/src/server/handler/timeline.rs`, where the comment is attached to the
  existing `tokio::task::spawn_blocking` boundary in `execute_timeline`.

The call graph is:

`execute_timeline` -> `spawn_blocking` ->
`Engine::dereference_timeline_coordinate` -> `EngineOps` ->
`world_read_ops::dereference_timeline_coordinate` ->
`ReadCache::cached_dereference_timeline_coordinate` ->
`with_tracked_conn` -> `dereference_timeline_coordinate_via_conn`.

Pre-dispatch work remains query classification only, and post-await work
remains response mapping. The SQLite open/verify path, audit transaction, audit
chain verification, row classification, and retained-CAS body lookup stay
inside the blocking worker.

Fresh review:

- Avicenna the 3rd / Hooke + Bacon: clean P0-P3. Confirmed the
  `spawn_blocking` closure covers the full dereference path, including
  read-cache connection open/verify, audit transaction, and retained-CAS lookup;
  no storage work happens on the Tokio worker before or after the closure; and
  no runtime hook is needed because the call graph pins the boundary directly.
- Wegener the 3rd / Mencius + QA-Enforcement: clean P0-P3. Confirmed the layer
  is a valid small comment-only stack layer, the comment captures a non-obvious
  blocking/resource invariant, and no public API, unsafe, behaviour change, or
  unwrap/expect is introduced.

Validation:

- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `git diff --check`
- `cargo test --locked --manifest-path bin\Cargo.toml timeline -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `python tools\panic_discipline_scan.py core bin ffi`

## 22r92: Timeline no-new-env parity

- Branch: `stack/22r92-timeline-no-env-doc`
- Commit: `13eaeae docs: document timeline env parity`
- Base: `stack/22r91-timeline-spawn-blocking-evidence`
- Scope: closes the PLAN section 8 `.env.example` parity item by documenting
  why timeline mode adds no environment variables instead of inventing a fake
  timeline-specific knob.
- Production diff: docs-only. The only changed file is
  `bin/src/server/http/README.md`.

Timeline mode reuses the existing HTTP adapter controls: read-token
authorization, header persistence policy, read-cache settings, and storage
settings. The README now states that explicitly next to the timeline
dereference contract, so `.env.example` stays aligned without adding a dead
configuration surface.

Fresh review:

- Newton the 3rd / Sagan + Heisenberg: clean P0-P3. Confirmed the diff is
  docs-only, matches the PLAN allowance for either env parity or explicit
  no-new-env rationale, and the reused-setting list matches the implementation
  paths for read authorization, timeline dereference, persisted metadata, and
  hard-denied `x-timeline-*` spoofing.
- Socrates the 3rd / Bacon + Mencius + QA-Enforcement: clean P0-P3. Confirmed
  the layer adds no code/API/unsafe/panic diff, introduces no timeline env var,
  satisfies the AGENTS README / `.env.example` parity rule, and remains inside
  the deep-stack local repair exception constraints.

Validation:

- `git status --short --branch`
- `git diff --name-status`
- `git diff --stat`
- `git diff --check`
- `rg -n "ELASTIK_.*TIMELINE|TIMELINE_.*ELASTIK" -S .` returned no matches.
- `rg -n "Timeline mode adds no environment variables" bin/src/server/http/README.md`
- `cargo test --locked --manifest-path bin\Cargo.toml timeline -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `python tools\panic_discipline_scan.py core bin ffi`
- `cargo fmt --manifest-path bin\Cargo.toml --check`
- `cargo fmt --manifest-path core\Cargo.toml --check`
- `cargo fmt --manifest-path ffi\Cargo.toml --check`

## 22r93: Panic discipline wording matches current lint gate

- Branch: `stack/22r93-panic-discipline-current`
- Commit: `d9f590d docs: align panic discipline with current lint gate`
- Base: `stack/22r92-timeline-no-env-doc`
- Scope: removes stale process wording that described the crate-root
  `clippy::unwrap_used` / `clippy::expect_used` deny gate as a future target
  even though `core`, `bin`, and `ffi` already carry the lint wall.
- Production diff: docs-only. The only changed file is `AGENTS.md`.

The panic-discipline contract now states the current rule directly:
production crates carry crate-root deny attributes for naked `unwrap` and
`expect`; reviewers must keep that lint wall present; any production escape
must be local, documented, and accepted by `tools/panic_discipline_scan.py`.

Fresh review:

- Leibniz the 3rd / Sagan + Heisenberg: clean P0-P3. Confirmed the wording
  does not overclaim compiler enforcement: unsafe remains the compiler wall,
  while unwrap/expect is described as a Clippy lint wall plus process/scanner
  enforcement. Confirmed `core`, `bin`, and `ffi` crate roots match the new
  wording and the scanner still enforces exact lint-name suppressors.
- Peirce the 3rd / Bacon + Mencius + QA-Enforcement: initially found one P2
  process issue: the layer was not commit-ready until this durable ledger entry
  recorded the branch, validation, reviewer lenses, and fresh clearance. The
  re-review was clean P0-P3 and confirmed the entry does not overclaim the
  initial QA result.

Validation:

- `git status --short --branch`
- `git diff --name-status`
- `git diff --stat`
- `git diff --check`
- `python tools\panic_discipline_scan.py core bin ffi`
- `cargo clippy --locked --manifest-path core\Cargo.toml --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks -D clippy::unwrap_used -D clippy::expect_used`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `cargo clippy --locked --manifest-path ffi\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::undocumented_unsafe_blocks -D clippy::unwrap_used -D clippy::expect_used`

## 22r94: Config and process docs drift cleanup

- Branch: `stack/22r94-doc-drift-cleanup`
- Base: `stack/22r93-panic-discipline-current`
- Scope: docs drift cleanup across existing config and process docs. This
  layer fixes three documentation subclaims without changing code:
  `AGENTS.md` panic-discipline origin wording, `.env.example` cap parser
  fallback wording, and HTTP README trace-env wording.
- Production-facing docs diff: `AGENTS.md`, `.env.example`, and
  `bin/src/server/http/README.md`. This ledger file was updated as the durable
  review artifact for the layer.

Findings fixed:

- Curie the 3rd / Heisenberg + Sagan found P2: `AGENTS.md` still said the
  unwrap/expect lint gate was planned physics even though `core`, `bin`, and
  `ffi` already carry crate-root `clippy::unwrap_used` /
  `clippy::expect_used` deny gates. The origin text now says the lint gate is
  part of the crate-root contract.
- Curie also found P3: `.env.example` said zero and non-numeric cap values
  both fall back for connection/replay/CoAP caps. The implementation maps zero
  to default but fails startup on non-numeric values, so the docs now state that
  distinction.
- Curie also found P3: the HTTP README said `ELASTIK_TRACE_PIPELINE` emits
  trace lines "when set". The implementation enables trace only for `1`,
  `true`, `yes`, or `on`, so the README now names those truthy values.

Fresh review:

- Noether the 3rd / Heisenberg + Sagan: clean P0-P3. Confirmed the three
  reported docs drift items are fixed and no new unsupported overclaim was
  introduced.
- Maxwell the 3rd / Bacon + QA-Enforcement initially found one process P2: the
  layer was not commit-ready without this durable ledger entry. It also noted
  P3 requirements to name the three docs subclaims and record Curie's findings
  honestly rather than flattening them into a clean review.

Validation:

- `git status --short --branch`
- `git diff --name-status`
- `git diff --cached --name-status`
- `git diff --stat`
- `git diff --numstat`
- `git diff --check`
- `git diff --name-only -- '*.rs' '*.toml' '*.lock' '*.py' '*.yml' '*.yaml'`
  returned no matches.
- Diff symbol scan for code/API/unsafe/panic tokens returned no matches.
- `rg -n "planned physics|before that gate lands|Zero/non-numeric|Emit request pipeline trace lines when set\.|Zero or non-numeric" AGENTS.md .env.example bin\src\server\http\README.md` returned no matches.
- `rg -n "ELASTIK_TRACE_PIPELINE|truthy_env|trace" bin\src\server\pipeline\context.rs bin\src\server\mod.rs bin\src\server\http\README.md`
- `cargo test --locked --manifest-path bin\Cargo.toml resource_cap_env -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml optional_storage_quota_zero_is_unlimited -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml init_trace_from_env -- --nocapture`
- `python tools\panic_discipline_scan.py core bin ffi`
- `python tools\header_policy_scan.py --offline`

## 22r95: Timeline delete ledger does not overclaim earlier coordinates

- Branch: `stack/22r95-timeline-delete-earlier-coordinate-proof`
- Base: `stack/22r94-doc-drift-cleanup`
- Scope: closes Darwin the 3rd's P3 evidence gap for PLAN Counterexample K.
  The new endpoint test covers the exact shape where seq 1 has body `B`, seq 2
  has final body `C`, the world is deleted, and the client later asks for seq 1.
- Production diff: 0 lines. The only changed production-adjacent file is
  `bin/src/server/pipeline.rs`, under the existing `#[cfg(test)]` module.

The test writes `home/timeline/delete-ledger-k` once and asserts the captured
timeline address has sequence 1. It writes the same world again with a different
body, asserts the captured final address has sequence 2 and a different body
hash, then deletes the world and confirms `var/log/deletes` exists. A timeline
GET for the seq-1 coordinate then returns `404` with
`timeline coordinate not proven\n`, proving the current v1 HTTP path does not
turn the final delete fact into `410 Gone` for an earlier coordinate.

Fresh review:

- Nietzsche the 3rd / Popper + Noether: clean P0-P3. Confirmed the test covers
  Counterexample K's required shape, changes no production code, and excludes
  `410 Gone` by asserting `404` plus the unproven body.
- Heisenberg the 3rd / Bacon + QA-Enforcement initially found one process P2:
  the content was clean but not commit-ready until this durable ledger entry
  recorded the layer evidence. It also confirmed the diff is test-only,
  single-concern, and introduces no production code, public API, unsafe, route,
  lint-wall, or panic-policy change.

Validation:

- `git status --short --branch`
- `git diff --name-status`
- `git diff --stat`
- `git diff --cached --name-status`
- `git diff --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_delete_ledger_does_not_overclaim_earlier_coordinates -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml timeline -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `python tools\panic_discipline_scan.py core bin ffi`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`

## 22r96: Timeline poisoned current headers stay suppressed

- Branch: `stack/22r96-timeline-poisoned-header-proof`
- Base: `stack/22r95-timeline-delete-earlier-coordinate-proof`
- Scope: closes Darwin the 3rd's P3 evidence gap for PLAN section 8 header
  deny-list endpoint evidence. The historical response test now poisons
  persisted metadata with current-read response headers and proves they are
  filtered before the response is returned.
- Production diff: 0 lines. The only changed production-adjacent file is
  `bin/src/server/pipeline.rs`, under the existing `#[cfg(test)]` module.

The strengthened test stores allowed metadata, spoofed `X-Timeline-*` proof
headers, and poisoned current-read response headers: `ETag`, `Accept-Ranges`,
`Content-Range`, and `Link`. It still asserts allowed metadata survives,
trusted proof headers are single-valued and core-minted, and historical
responses suppress `ETag`, `Accept-Ranges`, `Content-Range`, and `Link`.

Fresh review:

- Galileo the 3rd / Popper + Sagan: clean P0-P3. Confirmed the poisoned
  headers and suppression assertions match PLAN section 8, and no production
  code changed.
- Tesla the 3rd / Bacon + QA-Enforcement initially found one process P2: the
  content was clean but not commit-ready until this durable ledger entry
  recorded the branch, base, scope, production diff, reviewer lenses, and
  validation evidence.

Validation:

- `git status --short --branch`
- `git diff --name-status`
- `git diff --stat`
- `git diff --cached --name-status`
- `git diff --check`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_get_returns_historical_body_and_proof_headers -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml timeline -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `python tools\panic_discipline_scan.py core bin ffi`
- `python tools\header_policy_scan.py --offline`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`

## 22r97: Listen cursor docs use opaque SSE IDs

- Branch: `stack/22r97-listen-cursor-doc-parity`
- Base: `stack/22r96-timeline-poisoned-header-proof`
- Scope: closes Harvey the 3rd's P2 docs/type-shape drift: primary listen
  examples still showed decimal SSE `id` values even though the implementation
  emits opaque subscription cursors. This layer also fixes two nearby P3 docs
  drift items reported in the same review round.
- Production diff: docs-only. No Rust, route, public API, storage, unsafe,
  panic-policy, or lint-wall change.

Findings fixed:

- Harvey the 3rd / Heisenberg + Sagan found P2: the HTTP README and Elastik
  skill reference showed `id: 42` / `id: 43`, while `listen.rs` emits
  `change.cursor.to_string()` and `SubscriptionCursor` renders as
  `<32 lowercase hex epoch>:<decimal event id>`. The examples now use that
  opaque shape.
- Harvey found P3: `.env.example` pointed readers at a nonexistent trace
  section in the README. The trace comment now stops at the implemented
  startup/frozen-lifetime behaviour.
- Harvey found P3: the 22r94 ledger's changed-file sentence omitted this
  ledger file. The wording now distinguishes production-facing docs from the
  durable review artifact.

Validation:

- `git status --short --branch`
- `git diff --name-status`
- `git diff --stat`
- `git diff --cached --name-status`
- `git diff --check`
- Targeted residue scans over production-facing docs found no stale decimal SSE
  IDs or stale trace-section pointer. The ledger intentionally retains Harvey's
  historical finding text while narrowing the corrected 22r94 changed-file
  wording.
- `python tools\panic_discipline_scan.py core bin ffi`
- `python tools\header_policy_scan.py --offline`

## 22r98: Generation mismatch wins before absent-row lookup

- Branch: `stack/22r98-generation-mismatch-absent-seq-proof`
- Base: `stack/22r97-listen-cursor-doc-parity`
- Scope: closes Arendt the 3rd's P3 Counterexample I test gap. The resolver and
  HTTP adapter already returned generation mismatch before row lookup; this
  layer adds explicit evidence for the edge where the requested generation is
  wrong and the requested sequence is absent.
- Production diff: 0 lines. Only existing `#[cfg(test)]` modules changed in
  `core/src/audit/timeline_dereference.rs` and `bin/src/server/pipeline.rs`.

The core test now asks for the wrong generation with sequence `99`, while the
subject world has only sequence `1`, and still expects
`TimelineDereference::GenMismatch`. The HTTP pipeline test sends the same shape
over the wire and expects `409 Conflict` with
`timeline generation mismatch\n`, not `404 timeline row not found\n`.

Finding fixed:

- Arendt the 3rd / Popper + Precondition found P3: Counterexample I had
  existing-generation mismatch tests only for an existing sequence. The missing
  edge was wrong generation plus absent requested sequence.

Fresh review:

- Boole the 3rd / Popper + Precondition: clean P0-P3. Confirmed the new core
  and HTTP tests close Counterexample I's absent-sequence edge and do not change
  production behavior.
- Carver the 3rd / Bacon + QA-Enforcement initially found one process P2: this
  entry did not yet record the QA/enforcement reviewer or broader Rust
  readiness evidence. The code/test content was clean, test-only plus ledger,
  and single-concern.
- Euler the 3rd / Bacon + QA-Enforcement re-reviewed after this entry recorded
  the missing QA/enforcement reviewer and broader validation evidence. The
  re-review was clean P0-P3 and closed Carver's process P2.

Validation:

- `git status --short --branch`
- `git diff --name-status`
- `git diff --stat`
- `git diff --cached --name-status`
- `git diff --check`
- `cargo test --locked --manifest-path core\Cargo.toml coordinate_resolver_returns_generation_mismatch_after_chain_verification -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml pipeline_timeline_head_errors_have_no_body -- --nocapture`
- `cargo test --locked --manifest-path core\Cargo.toml timeline -- --nocapture`
- `cargo test --locked --manifest-path bin\Cargo.toml timeline -- --nocapture`
- `cargo test --locked --manifest-path core\Cargo.toml`
- `cargo test --locked --manifest-path bin\Cargo.toml`
- `cargo fmt --manifest-path core\Cargo.toml -- --check`
- `cargo fmt --manifest-path bin\Cargo.toml -- --check`
- `cargo clippy --locked --manifest-path core\Cargo.toml --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks -D clippy::unwrap_used -D clippy::expect_used`
- `cargo clippy --locked --manifest-path bin\Cargo.toml --all-targets -- -D warnings -D unsafe_code -D clippy::unwrap_used -D clippy::expect_used`
- `python tools\panic_discipline_scan.py core bin ffi`
- `python tools\header_policy_scan.py --offline`

## 22r100: Timeline README metadata status wording

- Branch: `stack/22r100-timeline-readme-metadata-status`
- Base: `stack/22r99-ledger-qa-closure-wording`
- Scope: closes Kierkegaard the 3rd's P3 docs overclaim. The HTTP README status
  table no longer says invalid stored metadata is a `400` timeline query
  failure. It now states the implemented behaviour: persisted metadata is
  filtered before historical response headers are emitted, and invalid or
  denied stored metadata does not become a timeline parse failure.
- Production diff: 0 Rust lines. Documentation and ledger only.

Finding fixed:

- Kierkegaard the 3rd / Popper + Precondition found P3: README line 115 grouped
  "invalid stored metadata" with `400` timeline query failures, but
  `timeline_body_response` renders successful historical bodies and
  `apply_meta_headers` filters denied or invalid persisted metadata instead of
  returning `400`.

Validation:

- `git diff --check`
- `python tools\panic_discipline_scan.py core bin ffi`
- `python tools\header_policy_scan.py --offline`

## 22r101: Ledger placement for 22r100

- Branch: `stack/22r101-ledger-placement-fix`
- Base: `stack/22r100-timeline-readme-metadata-status`
- Scope: closes Laplace the 3rd's P3 ledger-structure finding. The 22r100 entry
  was first inserted inside the 22r89 validation list, which mis-attributed a
  pre-existing `git diff --check` bullet. This layer moves the 22r100 entry to
  the end of the ledger and leaves the older validation list intact.
- Production diff: 0 Rust lines. Ledger only.

Finding fixed:

- Laplace the 3rd / Sagan + Docs Drift found P3: the 22r100 ledger block split a
  prior validation list, so the ledger structure overclaimed which command
  belonged to which layer.

Validation:

- `git diff --check`
- `python tools\panic_discipline_scan.py core bin ffi`
- `python tools\header_policy_scan.py --offline`

## 22r102: Local completion audit

- Branch: `stack/22r102-local-completion-audit`
- Base: `stack/22r101-ledger-placement-fix`
- Scope: adds a local-only completion matrix for
  `PLAN-http-timeline-dereference.md` in
  `design_notes/http-timeline-dereference-completion-audit.md`. This does not
  claim remote PR or GitHub CI completion; it records the current local evidence
  for implementation order, endpoint checklist gates, SDK helper coverage,
  validation commands, and fresh review state.
- Production diff: 0 Rust lines. Design-note and ledger only.

Findings fixed:

- Popper the 3rd / Hypatia + QA-Enforcement found P1: the first 22r102 draft
  did not durably record fresh review evidence for the current 22r102 diff, and
  its review-state paragraph pointed only at the prior 22r99..22r101 review
  range.
- Popper also found P3: the audit said local evidence "replaces" GitHub
  PR/check evidence. The wording now says it records local evidence available
  while GitHub PR/check evidence is unavailable.
- Ohm the 3rd / Sagan + Bacon independently confirmed the same review-state
  overclaim as P2 after the wording repair: the audit now points to this ledger
  section for 22r102 review evidence instead of claiming a completed clearing
  round before it is recorded.
- Erdos the 3rd / Popper + Precondition: clean P0-P3 on PLAN Counterexamples
  A-U and endpoint checklist coverage. Confirmed the completion audit's coverage
  claims are backed by current code and tests.
- Parfit the 3rd / Noether + QA-Enforcement: final clearing review clean P0-P3.
  Confirmed the diff is exactly two docs artifacts, the audit file is trackable,
  remote PR/CI are not overclaimed, first-round findings/fixes are recorded, and
  AGENTS plus PLAN section 9 review-ledger requirements are satisfied for this
  local-only layer.

Validation:

- `python sdk\tests\test_tools.py`
- `python -m py_compile sdk\src\elastik\sdk.py sdk\src\elastik\__init__.py sdk\src\elastik\testing.py sdk\src\elastik\reactor.py`
- `python sdk\tests\e2e_blackbox.py`
- `git diff --check`
- `python tools\panic_discipline_scan.py core bin ffi`
- `python tools\header_policy_scan.py --offline`

## 22r103: Local panic discipline gate

- Branch: `stack/22r103-local-panic-discipline-gate`
- Base: `stack/22r102-local-completion-audit`
- Scope: wires the existing panic-discipline scanner into the local pre-push
  gate, so local validation enforces the same documented unwrap/expect
  suppressor discipline that CI already runs.
- Production diff: 0 Rust lines. Local tooling and ledger only.

Finding fixed:

- Hume the 3rd / Mencius + QA-Enforcement found P3: CI runs
  `tools/panic_discipline_scan.py core bin ffi`, but `scripts/pre-push.ps1`
  did not. With GitHub unavailable, local gates must catch undocumented
  production unwrap/expect suppressors before push.

Review:

- Pauli the 3rd / Popper + Bacon found no P0-P2 counterexample where production
  naked `.unwrap()` or `.expect()` can pass the local CI-equivalent gates.
  Pauli noted the remaining semantic review duty: a documented suppressor can
  still be a bad suppressor if it is used around validation, IO, config,
  storage, FFI, auth, audit, or user-controlled input. That is reviewer-owned,
  not syntax-owned.

Validation:

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
- `python tools\header_policy_scan.py --offline`
- `python sdk\tests\test_tools.py`
- `python -m py_compile sdk\src\elastik\sdk.py sdk\src\elastik\__init__.py sdk\src\elastik\testing.py sdk\src\elastik\reactor.py`
- `python sdk\tests\e2e_blackbox.py`
- `python tools\panic_discipline_scan.py core bin ffi`
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\pre-push.ps1`
- `git diff --check`
