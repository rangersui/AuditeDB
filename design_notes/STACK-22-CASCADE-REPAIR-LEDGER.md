# Stack 22 Cascade Repair Ledger

Status: current code QA clearing round passed; lower-stack drain remains a
separate process gate before upper stack layers should be marked ready.

This ledger records the repair of the forked Stack 22 cascade:
`stack/22r19-audit-verify-world-target` through
`stack/22r41-sdk-timeline-coordinate`.

## Why The Depth Exception Applies

AGENTS.md normally caps open cascade depth at 3-4 layers. This repair is being
tracked under the Stack repair exception. The durable-ledger condition is
cleared by the final QA round recorded below.

- the user explicitly authorised an unlimited repair cascade for this stack;
- the work repairs an already-existing fork caused by merging the lower stack
  while `22r19..22r41` still pointed at the old `stack/21` head;
- no new product feature scope was added during the repair;
- each semantic fix was placed at the lowest affected layer and propagated
  upward by merge cascade;
- this file records branches, validation, reviewer lenses, QA findings, and the
  fresh round that cleared P0-P2.

The exception waives stack depth only. It does not waive type seals,
validation, or Fleet Review Convergence.

## Branch Scope

The exact final `22r41` commit cannot be embedded in this file, because adding
this file changes that commit. Validators must use `git rev-parse HEAD` on
`stack/22r41-sdk-timeline-coordinate` for the exact artifact under review.

Repair heads before adding this ledger:

| Branch | Short head |
|---|---|
| `stack/22r19-audit-verify-world-target` | `c96f9cb22756` |
| `stack/22r20-timeline-address-extraction` | `6e106660c64f` |
| `stack/22r21-timeline-cas-deref` | `53b4bf4783dc` |
| `stack/22r22-timeline-read-cache` | `82be0b6ccedb` |
| `stack/22r23-public-timeline-contract` | `dff21472af26` |
| `stack/22r24-public-timeline-resolver` | `03d3c440555b` |
| `stack/22r25-subscription-types-module` | `119bfbd68d24` |
| `stack/22r26-world-read-ops-module` | `fe9a31306123` |
| `stack/22r27-change-event-timeline-address` | `58c1473d27b2` |
| `stack/22r28-delete-subject-proof` | `6377e73f000d` |
| `stack/22r29-sse-timeline-address` | `5a0eb7b08227` |
| `stack/22r30-timeline-address-wire-parse` | `612936bdb804` |
| `stack/22r31-http-timeline-deref-plan` | `e5823782f4e9` |
| `stack/22r32-timeline-deref-result-type` | `a51f322a31bc` |
| `stack/22r33-audit-header-split` | `dccc1a347255` |
| `stack/22r34-timeline-deref-audit-home` | `193f8828b184` |
| `stack/22r35-read-cache-ops-split` | `2c7d35fe6c07` |
| `stack/22r36-timeline-coordinate-resolver` | `8d446eb2a953` |
| `stack/22r37-pipeline-context-split` | `bf940636d558` |
| `stack/22r38-http-raw-query-plumbing` | `0884d7337999` |
| `stack/22r39-http-query-classifier` | `34c4268b1bfa` |
| `stack/22r40-http-timeline-query-wall` | `b35e49dd1ca9` |
| `stack/22r41-sdk-timeline-coordinate` | `050182ebce1f` |

## Fixes Applied

- `22r19`: merged current `stack/21-cas-schema` into the old `22r19` base and
  kept audit verification bound to `ValidatedWorldPath`.
- `22r19`: hardened `chain_head` against rowid-trusting rollback by keeping
  `COUNT(*)` semantics and explicit tamper-test assertions.
- `22r19`: added the AGENTS.md Stack repair exception so repo policy now has an
  explicit repair-exception path; the user authorisation remains part of the
  working conversation, not something this file alone can prove.
- `22r20`: preserved generation-aware event HMAC verification while exposing
  only read projections needed by HMAC sinks.
- `22r23`: kept public timeline read projections public without exposing public
  constructors for timeline addresses.
- `22r26`: preserved the `world_read_ops` module split and kept read APIs on
  `ValidatedWorldPath` / `ReadPermit`.
- `22r35`: preserved the read-cache module split while carrying forward
  `OpeningTransition` failure/drop as `Evicted`, not `Tombstone`.
- `22r36`: moved the timeline-coordinate read-cache proof fix to the layer that
  introduced coordinate dereference: `with_tracked_conn(data,
  coordinate.world(), ...)`, not `coordinate.world().as_str()`.
- `22r37..22r41`: propagated the repaired lower layers upward by merge cascade,
  without rebasing or squashing.

## Current Repair Addendum

Additional repair work after the first ledger pass:

- `22r19` hidden-base gap: opened PR #359 for
  `stack/22r19-audit-verify-world-target` against `stack/21-cas-schema`, so #336
  no longer rests on an untracked branch.
- `22r19` hidden-base CI fix: #359 failed bin tests because CAS retained-body
  accounting had changed the storage quota contract, but the matching bin test
  assertions lived only in `22r20+`. Moved that test-contract fix down to
  `22r19` (`bin: align quota tests with retained cas accounting`) and cascaded
  it upward.
- `22r21`: added `TimelineRead::NeverRetained`,
  `TimelineRead::AddressMismatch`, and `TimelineRead::Unproven` so absence and
  mismatch states keep their proof strength instead of collapsing into
  `Expired`, `Gone`, or generic corruption.
- `22r21`: changed missing CAS body handling: pre-retention rows become
  `NeverRetained`; rows at or after the retention floor become
  `Corrupt(MissingBodyForPresentRow)`. No missing CAS row is currently promoted
  to `Expired` without pruning proof.
- `22r21`: annotated the touched production `expect("hmac key")` with a local
  HMAC/AuditHmacKey invariant and `#[allow(clippy::expect_used)]`.
- `22r24` and `22r26`: changed missing local timeline storage/read-cache `None`
  to `TimelineRead::Unproven`, not `Gone`. Physical absence is not delete-ledger
  proof.
- `22r40`: moved ordinary `OPTIONS` ahead of raw-query extraction so
  `OPTIONS /home/a?timeline%ZZ=1` remains ordinary world-route `OPTIONS`.
- `22r19..22r41`: propagated the #359 bin-test contract fix upward by merge
  cascade, without rebasing or squashing. The cascade had no merge conflicts.
- `22r21..22r41`: propagated the new fixes upward by merge cascade, without
  rebasing or squashing.

## Validation Evidence

Local validation on the repaired stack tip before this ledger file:

- `cargo fmt --manifest-path core/Cargo.toml -- --check`
- `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path core/Cargo.toml`
- `git diff --check`
- `rg -n "^(<<<<<<<|=======|>>>>>>>)" AGENTS.md core/src design_notes`
- `rg -n "with_tracked_conn\([^\n]*as_str\(\)|read_world\([^&]|read_world\(.*as_str\(\)" core/src -g "*.rs"`; observed only the legitimate `read_world` call/definition matches, and no `with_tracked_conn(...as_str())` match.
- adjacent ancestry check from `22r19` through `22r41`
- `git merge-base --is-ancestor stack/21-cas-schema stack/22r19-audit-verify-world-target`
- `git merge-base --is-ancestor stack/22r36-timeline-coordinate-resolver stack/22r41-sdk-timeline-coordinate`

Observed core result: 193 passed, 2 ignored; doc tests 17 passed.

Current-head validation on `stack/22r41-sdk-timeline-coordinate` after the
addendum repairs:

- `git diff --check`
- `cargo fmt --manifest-path core/Cargo.toml -- --check`
- `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path core/Cargo.toml`
- `cargo fmt --manifest-path bin/Cargo.toml -- --check`
- `cargo clippy --manifest-path bin/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path bin/Cargo.toml`
- `python sdk/tests/test_tools.py`
- `python sdk/tests/e2e_blackbox.py`
- `cargo fmt --manifest-path ffi/Cargo.toml -- --check`
- `cargo clippy --manifest-path ffi/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path ffi/Cargo.toml`

Observed current-head results:

- core: 197 passed, 2 ignored; doc tests 17 passed.
- bin: 145 passed.
- sdk tools: pass.
- sdk e2e blackbox: 248 checks passed.
- ffi: 23 passed; doc tests 0 passed/0 failed.

Layer-specific validation after the #359 CI repair:

- `stack/22r19-audit-verify-world-target`: `cargo test --manifest-path
  bin/Cargo.toml` passed, 108 tests.
- `stack/22r19-audit-verify-world-target`: `cargo test --manifest-path
  core/Cargo.toml` passed, 157 tests plus 5 doc tests; 2 ignored.
- `stack/22r19-audit-verify-world-target`: core/bin fmt and clippy checks
  passed.
- `stack/22r41-sdk-timeline-coordinate`: core/bin/ffi fmt passed after the
  repair cascade.
- `stack/22r41-sdk-timeline-coordinate`: `cargo test --manifest-path
  bin/Cargo.toml` passed, 145 tests.
- `stack/22r41-sdk-timeline-coordinate`: `cargo test --manifest-path
  core/Cargo.toml` passed, 197 tests plus 17 doc tests; 2 ignored.

Reported additional subagent spot checks from the repair round, not re-run by
this ledger commit:

- core timeline tests: 40 passed;
- core read-cache tests: 24 passed;
- core engine-subscribe tests: 3 passed;
- core replay-after tests: 2 passed;
- bin timeline tests: 21 passed;
- bin listen tests: 4 passed.

## Review Ledger

Active skills checked:

- `stacked-pr`
- `delegation-doctrine`
- `assign-scientist-reviewers`
- `rust-type-seal-enforcement`
- `precondition-problem`
- `monte-carlo-review`
- `http-type-seal-review`
- `http-peer-protocol`

Round 1 reviewers:

- Herschel, lens Poincare/Bacon: stack topology QA. Result: no P0-P2 finding
  for assigned Round 1 slice.
- Kepler, lens Mencius/Noether: type-seal QA. Result: no P0-P2 finding for
  assigned Round 1 slice.
- Peirce, lens Popper/precondition/Bacon: timeline/precondition QA. Result:
  no P0-P2 finding for assigned Round 1 slice.
- Meitner, lens QA enforcement/Locke/Sagan: process QA. Result: not approved.

Round 1 confirmed findings:

- P1: Stack depth exception existed only in chat/PR wording, not in AGENTS.md.
  Fix: add the AGENTS.md Stack repair exception at the lowest repaired layer
  and cascade it upward.
- P1: PR ledgers described stale remote heads, not the exact repaired local
  artifact. Fix: add this durable stack repair ledger.
- P2: one PR body had incomplete Fleet Review ledger shape. Fix: this
  stack-wide ledger names lenses, skills, QA/enforcement, findings, fixes, and
  validation evidence for the repaired artifact.
- P3: platform-gated validation should be named when cited. Fix: do not claim
  Windows unlink semantics are proven by Unix-only file-permission coverage.

Final clearing round:

- Hegel, lens QA enforcement/Locke/Sagan: process QA. Result: AGENTS/process
  QA approve, no P0-P3 findings. Cleared the prior stack-depth, stale-ledger,
  and incomplete-ledger findings against the updated AGENTS.md and this repair
  ledger.
- Dalton, lens Sagan/Dirac: ledger wording QA. Result: ledger wording QA
  approve, no P0-P3 findings. Cleared the overclaim, user-authorisation,
  raw-string-sweep, Round 1 wording, and reported-evidence wording risks.

Current addendum review round:

- Aquinas the 2nd, lens Popper/precondition: APPROVE, no P0-P2 findings.
  Confirmed missing CAS bodies no longer become `Expired` without proof, missing
  subject storage becomes `Unproven`, and `OPTIONS` short-circuits before query
  decoding.
- Bacon the 2nd, lens Noether/Mencius: APPROVE, no P0-P2 findings. Confirmed
  type seals remain intact, `event_hmac` has the required invariant/allow, and
  HTTP/SDK boundaries do not treat raw coordinates as proof.
- Ramanujan the 2nd, lens Euclid/HTTP topology: APPROVE, no P0-P2 findings.
  Confirmed `OPTIONS` ignores timeline query shape while GET/HEAD still fail
  malformed timeline queries at the query boundary.
- Faraday the 2nd, QA/enforcement: code APPROVE, process not fully cleared.
  Confirmed no current code P0-P2 finding, but kept lower-stack process gates:
  #330-#335 should drain bottom-up, and #359 must be reviewed before #336+
  leaves draft/repair mode.

The current code repair is ready to push when the current `HEAD` static checks
remain clean. The upper implementation stack is not ready to mark non-draft
until the lower process gates above are cleared.
