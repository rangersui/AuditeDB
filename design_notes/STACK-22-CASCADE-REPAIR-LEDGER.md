# Stack 22 Cascade Repair Ledger

This ledger exists because `stack/22r19-audit-verify-world-target` was a hidden
base for upper Stack 22 PRs. The repair exposes that base as PR #359 instead of
letting later PRs depend on an untracked branch.

## Drain Boundary

- #330 through #335 have been merged into `master` with merge commits.
- `master` has the same tree as the former `stack/21-cas-schema` base.
- #359 is based on `master` and keeps `stack/22r19-audit-verify-world-target`
  as the first visible Stack 22 layer.
- #336 through #357 remain draft and depend on the #359 head branch chain.

## Exception Scope

This is a stack-topology repair exception, not permission to add unrelated
feature scope. The exception allows a larger-than-normal PR only because this
branch already existed and already sat under reviewed upper-stack work.

The exception does not waive:

- type-seal requirements for internal APIs;
- no-rebase/no-squash stack handling;
- subagent QA before advancing;
- local validation;
- keeping dependent stack branches alive while PRs still use them as bases.

## Current Local Gates

Run on `stack/22r19-audit-verify-world-target` after retargeting #359 to
`master`:

- `cargo fmt --manifest-path core/Cargo.toml -- --check`
- `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path core/Cargo.toml`
- `cargo fmt --manifest-path bin/Cargo.toml -- --check`
- `cargo clippy --manifest-path bin/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path bin/Cargo.toml`
- `git diff --check origin/master..origin/stack/22r19-audit-verify-world-target`

GitHub CI must still be treated as authoritative for remote checks when it
finishes; queued checks are not green checks.
