# Contributing

Elastik is a small HTTP byte engine. The contribution model is intentionally
small too: one coherent change, one pull request.

## Before You Start

- Read `README.md` for the user-facing model.
- Read `SECURITY.md` before reporting anything security-sensitive.
- Read `AGENTS.md` before changing Rust core architecture. It contains the
  review contract: small diffs, file-size budgets, drain-before-remove, and
  type-system safety rules.

## Change Shape

- One coherent change should become one pull request. Fixup commits during
  review are fine; pull requests are squashed on merge.
- Keep production-code diffs under 500 lines unless the maintainer explicitly
  signs off.
- Keep Rust production files under 500 lines unless there is an explicit
  sign-off.
- Prefer mechanical extraction PRs before behavior changes.
- If a change is stacked, keep the cascade shallow and merge from the bottom.

## Rust Core Checklist

For core changes, check the same surfaces reviewers check:

- Blocking: durable scans and SQLite-heavy work must not park Tokio workers.
- Explicit errors: do not swallow storage errors into defaults or empty data.
- Auth: new routes must use the right token gate.
- Notify: externally visible writes must notify listeners.
- Audit: durable mutations must be represented in the HMAC audit chain.
- Headers: persisted response headers must pass the denylist.
- Resources: new loops, queues, caches, and listeners need bounds.
- Storage: expected storage exhaustion maps to 507, not panic or vague 500.
- Docs and tests: new public behavior needs a test and public documentation.

The pull request template includes this same checklist so authors can fill it
inline when opening a PR.

## Local Checks

Run the narrowest checks that cover your change. For Rust core work, the usual
gate is:

```
cargo fmt --manifest-path core/Cargo.toml -- --check
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path core/Cargo.toml
python sdk/tests/test_tools.py
node sdk-js/test.mjs
python tools/header_policy_scan.py --self-test
python tools/header_policy_scan.py --offline
git diff --check
```

If a check is not relevant or cannot run locally, say so in the PR.

## Issues

Use the [bug report](.github/ISSUE_TEMPLATE/bug_report.yml) or
[feature request](.github/ISSUE_TEMPLATE/feature_request.yml) template. A
good issue includes:

- What you expected.
- What happened.
- The command or request that reproduces it.
- The version, platform, and relevant environment variables.
- Whether the issue affects Rust core, Python SDK, JavaScript SDK, packaging,
  docs, or CI.

Do not file public security issues. Use `SECURITY.md`.

## Releases

A version bump touches `core/Cargo.toml`, `sdk/pyproject.toml`, and every
`sdk-js/**/package.json` (the main package plus per-platform binary packages)
in one commit. Tag `vX.Y.Z` only after every manifest agrees. Then commit
`RELEASE-NOTES-vX.Y.Z.md` and create the GitHub release.

## Pull Requests

Good PRs are small enough to review in one pass. Include:

- The intent of the change.
- The user-visible behavior, if any.
- The verification commands you ran.
- Known follow-ups that are intentionally not part of this PR.

Elastik values boring correctness. If a change can be made physically safer by
types instead of reviewer discipline, prefer the type-system shape.
