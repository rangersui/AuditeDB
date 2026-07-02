# Contributing

AuditeDB is the db that listens — powered by the Elastik L5 Engine, with HTTP,
CoAP, MQTT, SDK, and FFI adapters. The contribution model is intentionally
small: one coherent change, one pull request.

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

For Engine/library changes, check the same surfaces reviewers check:

- Blocking: durable scans and SQLite-heavy work must not park Tokio workers.
- Explicit errors: do not swallow storage errors into defaults or empty data.
- Auth: Engine calls must pass the right `AccessTier`; binary-adapter routes
  must use the right token gate.
- Notify: externally visible writes must notify listeners.
- Audit: durable mutations must be represented in the HMAC audit chain.
- Headers: persisted response headers must pass the denylist.
- Resources: new loops, queues, caches, and listeners need bounds.
- Storage: Engine errors must preserve `QuotaExceeded`, `TransientStorage`,
  and `InsufficientStorage`; binary adapters map those to protocol status or
  error codes.
- Docs and tests: new public behavior needs a test and public documentation.

The pull request template includes this same checklist so authors can fill it
inline when opening a PR.

## Local Checks

Run the narrowest checks that cover your change. For Engine-only work, the
usual gate is:

```
cargo fmt --manifest-path core/Cargo.toml -- --check
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path core/Cargo.toml
```

For binary-adapter work, add the binary crate checks:

```
cargo fmt --manifest-path bin/Cargo.toml -- --check
cargo clippy --manifest-path bin/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path bin/Cargo.toml
```

For SDK or header-policy work, also run the matching smoke checks:

```
python sdk/tests/test_tools.py
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
- Whether the issue affects Rust core, Python SDK, packaging,
  docs, or CI.

Do not file public security issues. Use `SECURITY.md`.

## Releases

A version bump touches `core/Cargo.toml`, `core/Cargo.lock`,
`bin/Cargo.toml`, `bin/Cargo.lock`, `ffi/Cargo.toml`, `ffi/Cargo.lock`,
`sdk/pyproject.toml` in one commit. Current-facing README and SDK docs must
agree with the version and product wording. Tag `vX.Y.Z` only after every
manifest agrees, `RELEASE-NOTES-vX.Y.Z.md` exists, and package dry-runs report
the same version.

The release workflow publishes the Rust crate, PyPI wheels, and GitHub Release
assets from the tag. It requires `CARGO_REGISTRY_TOKEN` for crates.io and PyPI
trusted publishing for the `publish to PyPI` job.

## Pull Requests

Good PRs are small enough to review in one pass. Include:

- The intent of the change.
- The user-visible behavior, if any.
- The verification commands you ran.
- Known follow-ups that are intentionally not part of this PR.

AuditeDB values boring correctness. If a change can be made physically safer by
types instead of reviewer discipline, prefer the type-system shape.
