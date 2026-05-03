# Security Policy

## Supported Versions

Elastik is a small project with one supported security line: the latest released
version.

| Version | Supported |
| ------- | --------- |
| latest release | Yes |
| older releases | No |

If you are running an older version, please upgrade before reporting unless the
issue also reproduces on the latest release.

## Reporting a Vulnerability

Please report security issues privately through GitHub private vulnerability
reporting or GitHub Security Advisories for this repository.

Do not open a public issue for a vulnerability.

Please include:

- The affected version and platform.
- Whether the issue affects `elastik-core`, the Python SDK, the JavaScript SDK,
  or release packaging.
- A minimal reproduction, if possible.
- Whether credentials, tokens, or persisted data may have been exposed.

We will triage reports as soon as practical and respond with one of:

- Accepted: we believe this is a security issue and will prepare a fix or
  advisory.
- Needs information: we need a smaller reproduction or more environment detail.
- Declined: the report is outside Elastik's security boundary.

## Security Boundary

Elastik core stores and serves bytes over explicit protocol surfaces. It does
not provide browser sandboxing, HTML sanitization, TLS termination, schema
validation, application authorization rules, or deployment policy.

These are expected to live in the client, SDK, application, browser, or edge
proxy. For example, HTML resources should carry their own browser policy
(`Content-Security-Policy`, frame policy, CORS policy, and related response
headers) when that policy matters.

Valid security reports for Elastik usually involve the core, SDKs, release
artifacts, token enforcement, audit-chain integrity, persisted safe-header
semantics, or accidental credential exposure.
