# Security Policy

## Supported Versions

Only the latest released version is supported for security fixes.

| Version | Supported |
| ------- | --------- |
| latest release | Yes |
| older releases | No |

Please upgrade first if the issue does not reproduce on the latest release.

## Reporting a Vulnerability

Report security issues privately through GitHub private vulnerability reporting
or GitHub Security Advisories.

Do not open a public issue for a vulnerability.

Please include the affected version, platform, component (`elastik-core`,
Python SDK, JavaScript SDK, or packaging), and a small reproduction if possible.

## Security Boundary

The Elastik L5 Engine is a byte store.

The engine accepts bytes, stores bytes, returns bytes, enforces token tiers,
signs durable writes into an HMAC audit chain, and replays safe persisted
response metadata. That is the engine's security boundary.

Documentation tokens such as `read-token`, `write-token`, `approve-token`,
`admin-token`, and `change-me` are examples only. Audit-chain HMAC keys must be
at least 32 bytes and must not be empty or all whitespace. The engine does not
ship with built-in defaults. If copied strings protect a shared deployment, that
is a deployment configuration problem, not a hidden default credential.

Good security reports usually involve one of these:

- Token enforcement can be bypassed.
- The HMAC audit chain can be forged, skipped, or verified incorrectly.
- Persisted response headers can inject protocol state, credentials, or unsafe
  bytes.
- Tokens or other credentials are exposed by logs, SDKs, packages, release
  artifacts, or default configuration.
- A published package ships the wrong binary or a binary that does not match
  the source/release.

Usually outside the Elastik Engine's security boundary:

- HTML sanitization, XSS filtering, CSP authoring, iframe policy, or browser
  sandboxing.
- TLS termination, public edge routing, CDN policy, or firewall policy.
- Application schemas, business rules, per-user authorization, or validation.
- Bugs in user plugins, user applications, or content stored via the engine.

If you store an HTML app, that HTML app owns its browser policy. If you expose
an AuditeDB deployment to a network, that deployment owns its edge policy. The
Elastik L5 Engine remains a small storage engine: bytes in, bytes out, with
token gates and an audit chain.
On the optional CoAP/UDP binary surface, auth tokens travel as plaintext
datagram metadata unless you wrap that edge in CoAPS/DTLS or another trusted
tunnel.
