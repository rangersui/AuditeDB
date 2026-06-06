# Elastik v7.2.0 — Header Persist Policy Flipped to Default-Deny for Custom

A correctness and supply-chain release. The HTTP grammar — six verbs, one
HTTP disk — is byte-identical to v7.1.0. What's new is a **four-layer
header persist policy** that flips the default for custom headers from
allow to deny, removes a class of inbound-pollutant leaks, and lets
operators carry their own allow/deny rules through `ELASTIK_PERSIST_HEADERS`
and `ELASTIK_DENY_HEADERS`.

**Breaking change.** Custom representation headers (`x-author`, `x-tag`,
arbitrary `x-meta-*`, anything not on the L2 default-allow list) are no
longer persisted by default. If your deployment relies on them, see the
migration paragraph below.

## Highlights

- **Four-layer policy** at `core/src/http_semantics.rs:147-162`.
  Order of precedence, top to bottom:
  1. **L1 hardcoded deny** — credentials (`Authorization`,
     `Cookie`, `Set-Cookie`), hop-by-hop and transport
     (`Connection`, `Transfer-Encoding`, `TE`, ...), request
     controls (`Accept-*`, `If-*`, `Range`, `User-Agent`, ...),
     server/transport advertisements (`Alt-Svc`, `Server-Timing`,
     `Retry-After`, ...), core-owned response headers
     (`Content-Type`, `Content-Length`, `ETag`, `Vary`, `Link`,
     `Location`, ...), proxy trail and IP-leak (`Forwarded`,
     `Via`, `X-Forwarded-*`, `X-Real-IP`, `True-Client-IP`,
     `Client-IP`), distributed tracing (`traceparent`,
     `tracestate`, `baggage`, `b3`, `x-b3-*`), cloud runtime
     injections (`x-amzn-*`, `cf-*`), HTTP/2+3 pseudo-headers
     (`:`-prefixed), transport version markers (`http2-settings`,
     `http3-settings`), HTTP/1.0 fossils (`pragma`), CORS request
     prefixes (`access-control-request-*`), security request
     prefixes (`sec-*`), and feature negotiation (`want-*`).
     Never persisted, never overridable.
  2. **L1.5 `ELASTIK_DENY_HEADERS`** — operator deny rules.
     Subtracts from L2 and L3 below. Format: comma-separated,
     exact match or trailing-`*` prefix, lowercase,
     whitespace-tolerant.
  3. **L2 hardcoded default allow** — 21 standard representation
     headers: 4 body representation (`content-disposition`,
     `content-encoding`, `content-language`, `content-md5`),
     2 caching (`cache-control`, `expires`), 6 CORS-response
     (`access-control-allow-origin`/`-methods`/`-headers`/
     `-credentials`, `access-control-expose-headers`,
     `access-control-max-age`), 7 browser security policies
     (`content-security-policy`, `content-security-policy-report-only`,
     `x-frame-options`, `permissions-policy`,
     `cross-origin-resource-policy`, `cross-origin-opener-policy`,
     `cross-origin-embedder-policy`), 2 indexing/referrer policies
     (`referrer-policy`, `x-robots-tag`).
  4. **L3 `ELASTIK_PERSIST_HEADERS`** — operator allow rules. Same
     format as L1.5. The opt-in for any custom header.

  Notation in the L1 enumeration above: `cf-*`, `x-amzn-*`, `x-b3-*`,
  `sec-*`, `want-*`, `access-control-request-*`, and `:`-prefixed are
  real prefix matches (any name starting with the prefix is denied).
  Names without `*` are exact matches. Shorthand groups like
  `Accept-*`, `If-*`, and `X-Forwarded-*` denote several enumerated
  exact matches, not a prefix — see `core/src/http_semantics.rs:406+`
  for the canonical list.
- **`HeaderAllowlist` matcher** (`core/src/http_semantics.rs`,
  mirrored in `sdk/src/elastik/sdk.py`). Single type used dual-purpose
  for both allow and deny lists. Exact-match + trailing-`*` prefix,
  lowercase normalization, RFC-7230 case-insensitive per HTTP grammar.
- **`Last-Modified` intentionally omitted** from L2 (see comment at
  `core/src/http_semantics.rs:88-93`). ETag is canonical;
  `Last-Modified` would invite `If-Modified-Since` to bypass the
  HMAC-chained `If-None-Match` flow. The default is the contract; not
  a recommended opt-in.
- **`Content-Type` and `ETag` round-trip outside L2.** `Content-Type`
  is stored as the body's media type (`Stage.content_type`); `ETag`
  is emitted by the server, derived from the audit chain. They aren't
  in the 21-entry L2 list because they have dedicated channels — and
  they're in L1 to prevent operator-supplied values from overriding
  the canonical ones.
- **Write-time-only filtering for L1.5 / L2 / L3.** The allow/deny
  lists run at PUT time against incoming request headers. Headers
  already stored from earlier versions are not re-filtered on read —
  re-PUT the affected representation under the new policy if you
  need to scrub. **L1 hard deny does still re-apply on read** as
  defense-in-depth (`core/src/http_semantics.rs:179-191`), so a
  write-time policy bug or a corrupted database row can never
  replay credentials or tracing context.
- **`FakeElastik` mirrors core verbatim.** Imports `HeaderAllowlist`
  and `_should_persist_response_header` from `elastik.sdk`. Defaults
  to `HeaderAllowlist.from_env()`, so SDK unit tests behave the same
  way the real core does under the same env. Test fixtures can
  override via `persist_allow=` / `persist_deny=` kwargs.
- **`tools/header_policy_scan.py`** — drift radar for the **L1 deny**
  surface. Parses both `core/src/http_semantics.rs` and
  `sdk/src/elastik/sdk.py`, asserts Rust ↔ Python parity for
  exact-match and prefix denies, fails CI when IANA / MDN registries
  surface new names not on the reviewed baseline. (L2 default-allow
  parity is not yet checked by the scanner — the L2 list is small
  enough that a code-review diff catches drift; if that changes,
  the scanner is the place to add it.)

User-facing API: unchanged. The flip is in the *body* of HTTP
responses (which headers round-trip), not in the request/response
shape.

## The trigger

The denylist 追着加 in v7.1.x was unsustainable. Every new CDN, every
new APM vendor, every new tracing standard meant another header to
deny. The review thread on PR #124 made it explicit: the surface is
unbounded, and the deny list will keep growing forever unless the
default flips.

PR #125 flips it. Standard representation headers are still allowed by
default (the 21-entry L2 list); custom headers are denied by default;
operators carry their own opt-in/opt-out via two env vars. The
denylist remains as L1 (hardcoded, non-overridable) and L1.5 (operator
overrides).

## Migration

**Breaking — custom representation headers are now opt-in.**

If your deployment relies on custom headers like `x-author`, `x-tag`,
or arbitrary `x-meta-*`:

```bash
ELASTIK_PERSIST_HEADERS=x-meta-*,x-author
```

Standard representation continues to round-trip without
configuration: `Content-Type` rides the body's media-type slot,
`ETag` is emitted by the audit chain, and the 21-entry L2 set covers
the rest (body representation, caching directives, CORS-response
family, browser security policies, indexing/referrer policies — see
§Highlights for the full enumeration).

To drop a default L2 entry — for example, suppress `cache-control`
on all responses:

```bash
ELASTIK_DENY_HEADERS=cache-control
```

Layer order: L1 hardcoded deny → L1.5 `ELASTIK_DENY_HEADERS` →
L2 hardcoded allow → L3 `ELASTIK_PERSIST_HEADERS`. Deny beats allow
at every layer. Both env knobs accept comma-separated names with
exact match or trailing-`*` prefix.

The flip applies at write time. Existing stored representations keep
their old headers until they are re-PUT under the new policy.

## Compatibility

| Surface | v7.1.0 → v7.2.0 |
|---|---|
| HTTP grammar | identical |
| CoAP grammar | identical |
| Auth tiers | identical |
| Audit chain | identical (same HMAC, same canonical headers, same chain shape; v7.1 worlds remain readable; no migrator) |
| Env vars | existing unchanged; two new optional: `ELASTIK_PERSIST_HEADERS` (L3 allow), `ELASTIK_DENY_HEADERS` (L1.5 deny) |
| `/proc/*` | unchanged |
| Default response headers | **breaking — custom headers (`x-meta-*`, `x-author`, etc.) no longer round-trip without `ELASTIK_PERSIST_HEADERS`**; standard 21-header L2 set unchanged; `Content-Type` and `ETag` continue to ride their dedicated channels |
| SDKs | Python (`elastik`) and JS (`@elastikjs/client`) bumped to 7.2.0 to match; `FakeElastik` now reads the same env by default |

There is no migration step beyond setting `ELASTIK_PERSIST_HEADERS`
if you rely on custom headers. Stop the old binary, set the env,
start the new binary. Existing audit chains continue verifying;
existing representations keep the headers they already have.

## Internal architecture

The v7.2 cascade in PR order:

| PR | Branch | What it shipped |
|---|---|---|
| [#124](https://github.com/rangersui/elastik/pull/124) | `fix/header-denylist-tracing-cloud` | L1 hard-deny extended: 4 new prefixes (`:`, `x-b3-`, `x-amzn-`, `cf-`) + 9 new exact-match names (`x-real-ip`, `true-client-ip`, `client-ip`, `traceparent`, `tracestate`, `baggage`, `b3`, `http3-settings`, `pragma`); scanner regex updated for `:`-pseudo-header form |
| [#125](https://github.com/rangersui/elastik/pull/125) | `feat/header-allowlist-flip` | Flip default for custom headers from allow to deny; introduce `HeaderAllowlist` matcher + four-layer policy (L1 / L1.5 / L2 / L3); `ELASTIK_PERSIST_HEADERS` + `ELASTIK_DENY_HEADERS` env vars; `FakeElastik` reads env by default; PR-#124 prefixes promoted into the structured `should_persist_for_storage` decision |

File-line state at v7.2.0 (master line counts, prod-only where the
file has a top-level `#[cfg(test)] mod tests`):

```text
core/src/http_semantics.rs   595 prod    (was 366 at v7.1.0; +229 for HeaderAllowlist + four-layer logic)
core/src/state.rs            486         (was 468; +18 for two Arc<HeaderAllowlist> fields)
core/src/main.rs             347 prod    (was 345; +2 wiring for two new Core fields; the +245 total-line delta is in mod tests — five new persist-policy tests + ctor fixture wiring)
core/src/config.rs           101         (was 78; +23 for two header_*_from_env helpers)
sdk/src/elastik/sdk.py       1971        (was 1816; +155 for HeaderAllowlist + _DEFAULT_PERSIST_HEADERS + four-layer _should_persist_response_header)
sdk/src/elastik/testing.py   205         (was 167; +38 for HeaderAllowlist wiring + opt-in default)
tools/header_policy_scan.py  668         (was 610; +58 for backward-compat parser fallback + `:` pseudo-header regex)
```

Two AI reviewers (Codex P1/P2/P3 + a separate design reviewer) raised
12 findings across two review rounds on PR #125, plus 7 documentation
nits in the doc-only sweep. All resolved before merge. PR #125 landed
with all CI matrix runs green: rustfmt + clippy + `cargo test` on
Ubuntu (rust stable), SDK blackbox on Linux / macOS / Windows
(Python 3.12), header-policy drift radar on Ubuntu (Python 3.12),
and dry-run wheel builds on Linux / macOS / Windows.

## Roadmap

- **Known issue: spurious 404 from at-cap transient slot drain.**
  Codex P1 on PR #125 raised a real semantic issue, separable from
  the header policy itself: `SlotState::Tombstone` is currently
  overloaded for two unrelated intents — DELETE (world is gone,
  return 404) and at-cap transient-slot cleanup (world still exists,
  slot is being drained for memory pressure). The cleanup path can
  race with concurrent readers and surface a 404 for a world that's
  still on disk. Fix: split `SlotState::Tombstone` (DELETE → 404 is
  correct) from `SlotState::DrainingTransient` (cap cleanup → reader
  retries instead of 404'ing). Targeted as the next merge after
  v7.2.0 ships.
- **Still queued from v7.1 roadmap:** merge `execute_get` +
  `execute_head` → `execute_read(BodyMode::{Full, HeadersOnly})`,
  then merge `execute_put` + `execute_post` →
  `execute_write(WriteMode::{Replace, Append})`.

## Install

```bash
# Rust
cargo install elastik-core

# Python
pip install --upgrade elastik

# JavaScript
npm install @elastikjs/client@7.2.0
```

## Thanks

Solo-maintained by Ranger Chen with AI co-authoring. Two review
rounds on PR #125 across two AI reviewers, plus a doc-only sweep,
before the default-deny flip landed. The principle of the release:
**a deny list that grows monotonically is a design that hasn't found
its center yet.** Flipping the default surface back to a small,
principled L2 set, and giving operators two parallel env knobs to
carry the rest, moved the policy from "track the world's CDN vendors
forever" to "ship a fixed surface and let operators carry the
deltas."
