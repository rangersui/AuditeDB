---
name: elastik
description: "Deploy and use Elastik (Audi-ted L5 storage engine), shipped as a Rust library + binary on SQLite. Use this skill whenever the user mentions elastik, wants to start a local or network elastik instance, configure keys/tokens/data paths/header policy, inspect /proc/* introspection endpoints, PUT/GET/HEAD/POST/DELETE worlds or LISTEN to /listen/* SSE streams with curl, publish static HTML worlds, use ETags/CAS/audit chains, route by namespace (home/etc/lib/boot/usr/var durable + tmp/dev/sys transient + proc generated), embed the protocol-neutral `Engine` library directly in a Rust project, or evaluate whether an HTTP subsystem should reuse Elastik instead of reinventing health/metrics/version/auth/audit/static serving."
---

# Elastik

**Audi-ted L5 storage engine.** Bytes at paths + versions + HMAC audit chain
+ four-tier auth + change subscriptions. Five verbs (read · replace · append ·
delete · subscribe), one SQLite store.

Two ways to use it:

- **Binary** (`elastik-core`): HTTP + CoAP server with `curl` as the control
  surface. This skill covers this mode.
- **Library** (`elastik_core` crate, `unstable-engine` feature): embed the
  protocol-neutral `Engine` directly in a Rust process; bring your own wire
  shape. In minimal library-only builds it has no HTTP, no CoAP, no env vars,
  no sockets — see the crate-level rustdoc and `core/src/engine.rs` for the
  public surface.

Elastik (the binary) is a flat HTTP key-value store with an introspection
plane. The key prefix is policy.

```text
home/ etc/ lib/ boot/ usr/ var/   ->  durable SQLite-backed values
tmp/ dev/ sys/                    ->  transient memory-backed values
proc/                             ->  generated introspection
```

Worlds are not files. A world is one HTTP key-value entry: a canonical key,
body bytes, HTTP metadata, and an ETag/version identity. Slashes in the key
are naming convention, not directory structure.

The user-facing operation set:

```text
GET     read body
HEAD    read metadata
PUT     replace world
POST    append (where supported)
DELETE  remove world
LISTEN  subscribe to events  (wire = GET /listen/<pattern>, SSE)
```

Disk contract: paths are authority boundaries; status codes must tell the
truth; durable mutation verifies before write; auth, audit, proc, and static
serving are shared primitives, not adapter-local reinventions.

Curl is the portable control surface. The browser is the HTML client. ETags
are version clocks. `/proc/*` is the status surface.

## First moves

1. If no Elastik instance is running, deploy one first. Startup verifies all
   durable audit chains before the process listens; see `references/deployment.md`
   if boot fails with a chain-broken error.
2. Set `ELASTIK_BASE`, usually `http://127.0.0.1:3105`.
3. Probe with `curl -i "$ELASTIK_BASE/proc/version"`. No read token needed.
4. The bare root `GET /` returns a hint, e.g. `elastik-core <version> (rust)\ntry: curl /proc/worlds\n`.
5. Use HTTP primitives directly: method, path, headers, body, status.
6. Do not invent JSON envelopes for core world operations.
7. When serving UI, PUT HTML/CSS/JS as worlds.

Curl cookbook:

- `scripts/curl-cases.sh`: runnable bash examples for probe, PUT, HEAD, GET,
  Range, CAS, audit verify, and listen.
- `scripts/curl-cases.ps1`: PowerShell version for Windows users without a
  working bash.

## Canonical key

HTTP wire path carries a leading slash; the core canonicalises it away.

```text
HTTP wire:        /home/a    /tmp/x
core canonical:   home/a     tmp/x
```

The canonical form is deliberately MQTT-like: no leading slash, slash-separated
hierarchy, no query string. A future MQTT adapter would use the topic as the
world path; it should not add a second naming grammar.

Unprefixed paths fall under the bare-path rule and are prepended with `home/`:

```text
/log/foo     ->  home/log/foo
/jobs/x      ->  home/jobs/x
/channel/me  ->  home/channel/me
```

Reserved roots (cannot be written as the world itself, only as a prefix):

```text
home  tmp  dev  sys  proc  etc  lib  boot  usr  var  var/log
```

The entire `proc/*` subtree is reserved for generated introspection and is not
user-writable.

## Reference routing

Load only the reference needed for the task:

- `references/deployment.md`: start Elastik, configure environment variables,
  bind address, tokens, data path, and safety checks.
- `references/flexible-deployment.md`: choose local, LAN, overlay, NAS-backed,
  or public-proxy deployment shapes without changing the HTTP world model.
- `references/http-worlds.md`: HTTP method semantics, namespace policy, path
  validation, header policy, ETag/CAS, `/proc/*`, `/listen/*` SSE, browser
  caching, and safe curl patterns.
- `references/navigation.md`: list, find, inspect, and search worlds with
  `/proc/worlds` and text filters; the `ls`/`find`/`tree` substitute.
- `references/projection-theorem.md`: the maximum-common-denominator rule for
  deciding when an HTTP subsystem should reuse Elastik instead of building a
  parallel control plane.
- `references/ui-worlds.md`: flat HTML world topology, no-JS fallbacks,
  HTML/CSS/JS splitting, and X-Meta-Summary conventions.
- `references/async-client.md`: synchronous storage vs asynchronous workflows;
  JavaScript and Python client patterns, SSE, polling, sidecar daemons.
- `references/e2e-auth.md`: end-to-end encryption with self-signed certificates;
  using Elastik as a zero-knowledge relay between client and sidecar.

## Deploy workflow

1. Pick a data directory with `ELASTIK_DATA`.
2. Generate `ELASTIK_KEY`.
3. Decide tokens: read, write, approve.
4. Start the Elastik process from source, installed binary, or Python package.
5. Verify `/proc/version`.
6. PUT a small test world and HEAD it.

## Use workflow

When publishing a file into Elastik:

1. Choose the world path explicitly. Use `home/` (or another reserved prefix)
   rather than relying on bare-path canonicalisation, so the key is obvious.
2. Pick an accurate `Content-Type`.
3. Add `Content-Language` for human-readable pages.
4. Add `X-Meta-Summary` only when custom metadata is enabled with
   `ELASTIK_PERSIST_HEADERS=x-meta-*`.
5. Use `Cache-Control: no-cache` for mutable HTML pages.
6. PUT with the write token from the environment, never hardcode tokens.
7. Verify with `HEAD` (or `curl -I`).

Token gates by namespace:

```text
write token    home/* tmp/* dev/* sys/* var/* (non-log)
approve token  etc/* lib/* boot/* usr/* var/log/* + all DELETE
read token     reads (when configured)
public         /proc/version, root /
```

The PUT below illustrates the typical write shape. `X-Meta-Summary` only
round-trips when the instance is started with `ELASTIK_PERSIST_HEADERS=x-meta-*`;
otherwise omit it or treat it as non-persistent write-time advice.

```bash
export ELASTIK_BASE="http://127.0.0.1:3105"
export ELASTIK_WORLD="/home/report.html"
export ELASTIK_WRITE_TOKEN="$TOKEN"

curl -i -X PUT "$ELASTIK_BASE$ELASTIK_WORLD" \
  -H "Authorization: Bearer $ELASTIK_WRITE_TOKEN" \
  -H "Content-Type: text/html; charset=utf-8" \
  -H "Content-Language: en" \
  -H "Cache-Control: no-cache" \
  -H "X-Meta-Summary: Report stored as an Elastik world." \
  --data-binary @report.html
```

## Status triage

```text
401  missing or wrong Authorization Bearer token
403  token tier too low for this namespace
404  world missing or wrong namespace
412  stale If-Match ETag (CAS lost a race); re-read then retry
413  body exceeds ELASTIK_MAX_WORLD_BYTES (64 MiB default)
416  Range starts past EOF
503  transient listen/SQLite busy condition; respect Retry-After when present
507  durable quota, memory quota, or filesystem full
```

## UI workflow

For browser pages:

1. Use a shallow topology. Split structure, presentation, and behaviour into
   sibling worlds.
2. Let `/proc/worlds` be the source of truth for navigation or discovery.
3. Use plain text fetches when possible. Do not require JSON unless the page is
   intentionally a JSON tool.
4. No-JS pages should use links, forms, tables, and `meta refresh`.
5. Do not ship mock data as if it were real. If an endpoint does not exist,
   render an empty state.

## Projection rule

If a user asks for a small HTTP gateway, PLC bridge, operator panel, static file
server, metrics route, health route, version route, audit route, or auth gate,
first ask whether it is just an Elastik world, proc surface, token gate, or
HTML page.

Elastik is the maximum common denominator. Domain adapters should supply domain
semantics; Elastik supplies the shared HTTP key-value store and control plane.

## Browser reality

Use curl for bare-metal HTTP checks. Browsers are policy stacks.

- Firefox usually preserves `If-None-Match` and shows normal 304 behaviour.
- Brave may strip `If-None-Match` to reduce ETag fingerprinting, producing 200
  instead of 304.
- Dillo does not execute JavaScript; use explicit no-JS pages instead of
  user-agent sniffing.
- Native `EventSource` cannot set the `Authorization` header; if reads require
  a token, use `fetch` + `ReadableStream` and parse SSE manually, or use the
  SDK's `listen()`.
