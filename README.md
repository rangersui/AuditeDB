# Elastik V6 Engine

Six verbs, one HTTP disk.

curl is still the first-class client.

Elastik V6 is a small HTTP byte engine:

- `PUT` writes bytes.
- `GET` reads bytes.
- `HEAD` inspects metadata.
- `POST` appends bytes.
- `DELETE` removes bytes.
- `LISTEN` reacts to bytes through `/listen/*`.

`OPTIONS` is supported for HTTP introspection, but it is not a cylinder in the
engine. The core loop is the six-verb shape above.

No JSON envelope. No `?raw`. No private extension field. No plugin runtime in
the core. The core accepts HTTP requests and returns HTTP responses. Everything
else is SDK glue.

```text
HTTP request in  ->  path policy  ->  storage backend  ->  HTTP response out
```

If WebDAV, SMTP, MQTT, a browser, an AI agent, or a Python decorator can turn
its work into HTTP, Elastik does not need to know where it came from.

## The API Document Is The Path Convention

Elastik integration is usually a naming agreement, not a generated API schema.

```text
/home/order/{id}    input written by UI
/home/receipt/{id}  output written by worker
```

UI code and business logic do not need to call each other. They can meet at
named paths.

```js
// Browser/UI: submit an order.
await fetch("/home/order/123", {
  method: "PUT",
  body: JSON.stringify({ sku: "tea", qty: 2 }),
  headers: { "Content-Type": "application/json" },
});

// Browser/UI: wait for the result.
const receipts = new EventSource("/listen/home/receipt/*");
receipts.onmessage = (event) => console.log(event.data);
```

```python
# Business worker: process orders.
import elastik

@elastik.listen("/home/order/*")
def on_order(body, path, e):
    order_id = path.rsplit("/", 1)[-1]
    e.put_json(f"/home/receipt/{order_id}", {"status": "accepted"})

elastik.run()
```

Debugging is just HTTP:

```powershell
curl.exe http://127.0.0.1:3105/home/order/123
curl.exe http://127.0.0.1:3105/home/receipt/123
curl.exe -N http://127.0.0.1:3105/listen/*
```

There is no Swagger, GraphQL schema, protobuf file, controller method, or
shared server object in the middle. If the UI can `PUT` bytes and the worker
can `GET` or `@listen` the same path, they are integrated.

## Status

This repository is the Phoenix core rewrite. It intentionally breaks from the
older Python server:

- `/lib` is storage, not execution.
- browser UI is not core.
- AI shaping/routing is not core.
- protocol bridges are not core.
- extensions are SDK clients or separate HTTP endpoints.

The core is deliberately boring. That is the point.

## Quickstart

Start the Rust core:

```powershell
cd path/to/elastik/core
$env:ELASTIK_KEY = "dev-hmac-key"
$env:ELASTIK_READ_TOKEN = "read-token"
$env:ELASTIK_WRITE_TOKEN = "write-token"
cargo run
```

`dev-hmac-key`, `read-token`, `write-token`, and similar strings in this
README are placeholders for local demos. Elastik does not use them as built-in
defaults. For any shared or networked deployment, generate unique secrets
instead of copying the examples.

In another terminal:

```powershell
curl.exe -X PUT http://127.0.0.1:3105/home/hello `
  -H "Authorization: Bearer write-token" `
  -H "Content-Type: text/plain; charset=utf-8" `
  --data-binary "hello elastik"

curl.exe http://127.0.0.1:3105/home/hello -H "Authorization: Bearer read-token"
curl.exe -I http://127.0.0.1:3105/home/hello -H "Authorization: Bearer read-token"
curl.exe http://127.0.0.1:3105/proc/worlds -H "Authorization: Bearer read-token"
```

Expected shape:

```http
HTTP/1.1 201 Created
Location: /home/hello
ETag: "hmac-..."
```

Then:

```text
hello elastik
```

That is the whole primitive.

## Environment

The core reads configuration from environment variables:

```env
ELASTIK_HOST=127.0.0.1
ELASTIK_PORT=3105
ELASTIK_DATA=./data

# Optional SCoAP/UDP surface. Disabled unless ELASTIK_COAP_PORT is set.
# ELASTIK_COAP_HOST=127.0.0.1
# ELASTIK_COAP_PORT=5683

ELASTIK_KEY=change-me
ELASTIK_READ_TOKEN=
ELASTIK_WRITE_TOKEN=
ELASTIK_APPROVE_TOKEN=
```

`change-me` is a placeholder, not a safe value. `ELASTIK_KEY` is required and
signs the audit chain. A public, empty, reused, or copied example key makes the
audit chain meaningless.

Tokens are optional capability gates. Missing tokens do not stop the core from
starting; they disable the corresponding protected operations:

- no `ELASTIK_READ_TOKEN`: reads are public.
- no `ELASTIK_WRITE_TOKEN`: ordinary `PUT` and `POST` are disabled.
- no `ELASTIK_APPROVE_TOKEN`: `DELETE` and system writes are disabled.

Local-first default: public reads are fine on `127.0.0.1` because that is your
own machine reading its own disk. If you bind `ELASTIK_HOST` to a non-loopback
interface without `ELASTIK_READ_TOKEN`, the core prints a startup warning:
you have deliberately exposed public reads and should decide whether that is
the surface you want.

The SCoAP/UDP surface is opt-in. The core does not open UDP by default; set
`ELASTIK_COAP_PORT=5683` to enable the UDP-curl adapter. `ELASTIK_COAP_HOST`
defaults to `127.0.0.1` when CoAP is enabled.

Humans should not hand-type CoAP bytes. The Python SDK is the tiny UDP
translator:

```powershell
python -m elastik coap put 127.0.0.1 5683 home/sensor/temp "23.5" --token write-token
python -m elastik coap get 127.0.0.1 5683 home/sensor/temp --token read-token
```

Or keep the endpoint once in Python:

```python
c = elastik.CoapClient("127.0.0.1", 5683, token="write-token")
c.put("home/sensor/temp", "23.5").raise_for_status()
print(c.get("home/sensor/temp").payload)
```

SCoAP is intentionally small: `GET` and `PUT`, one UDP datagram, content formats
the core can map (`text/plain`, `application/octet-stream`, `application/json`,
`application/cbor`). Bodies near 1 KiB or above should use HTTP: the SDK
enforces a 1152-byte datagram limit and rejects oversize `PUT`s with
`ValueError` immediately. Arbitrary media types should also use HTTP.

This is not a full RFC 7252 CoAP stack. It is a CoAP-shaped UDP surface:
CoAP wire format, HTTP-shaped storage semantics, and elastik auth.

It keeps the parts with semantic zero distance from HTTP:

- CoAP v1 header
- method codes for `GET` and `PUT`
- `Uri-Path` as the path
- `Content-Format` as `Content-Type`
- payload marker
- token echo
- response codes

It intentionally does not implement CoAP politics:

- retransmission or dedup cache
- Observe
- Block-Wise transfer
- DTLS / OSCORE
- `.well-known/core`
- multicast discovery
- `Max-Age`
- strict critical-option handling

Elastik uses private option `65001` to carry the raw elastik auth token. That
is not encryption and not CoAPS; it is the UDP equivalent of
`Authorization: Bearer ...`. Need full CoAP behavior? Put a compliant CoAP
gateway at the edge. Need reliability or large bodies? Use HTTP.

`ELASTIK_DATA` is the universe selector. Point the same binary at another data
directory and it serves another Elastik universe. Local SSD/tempdir is best for
writes. Synced folders and network shares can be useful for distribution, but
SQLite-on-network-filesystem is a tradeoff you should make deliberately.

Run one writer process per `ELASTIK_DATA`. The core has a per-process write
lock that makes conditional writes atomic inside one server, but it is not a
distributed lock across multiple core processes pointed at the same directory.

Empty token variables are treated as unset.

Resource caps:

| Variable                           |       Default | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------------------------------- | ------------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ELASTIK_MAX_WORLD_BYTES`        |  `67108864` | Maximum stored size of one world after `PUT` or `POST`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `ELASTIK_MAX_STORAGE_BYTES`      |     unlimited | Optional durable storage quota across SQLite-backed world body bytes.                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `ELASTIK_MAX_MEMORY_BYTES`       | `268435456` | Maximum total bytes in memory-backed worlds (`/tmp`, `/dev`, `/sys`).                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `ELASTIK_MAX_LISTEN_CONNECTIONS` |      `1024` | Maximum concurrent `/listen/*` SSE connections.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `ELASTIK_LISTEN_REPLAY_MAX`      |      `1024` | Number of recent change events kept for `Last-Event-ID` replay.                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `ELASTIK_COAP_MAX_IN_FLIGHT`     |      `1024` | Maximum concurrent SCoAP/UDP request handlers when CoAP is enabled.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `ELASTIK_READ_CACHE_MAX_ENTRIES` |      `5000` | Per-world SQLite read connection cache cap. Each cached entry pins ~250 KiB (PRAGMA `cache_size=-200`); default 5000 entries puts worst-case resident at ~1.25 GiB. At-cap reads still go through the slot protocol via a transient slot (the cap controls persistence, not safety). Zero or non-numeric values fall back to the default. Surface live cache state via `/proc/pool`.                                                                                                                                          |
| `ELASTIK_PERSIST_HEADERS`        |     _empty_ | Custom representation headers to round-trip with the body, on top of the built-in default-allow set (Layer 3 of the persist policy). Comma-separated; trailing `*` = prefix match (`x-my-*`). Default empty means "only the built-in standard reps round-trip; no custom headers." Example: `ELASTIK_PERSIST_HEADERS=x-author,x-version,x-my-*`.                                                                                                                                                                            |
| `ELASTIK_DENY_HEADERS`           |     _empty_ | Subtract entries from the built-in default-allow set (Layer 1.5). Use to drop a specific standard header your deployment doesn't want round-tripping (e.g.`cache-control`). Same matcher shape as `ELASTIK_PERSIST_HEADERS`. Hardcoded security deny (Layer 1: tracing / cloud / IP-leak / credentials / transport) always wins over this. **Affects future writes only** -- already-persisted headers still round-trip until the affected worlds are re-`PUT`. Default empty means "no built-in entries subtracted." |

The HTTP request body limit is 64 MiB. `POST` append also checks the projected
final world size before writing. If a write would cross a cap, the core returns
`413 Payload Too Large`. If `/listen/*` is full, the core returns
`503 Service Unavailable`. If SCoAP/UDP in-flight work is full, the core
returns CoAP `5.03 Service Unavailable`. If durable storage quota is exhausted,
or the underlying filesystem / SQLite reports storage exhaustion, the core
returns `507 Insufficient Storage`.

`ELASTIK_MAX_STORAGE_BYTES` counts durable body bytes, not SQLite or audit-log
file overhead. `/proc/df` reports the same body-byte accounting; physical disk
exhaustion is still caught separately as `507 Insufficient Storage`. Invalid
non-empty storage quota values fail startup so typos do not silently disable
the cap.

## Pipeline Trace

The Rust core has a structured FSM trace for the request lifecycle. Off by
default; set `ELASTIK_TRACE_PIPELINE=1` to enable. One stderr line per phase,
indented `aux` lines for sub-steps inside a verb handler:

```text
[req-42  +0.000ms] Received       PUT /home/data 1024B
[req-42  +0.054ms] Authenticated  tier=Write
[req-42  +0.061ms] PathValidated  world=home/data
[req-42  +0.063ms] Dispatched     verb=Put
[req-42  +0.184ms]   aux          lock_acquired
[req-42  +0.892ms]   aux          sqlite_committed etag=hmac-9f3a...
[req-42  +0.894ms]   aux          notify_sent
[req-42  +0.895ms] CommittedWrite status=201
[req-42  +0.895ms] Done           status=201 total=0.895ms
```

`grep req-42` reconstructs one full request lifecycle. `GET` and `HEAD` emit
one `body_size` aux line but no lock / audit / notify aux  reads don't
lock, don't write, don't fire change events. `DELETE` adds
`audit_intent` / `audit_commit` / `audit_commit_failed[_event_failed]` so
the intent / commit two-step is legible, including the honest
double-failure case where the commit append AND the subsequent
failure-event append both fail.

Cost when disabled is one atomic-bool load per phase (≈1 ns). Cost when
enabled is ≈1 µs per stderr line, a typical write request emits 6
lifecycle lines (`Received` → `Authenticated` → `PathValidated` →
`Dispatched` → `CommittedWrite` → `Done`) plus the verb aux lines shown
in the sample.

The flag is read once at startup and frozen for the process lifetime; toggle
it by restarting the process. A runtime toggle through `/etc/debug` is on the
roadmap.

## Auth

There are three token levels:

| Tier    | Variable                  | Meaning                                         |
| ------- | ------------------------- | ----------------------------------------------- |
| Read    | `ELASTIK_READ_TOKEN`    | Optional read gate. If empty, reads are public. |
| Write   | `ELASTIK_WRITE_TOKEN`   | Write ordinary worlds. Includes read.           |
| Approve | `ELASTIK_APPROVE_TOKEN` | Write system worlds and delete. Includes read.  |

Migration note: `ELASTIK_TOKEN` was the old write-token name. It still works
as a temporary fallback when `ELASTIK_WRITE_TOKEN` is unset, but startup and
the Python SDK warn so you can rename it.

Policy is small:

- `GET`, `HEAD`, `OPTIONS`, `/listen/*`, `/proc/worlds`, `/proc/du`,
  `/proc/df`, `/proc/pool`, and `/proc/audit/{path}/verify` require read only
  when `ELASTIK_READ_TOKEN` is configured.
- `PUT` and `POST` require `ELASTIK_WRITE_TOKEN` for ordinary worlds.
- `/etc/*`, `/lib/*`, `/boot/*`, `/usr/*`, and `/var/log/*` writes require
  `ELASTIK_APPROVE_TOKEN`.
- `DELETE` requires `ELASTIK_APPROVE_TOKEN`.

Use `Authorization: Bearer <token>`.

Startup requires only `ELASTIK_KEY`. Tokens are not required to boot:

```powershell
python -m elastik run --key dev-hmac-key
```

That creates a public-read server with writes and deletes disabled. For normal
local development, pass all three tokens:

```powershell
python -m elastik run `
  --key dev-hmac-key `
  --read-token read-token `
  --write-token write-token `
  --approve-token approve-token
```

```powershell
curl.exe -X PUT http://127.0.0.1:3105/home/x `
  -H "Authorization: Bearer write-token" `
  --data-binary "x"
```

## Paths Are Storage Policy

One port is enough. The path chooses the backend.

| Path prefix | Backend | Persistence | Audit |
| ----------- | ------- | ----------- | ----- |
| `/home/*` | SQLite  | durable     | yes   |
| `/etc/*`  | SQLite  | durable     | yes   |
| `/lib/*`  | SQLite  | durable     | yes   |
| `/boot/*` | SQLite  | durable     | yes   |
| `/usr/*`  | SQLite  | durable     | yes   |
| `/var/*`  | SQLite  | durable     | yes   |
| `/tmp/*`  | memory  | transient   | no    |
| `/dev/*`  | memory  | transient   | no    |
| `/sys/*`  | memory  | transient   | no    |
| `/proc/*` | virtual | generated   | no    |

Bare paths are convenience spelling for `/home`:

```text
/hello       -> /home/hello
/home/hello  -> /home/hello
/tmp/x       -> /tmp/x
```

This rule is load-bearing: `/home/tmp/foo` stays a durable home world. It does
not silently become `/tmp/foo`.

Namespace roots are reserved. You cannot create worlds named exactly `home`,
`tmp`, `dev`, `sys`, `proc`, `etc`, `lib`, `boot`, `usr`, `var`, or `var/log`.
`/proc/*` is reserved for core endpoints.

## HTTP Grammar

### PUT: replace

`PUT` stores the request body exactly as sent. `Content-Type` and selected
representation headers are stored and replayed on `GET` and `HEAD`.

```powershell
curl.exe -X PUT http://127.0.0.1:3105/home/report.pdf `
  -H "Authorization: Bearer write-token" `
  -H "Content-Type: application/pdf" `
  -H "Content-Disposition: attachment; filename=`"report.pdf`"" `
  --data-binary "@report.pdf"
```

Later:

```powershell
curl.exe -I http://127.0.0.1:3105/home/report.pdf
curl.exe http://127.0.0.1:3105/home/report.pdf --output report.pdf
```

Elastik does not need an extension field. The HTTP `Content-Type` is the type.

### GET: read

`GET` returns the stored bytes.

```powershell
curl.exe http://127.0.0.1:3105/home/hello
```

For binary data:

```powershell
curl.exe http://127.0.0.1:3105/home/report.pdf --output report.pdf
```

### HEAD: inspect

`HEAD` returns the same metadata headers as `GET`, without the body.

```powershell
curl.exe -I http://127.0.0.1:3105/home/report.pdf
```

Use `curl -I`, not `curl -X HEAD`. `-I` makes curl issue a real HEAD request
and handle the no-body response correctly.

### POST: append

`POST` appends bytes to an existing world. It does not change representation
metadata.

```powershell
curl.exe -X POST http://127.0.0.1:3105/home/log `
  -H "Authorization: Bearer write-token" `
  --data-binary "`nnext line"
```

### DELETE: remove

`DELETE` removes a world and requires the approve token.
The global delete ledger at `/var/log/deletes` is append-only and cannot be
deleted through HTTP.

Durable deletes are recorded as `delete_intent` before removal and
`delete_commit` after removal. If the physical delete succeeds but the commit
record fails, core returns `204` because the world is already gone and records a
best-effort `delete_commit_failed` event. An intent without either follow-up is
an operational reconciliation signal, not audit-chain corruption: the delete may
have been interrupted, or the physical delete may have completed while both
follow-up ledger appends failed. Check whether the target world still exists and
inspect the server warning log before deciding whether recovery is needed.

```powershell
curl.exe -X DELETE http://127.0.0.1:3105/home/old `
  -H "Authorization: Bearer approve-token"
```

### OPTIONS: discover

```powershell
curl.exe -X OPTIONS -I http://127.0.0.1:3105/home/x
```

The response includes:

```http
Allow: GET, HEAD, PUT, POST, DELETE, OPTIONS
Accept-Ranges: bytes
```

## Representation Headers

Elastik separates media type, persisted response metadata, request controls,
and core-owned response state.

`Content-Type` is first-class. It is stored as the representation media type
and returned on `GET` and `HEAD`.

It is also rejected from the generic persisted-header path: `Content-Type` has
a dedicated media-type slot rather than ordinary persisted response-header
storage.

Other safe response headers from `PUT` are persisted and replayed on read.
The decision is made by a four-layer policy:

1. **Hard deny** (hardcoded). Credentials, hop-by-hop transport state,
   request controls, distributed-tracing context, cloud-provider
   injections, IP-leak headers, HTTP/2+3 pseudo-headers, and core-owned
   response headers are never persisted. Operators cannot turn this off.
2. **User deny** (`ELASTIK_DENY_HEADERS`). Operator subtraction from the
   built-in default-allow set in step 3. Affects future writes only --
   already-persisted bytes still round-trip until the world is re-PUT.
3. **Default allow** (hardcoded). Standard representation headers that
   travel with the body without configuration -- all are response-only
   headers describing browser policy or body identity, not request or
   transport state:
   - `Content-Disposition`, `Content-Encoding`, `Content-Language`,
     `Content-MD5`
   - `Cache-Control`, `Expires`
   - Full `Access-Control-Allow-*` family + `Access-Control-Expose-Headers`
     + `Access-Control-Max-Age`
   - `Content-Security-Policy`, `Content-Security-Policy-Report-Only`,
     `X-Frame-Options`, `Permissions-Policy`, `Cross-Origin-Resource-Policy`,
     `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`,
     `Referrer-Policy`, `X-Robots-Tag`
4. **User allow** (`ELASTIK_PERSIST_HEADERS`). Operator opts in custom
   headers (`X-Author`, `X-Tag`, `X-Meta-*`, etc.) on top of step 3.
   Default empty: nothing custom round-trips.

`Last-Modified` is intentionally **not** in the default-allow set. Elastik
uses the HMAC-chained `ETag` as the canonical version identifier;
`Last-Modified` would invite clients to send `If-Modified-Since` and bypass
the audit-chained `If-None-Match` flow.

`X-Meta-*` is an SDK/user metadata convention but is **not** persisted by
default in v7.2 and later. To restore the v7.1-and-prior behavior:

```env
ELASTIK_PERSIST_HEADERS=x-meta-*
```

When `X-Meta-*` is allowlisted and persisted on durable worlds, it enters
the audit metadata hash (`meta_sha256`) and `event_headers`, so changing
`X-Meta-*` changes the audited representation state.

Each successful durable write advances the audit chain, so two `PUT`s with the
same body and metadata still produce different ETags. ETags identify a specific
write in the chain, not only a content hash.

Headers that describe this request, this connection, browser probing, proxy
trail, or core-generated state are not stored. The blacklist is category-based:

- credentials and ambient identity: `Authorization`, `Proxy-Authorization`,
  `Cookie`, `Set-Cookie`
- hop-by-hop and transport state: `Host`, `Connection`, `Keep-Alive`,
  `Proxy-Authenticate`, `Proxy-Connection`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`, `HTTP2-Settings`
- request controls and preferences: `Accept*`, `Expect`, `From`,
  `Max-Forwards`, `Origin`, `Prefer`, `Range`, `Referer`, `Referrer`, `DNT`,
  `User-Agent`, `If-*`
- core-owned response state: `Content-Type` generic persistence,
  `Content-Length`, `ETag`, `Accept-Ranges`, `Content-Range`, `Link`,
  `Location`, `Allow`, `Date`, `Server`, `WWW-Authenticate`, `Age`, `Vary`,
  `X-Request-Id`, `X-Elapsed-Us`, `X-Content-Type-Options`
- proxy trail: `Forwarded`, `Via`, `X-Forwarded-For`, `X-Forwarded-Host`,
  `X-Forwarded-Proto`
- browser probes and CORS preflight request headers: `Sec-*`,
  `Access-Control-Request-*`, `Want-*`

Because this policy is denylist-based, the repository also carries a drift
radar. `tools/header_policy_scan.py` compares the reviewed baseline in
`tools/header_policy_baseline.txt` with the IANA HTTP Field Name Registry and
MDN browser header data. New upstream header names fail the weekly header
policy workflow until a human classifies them as request state, transport
state, core-owned state, or representation metadata that may travel with the
bytes.

That split is the core contract:

```text
Content-Type                  -> first-class media type; travels with bytes
stored response headers        -> safe metadata; travels with bytes; audited
request control headers        -> used once, then discarded
core generated headers         -> ETag, Content-Length, Accept-Ranges,
                                  Content-Range, Link, Location, Allow, Date,
                                  Server, WWW-Authenticate, Age, Vary,
                                  X-Request-Id, X-Elapsed-Us,
                                  X-Content-Type-Options
```

Static resources can carry their own browser policy as HTTP headers:

```powershell
curl.exe -X PUT http://127.0.0.1:3105/home/logo.png `
  -H "Authorization: Bearer write-token" `
  -H "Content-Type: image/png" `
  -H "Access-Control-Allow-Origin: *" `
  -H "X-Frame-Options: DENY" `
  --data-binary "@logo.png"
```

`GET /home/logo.png` returns those policy headers with the image bytes. The
core does not know what CORS or frame policy means; it just preserves safe
response metadata for the client that does know.

## Trust Model

The core is a byte store, not a browser security product.

If a client stores HTML with `Content-Type: text/html`, Elastik will serve HTML.
If an AI stores JavaScript inside that HTML, Elastik will serve that JavaScript.
The core does not sanitize HTML, rewrite scripts, strip iframes, invent CSP, or
decide whether a page is safe to render.

That is intentional. Curl, SDK workers, protocol bridges, and agents need exact
bytes back. The browser is only one consumer, and it is the consumer with the
most policy.

Browser-facing surfaces should enforce browser policy outside the core or make
the resource carry its own policy:

- Serve untrusted HTML through a sandboxed renderer or a separate origin.
- Add `Content-Security-Policy` at the browser UI, reverse proxy, or
  static shell layer.
- Or store response-policy headers such as `Content-Security-Policy`,
  `Access-Control-Allow-Origin`, `X-Frame-Options`, and
  `Permissions-Policy` with the resource on `PUT`.
- Or make the HTML world carry its own browser policy with `<meta http-equiv="Content-Security-Policy" ...>`. HTML is already a web app; the
  policy can travel with the bytes that define the app.
- Use escaping or text rendering when displaying untrusted worlds in
  `index.html`.
- Use read-only tokens for public browsing surfaces.
- Do not give untrusted writers access to representation headers such as
  `Cache-Control`, `Content-Disposition`, `Content-Encoding`, CORS, or CSP
  unless you want them to control those HTTP semantics.

Core rule: store what was written, return what was stored. Browser safety is a
content, client, or edge concern. Whoever writes the HTML should decide whether
that HTML allows scripts, frames, network fetches, forms, or nothing at all.

## ETag and Conditional Requests

Durable worlds use the audit-chain HMAC as the strong ETag:

```http
ETag: "hmac-..."
```

Memory worlds use a body hash:

```http
ETag: "sha256-..."
```

Audit verification is HTTP too. The core owns the HMAC key, so it replays the
chain itself and answers in status plus headers:

```http
HEAD /proc/audit/home/note/verify
```

An intact durable chain returns:

```http
HTTP/1.1 200 OK
X-Audit-Valid: true
X-Audit-Events: 42
X-Audit-Genesis: hmac-...
X-Audit-Latest: hmac-...
```

A broken chain returns `409 Conflict` with `X-Audit-Valid: false`,
`X-Audit-Break-At`, `X-Audit-Expected`, and `X-Audit-Actual`. Missing worlds
return `404 Not Found`. Memory worlds return `204 No Content` with
`X-Audit-Valid: n/a`.

Create only if missing:

```powershell
curl.exe -X PUT http://127.0.0.1:3105/home/lock/build `
  -H "Authorization: Bearer write-token" `
  -H "If-None-Match: *" `
  --data-binary "agent-a"
```

Optimistic update:

```powershell
$etag = (curl.exe -sI http://127.0.0.1:3105/home/config |
  Select-String -Pattern '^etag:' |
  ForEach-Object { $_.ToString().Split(':', 2)[1].Trim() })

curl.exe -X PUT http://127.0.0.1:3105/home/config `
  -H "Authorization: Bearer write-token" `
  -H "If-Match: $etag" `
  --data-binary "@config.txt"
```

Cache validation:

```powershell
curl.exe -i http://127.0.0.1:3105/home/config -H "If-None-Match: $etag"
```

If unchanged, the core returns:

```http
HTTP/1.1 304 Not Modified
ETag: "hmac-..."
```

## Range Requests

Elastik supports single byte ranges:

```powershell
curl.exe -i http://127.0.0.1:3105/home/big.bin -H "Range: bytes=0-1023"
```

Expected response:

```http
HTTP/1.1 206 Partial Content
Accept-Ranges: bytes
Content-Range: bytes 0-1023/...
```

Use `If-Range` with a known ETag to say: return the range only if this is still
the same representation, otherwise return the whole body.

Multiple ranges are ignored and fall back to `200 OK` full-body responses.
Unsatisfiable ranges return `416 Range Not Satisfiable`.

## Link Headers

World responses include hypermedia hints:

```http
Link: </listen/home/report>; rel="monitor"
Link: </home/>; rel="collection"
```

They are ordinary RFC 8288-style links. A client can ignore them, or use them
to discover the monitor stream and parent collection.

## Listen: Server-Sent Events

`/listen/*` is the control-plane stream.

```powershell
curl.exe -N http://127.0.0.1:3105/listen/*
```

Then write from another terminal:

```powershell
curl.exe -X PUT http://127.0.0.1:3105/home/task/a `
  -H "Authorization: Bearer write-token" `
  --data-binary "hello"
```

The listener sees:

```text
event: put
id: 1
data: path: /home/task/a
data: method: PUT
data: etag: hmac-...
```

The stream does not embed the body. Consumers that need content follow up with
`GET` or `HEAD`. That keeps `/listen/*` small, replayable, and curl-readable.

Pattern examples:

```text
/listen/*              all changes
/listen/home/task/*    prefix
/listen/home/task/a    exact
```

The core keeps a small in-memory replay ring. Reconnect with the standard SSE
header to receive matching events after the last id you saw:

```powershell
curl.exe -N http://127.0.0.1:3105/listen/home/task/* -H "Last-Event-ID: 12"
```

This is not a durable queue. If the ring overflows, the stream emits
`event: lag`; consumers that cannot lose work should store tasks as worlds and
use `/listen/*` as a wakeup signal.

## Introspection

```powershell
curl.exe http://127.0.0.1:3105/proc/version
curl.exe http://127.0.0.1:3105/proc/worlds
curl.exe http://127.0.0.1:3105/proc/du
curl.exe http://127.0.0.1:3105/proc/df
```

`/proc/worlds` is plain text, one world per line:

```text
home/hello
tmp/scratch
```

No JSON. Pipe it.

```powershell
curl.exe -s http://127.0.0.1:3105/proc/worlds | Select-String '^home/'
```

`/proc/du` reports body bytes per world:

```text
home/hello	5
tmp/scratch	4
```

`/proc/du` is intentionally unpaginated management introspection: one line per
world, like Unix `du`. It is read-gated and scans durable state off the Tokio
worker; use `/proc/df` for cheap polling. `/proc/df` reads maintained durable
usage and world-count counters instead of scanning every durable world.

`/proc/df` reports usage, quota, and available bytes:

```text
storage	5	unlimited	unlimited
memory	4	268435456	268435452
worlds	2	unlimited	unlimited
```

`/proc/pool` reports the SQLite read connection cache and audit
ledger writer state. Eight metrics, one per line, with a
Prometheus-style `counter` (monotonic from process start) or
`snapshot` (instantaneous gauge) label so a polling operator knows
which to subtract vs read directly:

```text
read_cache_entries 7 snapshot
read_cache_tombstones 0 snapshot
read_cache_hits 1842 counter
read_cache_misses 11 counter
read_cache_capped 0 counter
read_cache_open_fails 0 counter
read_cache_max_entries 5000 snapshot
ledger_writer_inits 1 counter
```

`read_cache_capped > 0` means the workload's hot working set
exceeds `ELASTIK_READ_CACHE_MAX_ENTRIES`; at-cap reads still
complete correctly via a transient slot but skip caching. Raise
the cap if hit-rate drops. `ledger_writer_inits` should equal `1`
in steady state (lazy-init on first DELETE); higher values surface
re-init events that would otherwise be invisible. The DashMap walk
runs inside `spawn_blocking` so polling does not stall the async
runtime. Same auth gating as `/proc/df`: read token if
`ELASTIK_READ_TOKEN` is set, otherwise public.

## SDKs

The core is still just HTTP. SDKs are convenience layers around the same six
verbs; they do not add a second protocol or object model.

| SDK        | Status                           | Why                                                                                                                       |
| ---------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Python     | primary local glue               | Best for local agents, CLI wrappers, tests,`@listen`, debug sinks, and small automation.                                |
| JavaScript | shipped as `@elastikjs/client` | Browser and Node fetch client. In Node,`Elastik.start()` can spawn the bundled Rust core through platform npm packages. |
| Go         | roadmap                          | Good for single-binary sidecars and distribution.                                                                         |
| Rust       | roadmap                          | Good for embedding close to the core once the ABI stops moving.                                                           |

### Browser Is Already The SDK

Elastik does not need a browser SDK before browsers can use it. The browser is
already the most complete HTTP client SDK on the planet.

```html
<img src="/home/logo.png">
<link rel="stylesheet" href="/home/style.css">
<script src="/lib/app.js"></script>
<embed src="/home/report.pdf">
<a href="/home/file.zip" download>download</a>
```

Every tag above is a `GET`. The core returns bytes plus `Content-Type`, and the
browser does the rest: image decoding, CSS parsing, JavaScript execution, PDF
rendering, or download handling.

An HTML world can also carry its own browser policy:

```html
<!-- PUT /home/app.html with Content-Type: text/html -->
<html>
<head>
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; script-src 'none'; frame-ancestors 'none'">
</head>
<body>
  I carry my own policy. The core stores bytes and returns bytes.
</body>
</html>
```

The browser reads the meta policy and enforces it. Elastik does not need to
understand CSP to preserve it. For HTML, the document is already an app, and the
app can ship its own rules with its own bytes.

Non-HTML static resources can carry policy in their stored response headers:

```powershell
curl.exe -X PUT http://127.0.0.1:3105/home/logo.png `
  -H "Authorization: Bearer write-token" `
  -H "Content-Type: image/png" `
  -H "Access-Control-Allow-Origin: *" `
  --data-binary "@logo.png"
```

The later `GET /home/logo.png` returns `Access-Control-Allow-Origin: *`. The
browser enforces it; Elastik only preserves it.

The same applies to browser-native HTTP features:

```html
<img src="/home/logo.png" loading="lazy">
<video src="/home/demo.mp4" controls preload="none"></video>
<img srcset="/home/logo-1x.png 1x, /home/logo-2x.png 2x">
```

Lazy loading is browser scheduling. Video seeking is browser-issued `Range`
requests against the core's `206 Partial Content`. Responsive images are the
browser choosing which path to `GET`. ETag caching, `If-None-Match`, `304`,
gzip decoding, MIME handling, and rendering are all already in the browser.

When code is useful, the JavaScript package keeps that same shape:

```js
import { Elastik } from "@elastikjs/client";

const e = new Elastik("http://127.0.0.1:3105", {
  writeToken: "write-token",
  readToken: "read-token",
});

await e.putJson("home/order/123", { sku: "tea", qty: 2 });
const order = await e.getJson("home/order/123");
const stop = e.listen("home/receipt/*", (event) => console.log(event.path));
```

That is not a new protocol. It is just HTTP from JavaScript, with typed errors,
JSON/text helpers, `AbortController`, auth headers, and an SSE parser that can
send Bearer tokens where native `EventSource` cannot.

Install the JavaScript SDK:

```powershell
npm install @elastikjs/client
```

In Node, the `/start` entrypoint can launch the bundled Rust core:

```js
import { Elastik } from "@elastikjs/client/start";

const e = await Elastik.start();       // random key/token/port/temp data dir
await e.putText("home/note", "hello from node");
console.log(await e.getText("home/note"));
await e.stop();
```

In the browser, import `@elastikjs/client` and point it at an already-running
core. The Node-only `start()` machinery is deliberately absent from browser
bundles.

See `sdk-js/README.md` for the full JavaScript surface, including browser-policy
shortcuts such as `csp`, `cors`, `frameOptions`, `cache`, and `robots`.

### Python SDK

The Python SDK is a nicer curl for local systems. Its job is glue: starting the
local core, writing bytes, reading bytes, listening for changes, and connecting
Elastik to CLI tools, AI workers, tests, and small local automation.

Install from PyPI:

```powershell
py -m pip install elastik
```

Run the bundled core:

```powershell
py -m elastik run --key dev-hmac-key --read-token read-token --write-token write-token --approve-token approve-token
```

Install from source for local development:

```powershell
python -m pip install -e .\sdk
```

The same command works either way:

```powershell
python -m elastik run --key dev-hmac-key --read-token read-token --write-token write-token --approve-token approve-token
```

Use the atoms:

```python
from elastik import Elastik

e = Elastik("http://127.0.0.1:3105", bearer_token="write-token")

e.put("/home/note", "hello", content_type="text/plain; charset=utf-8")
body = e.get("/home/note")          # bytes
head = e.head("/home/note")         # dict, lower-case headers

etag = head["etag"]
e.put("/home/note", "new", if_match=etag)

chunk = e.get("/home/note", range=(0, 2))
missing_or_same = e.get("/home/note", if_none_match=etag)  # None on 304

r = e.request("OPTIONS", "/home/note")
print(r.status, r.headers.get("allow"))
```

`Elastik.request()` is the escape hatch. Any HTTP header the SDK has not sugared
can still be sent directly, except wire-level headers managed by the HTTP
client itself, such as `Content-Length`, `Transfer-Encoding`, `Host`, and
`Connection`.

If you pass `Authorization` explicitly in `headers=`, it takes precedence over
the client's `bearer_token`. That is intentional: `headers=` is the escape
hatch, so it wins.

### SDK Debug Sink

The core stamps every response with `X-Request-Id` and `X-Elapsed-Us`.
The Python SDK can turn those headers into a temporary request journal under
`/tmp/debug/*`:

```python
e.enable_debug(level="slow", slow_ms=100, record=True)

e.put("/home/note", "hello")
print(e.debug_history[-1])
print(e.debug_stats())
```

Levels are borrowed from the usual Python debugging instincts:

- `level="all"` records every request.
- `level="slow"` records slow requests and 4xx/5xx responses.
- `level="errors"` records only 4xx/5xx responses.

Use `disable_debug()` to turn tracing off. `verbose=0/1/2/3` maps to
errors/slow/all/all-with-redacted-headers and is mutually exclusive with
`level=`. A hook can observe each request without changing normal control flow:

```python
def alert(method, path, status, ms, rid):
    if ms > 200:
        print(f"slow request {rid}: {method} {path} {ms:.0f}ms")

e.enable_debug(level="all", hook=alert, break_on=412)
e.enable_debug(level="errors", break_on=range(400, 500))  # break on any 4xx
```

With `record=True`, debug history is in-memory only by default. To write JSONL
into elastik, pass a sink explicitly:

```python
e.enable_debug(level="slow", sink="/tmp/debug/requests")
```

The `/tmp/debug/requests` sink has convenience mirrors for `/tmp/debug/errors`
and `/tmp/debug/slow`. Debug writes are best-effort and do not recursively log
themselves. Because `/tmp` is memory-backed, these records are supposed to
disappear when the core restarts.

`panel=True` writes a tiny HTML panel to `/tmp/debug-panel.html` and prints its
URL to stderr. The panel uses `/listen/tmp/debug/requests` only as a wakeup
signal, then reads `/tmp/debug/requests` over normal `GET`, preserving the core
rule that SSE events are control-plane only and do not embed bodies. If your
core requires read auth, your browser still needs to send the same Bearer
token, for example through a header extension during local debugging.

You can also launch a child core with tracing already enabled:

```python
e = elastik.start(key="...", write_token="...", debug=True)
```

No framework is hidden here. The panel is just bytes in `/tmp`; overwrite it
with your own HTML if you want a different dashboard.

The core keyspace is flat. A path like `home/sensor/kitchen/temp` is one stored
world, not three real directories. The Python SDK gives you a virtual hierarchy
when that is the human-shaped view you want:

```python
e.ls("home/sensor")              # immediate children; virtual dirs end in /
e.ls("home/sensor", depth=-1)    # all descendants
print(e.tree("home"))
(e / "home" / "sensor").iterdir()
(e / "home" / "old").rmtree()
```

Recursive deletion refuses namespace roots such as `home` and the empty prefix
unless `force=True` is explicit. `mv()` is copy+delete and refuses overwrite by
default; it is not an atomic filesystem rename.

The on-disk `data/` directory is percent-encoded for filesystem safety:
`home/note.txt` becomes `home%2Fnote%2Etxt/`. For ops/debugging:

```powershell
python -m elastik decode-path "home%2Fnote%2Etxt"
python -m elastik ls-data .\data
```

## Performance: Stateless First

The Python SDK intentionally uses one-shot stdlib HTTP requests by default.
It does not keep a connection pool and it does not maintain hidden HTTP session
state.

That is slower than an HTTP keep-alive client, and that is fine. The default
SDK path optimizes for the boring properties first:

- zero dependencies: no `requests`, no `urllib3`, no version conflicts.
- no client connection state to leak.
- no stale pooled socket to recover.
- no half-dead keep-alive connection to debug.
- no SSE `/listen/*` stream accidentally occupying the only CRUD connection.

HTTP keep-alive is still available. It is already part of HTTP/1.1 and the
Rust core supports it through axum/hyper. High-frequency callers can use
`curl`, `ab -k`, `http.client.HTTPConnection`, or their own transport if they
measure a real bottleneck.

The default SDK stays deliberately dumb:

```text
request in -> response out -> connection gone
```

On small cloud containers, even this dumb path handles thousands of reads per
second. The fast path is there when needed, but stateless is the baseline.

## Python @listen

The decorator is SDK-side. The core only emits SSE events.

```python
import elastik

@elastik.listen("/home/task/*")
def on_task(body, world, e):
    result = body.upper()
    name = world.rsplit("/", 1)[-1]
    e.put(f"/home/result/{name}", result)

e = elastik.Elastik("http://127.0.0.1:3105", bearer_token="write-token")
elastik.run(e)
```

This replaces the local shape of a queue:

```text
PUT /home/task/a  -> SSE event -> SDK handler -> PUT /home/result/a
```

No Kafka. No Redis. No WebSocket server. Just HTTP plus an SDK callback.

Lifecycle hooks wrap the SDK event loop. They are useful for worker health
worlds and cleanup:

```python
@elastik.on_startup
def ready(e):
    e.put("/sys/health/worker-1", "alive")

@elastik.on_shutdown
def gone(e):
    e.delete("/sys/health/worker-1")

elastik.run(e)
```

Hooks may accept no arguments or ask for `e`. Shutdown hooks run even when
`run()` exits through `max_events`, Ctrl+C, or an exception.

## Trusted Shell Pool

For local agent pipelines, the SDK includes a warmed shell pool:

```python
from elastik.tools import TrustedShellPool

pool = TrustedShellPool(size=2, acquire_timeout=1.0)

@elastik.listen("/home/task/shell/*")
def run_shell(body, world, e):
    result = pool.run(body.decode("utf-8"), timeout=10)
    e.put("/home/result/" + world.rsplit("/", 1)[-1], result.stdout)
```

It is called `Trusted` on purpose. Feeding arbitrary worlds into a shell is
remote code execution. Use it for private local queues, not public inboxes.
`size` is the concurrency limit; when every worker is busy, `acquire_timeout`
lets callers fail fast instead of blocking the reactor forever.

## Build and Test

Rust core:

```powershell
cd core
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

Black-box SDK test:

```powershell
cd C:\Users\chenh\Elastik-franchise\Elastik-playground
python sdk\tests\e2e_blackbox.py
python sdk\tests\test_tools.py
python -m compileall -q sdk\src sdk\tests
```

Makefile shortcuts:

```powershell
make dev
make test
make build
```

## Design Rules

### Curl first, browser native

If an operation is not pleasant from curl, the core is wrong. Browser UI lives
outside the core because browsers bring CSP, CORS, HTML, iframes, service
workers, and policy. Those are real concerns, but they are not the disk.

That does not make the browser second-class. It makes the browser an HTTP
peer. HTML tags, `fetch`, and `EventSource` already know how to talk to the
core. A browser SDK should be an optional convenience snippet, not a second
object model.

### Bytes first

Elastik stores bytes and returns bytes. Text, PDF, HTML, images, gzip, and
application-specific formats are all just byte representations with HTTP
metadata.

### HTTP semantics before new knobs

Use existing headers before inventing names:

- `Content-Type` instead of extension fields.
- `ETag` instead of version fields.
- `Range` instead of custom chunk endpoints.
- `Link` instead of private next-route hints.
- `If-Match` and `If-None-Match` instead of custom CAS APIs.

### Path is policy

`/tmp/*` is memory. `/home/*` is durable. `/proc/*` is generated. The caller
does not need to know which data structure sits behind the path.

### Extensions are endpoints

An extension is any program that reads and writes HTTP:

- a WebDAV bridge
- an SMTP inbox bridge
- an MQTT sidecar
- an AI worker
- a Python `@listen` handler
- a CLI wrapper around another CLI

The core does not load them. It only receives the HTTP they produce.

## What Elastik Is Not

Elastik is not a database with a query planner.

Elastik is not a sync engine.

Elastik is not a plugin host.

Elastik is not an AI API server.

Elastik is a network-visible byte store with enough HTTP semantics that the
rest of the operating system can compose around it.

## License

MIT.
