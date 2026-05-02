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
cd C:\Users\chenh\Elastik-franchise\Elastik-playground\core
$env:ELASTIK_KEY = "dev-hmac-key"
$env:ELASTIK_READ_TOKEN = "read-token"
$env:ELASTIK_WRITE_TOKEN = "write-token"
cargo run
```

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

ELASTIK_KEY=change-me
ELASTIK_READ_TOKEN=
ELASTIK_WRITE_TOKEN=
ELASTIK_APPROVE_TOKEN=
```

`ELASTIK_KEY` is required. It signs the audit chain. A public or empty key makes
the audit chain meaningless.

Tokens are optional capability gates. Missing tokens do not stop the core from
starting; they disable the corresponding protected operations:

- no `ELASTIK_READ_TOKEN`: reads are public.
- no `ELASTIK_WRITE_TOKEN`: ordinary `PUT` and `POST` are disabled.
- no `ELASTIK_APPROVE_TOKEN`: `DELETE` and system writes are disabled.

`ELASTIK_DATA` is the universe selector. Point the same binary at another data
directory and it serves another Elastik universe. Local SSD/tempdir is best for
writes. Synced folders and network shares can be useful for distribution, but
SQLite-on-network-filesystem is a tradeoff you should make deliberately.

Run one writer process per `ELASTIK_DATA`. The core has a per-process write
lock that makes conditional writes atomic inside one server, but it is not a
distributed lock across multiple core processes pointed at the same directory.

Empty token variables are treated as unset.

Resource caps:

| Variable | Default | Meaning |
|---|---:|---|
| `ELASTIK_MAX_WORLD_BYTES` | `67108864` | Maximum stored size of one world after `PUT` or `POST`. |
| `ELASTIK_MAX_MEMORY_BYTES` | `268435456` | Maximum total bytes in memory-backed worlds (`/tmp`, `/dev`, `/sys`). |

The HTTP request body limit is 64 MiB. `POST` append also checks the projected
final world size before writing. If a write would cross a cap, the core returns
`413 Payload Too Large`.

## Auth

There are three token levels:

| Tier | Variable | Meaning |
|---|---|---|
| Read | `ELASTIK_READ_TOKEN` | Optional read gate. If empty, reads are public. |
| Write | `ELASTIK_WRITE_TOKEN` | Write ordinary worlds. Includes read. |
| Approve | `ELASTIK_APPROVE_TOKEN` | Write system worlds and delete. Includes read. |

Migration note: `ELASTIK_TOKEN` was the old write-token name. It still works
as a temporary fallback when `ELASTIK_WRITE_TOKEN` is unset, but startup and
the Python SDK warn so you can rename it.

Policy is small:

- `GET`, `HEAD`, `OPTIONS`, `/listen/*`, and `/proc/worlds` require read only
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
|---|---|---|---|
| `/home/*` | SQLite | durable | yes |
| `/etc/*` | SQLite | durable | yes |
| `/lib/*` | SQLite | durable | yes |
| `/boot/*` | SQLite | durable | yes |
| `/usr/*` | SQLite | durable | yes |
| `/var/*` | SQLite | durable | yes |
| `/tmp/*` | memory | transient | no |
| `/dev/*` | memory | transient | no |
| `/sys/*` | memory | transient | no |
| `/proc/*` | virtual | generated | no |

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

Elastik stores safe representation/response headers from `PUT` and replays
them on read. This is blacklist-based: core refuses credentials,
hop-by-hop transport state, request controls, and headers it computes itself.
Everything else travels with the bytes.

- `Content-Type`
- `Content-Encoding`
- `Content-Language`
- `Content-Disposition`
- `Cache-Control`
- `Access-Control-Allow-Origin`
- `Content-Security-Policy`
- `X-Frame-Options`
- `Permissions-Policy`
- future response headers the core does not understand
- `X-Meta-*`

Headers that describe this request, this connection, or core-generated state
are not stored:

- `Authorization`
- `Cookie`
- `Connection`
- `Transfer-Encoding`
- `Host`
- `Range`
- `If-Match`
- `If-None-Match`
- `If-Range`
- `ETag`
- `Content-Length`
- `Location`
- `Link`
- `Allow`
- `Accept-*`

That split is the core contract:

```text
stored representation headers -> travel with the bytes
request control headers       -> used once, then discarded
core generated headers        -> ETag, Content-Length, Link, Location, Allow
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
- Or make the HTML world carry its own browser policy with `<meta
  http-equiv="Content-Security-Policy" ...>`. HTML is already a web app; the
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

## Python SDK

The Python SDK is the primary SDK for this line.

It is a nicer curl. It does not add a second protocol. Its job is glue:
starting the local core, writing bytes, reading bytes, listening for changes,
and connecting Elastik to CLI tools, AI workers, tests, and small local
automation.

Other SDKs are roadmap until the HTTP surface settles:

| SDK | Status | Why |
|---|---|---|
| Python | primary | Best glue language for local agents, CLI wrappers, tests, and `@listen`. |
| Go | roadmap | Good for single-binary sidecars and distribution. |
| Rust | roadmap | Good for embedding close to the core once the ABI stops moving. |
| JavaScript package | mostly unnecessary | Browsers already speak HTTP. Use HTML tags, `fetch`, and `EventSource`; add a tiny app-local helper only when it buys clarity. |

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

When code is useful, the JavaScript surface is intentionally tiny:

```js
const e = {
  put: (path, body, headers = {}) => fetch(path, { method: "PUT", body, headers }),
  get: (path) => fetch(path).then((r) => r.arrayBuffer()),
  del: (path) => fetch(path, { method: "DELETE" }),
  listen: (pattern) => new EventSource(`/listen/${pattern}`),
};
```

That is not a new protocol. It is just HTTP from JavaScript. Python needs a
larger SDK because Python does not include a browser. Browsers do.

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
# prints: debug panel: http://127.0.0.1:3105/tmp/debug-panel.html

e.put("/home/note", "hello")
print(e.debug_history[-1])
print(e.debug_stats())
```

Levels are borrowed from the usual Python debugging instincts:

- `level="all"` records every request.
- `level="slow"` records slow requests and 4xx/5xx responses.
- `level="errors"` records only 4xx/5xx responses.
- `level="off"` disables the sink.

`verbose=0/1/2/3` maps to errors/slow/all/all-with-redacted-headers. A hook can
observe each request without changing normal control flow:

```python
def alert(method, path, status, ms, rid):
    if ms > 200:
        print(f"slow request {rid}: {method} {path} {ms:.0f}ms")

e.enable_debug(level="all", hook=alert, break_on=412)
```

The default sink is `/tmp/debug/requests`, with convenience mirrors for
`/tmp/debug/errors` and `/tmp/debug/slow`. Debug writes are best-effort and do
not recursively log themselves. Because `/tmp` is memory-backed, these records
are supposed to disappear when the core restarts.

`panel=True` is the default. It writes a tiny HTML panel to
`/tmp/debug-panel.html`. The panel uses `/listen/tmp/debug/requests` only as a
wakeup signal, then reads `/tmp/debug/requests` over normal `GET`, preserving
the core rule that SSE events are control-plane only and do not embed bodies.
If your core requires read auth, your browser still needs to send the same
Bearer token, for example through a header extension during local debugging.

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
