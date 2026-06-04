# elastik Python SDK

Python client and launcher for Elastik L5: the Audi-ted storage engine over HTTP.

The engine is small on purpose: the library has five verbs, while the HTTP
adapter maps them to `PUT`, `GET`, `HEAD`, `POST`, `DELETE`, and `LISTEN`.
The SDK gives that wire surface a Python shape without turning the core into a
framework.

The beginner surface in one breath:

```python
import secrets
import elastik

e = elastik.start(key=secrets.token_hex(32), write_token="write-token")
e.put("note", "hello")
print(e.get("note"))       # b"hello"
print(e.get_text("note"))  # hello
print(e.head("note"))      # lowercased HTTP headers
elastik.stop()
```

No hidden object model: `put()` replaces bytes, `post()` appends bytes,
`get()` returns bytes, and `head()` returns headers.

## API At A Glance

| Want to... | Use |
|---|---|
| Store/load bytes | `e.put(path, data)`, `e.get(path)` |
| Store/load text or JSON | `e.put_text` / `e.get_text`, `e.put_json` / `e.get_json` |
| Use dict style | `e["note"] = b"hello"`, `del e["note"]`, `"note" in e` |
| Stream a big read | `e.open(path)` (read-only file-like, Range-backed) |
| Use pathlib style | `e / "home" / "note"` (`WorldRef`) |
| Browse virtual directories | `e.ls("home")`, `e.tree("home")`, `ref.iterdir()` |
| Move/delete prefixes | `e.mv(src, dst)`, `e.rm(prefix, recursive=True)` |
| Read several paths | `e.get_many([...])` (concurrent HTTP requests) |
| Watch changes | `@elastik.listen(pattern)` + `elastik.run(e)` |
| Inspect metadata | `e.head`, `e.checksum`, `e.preview`, `e.diff` |
| Use scratch space | `with e.tmp() as path:` |
| Drop to raw HTTP | `e.request(method, path, headers=...)` |
| Send one UDP-curl packet | `CoapClient`, `python -m elastik coap` |

Prefer `e.put(...)` instance methods in libraries, tests, and long-running
tools where client lifecycle should be explicit. Use module-level
`elastik.put(...)` in scripts and notebooks with exactly one core per process.

## Path Contracts

Elastik apps can be coordinated by path names instead of API schemas.

```js
// Frontend writes input and listens for output.
await fetch("/home/order/123", {
  method: "PUT",
  body: JSON.stringify({ sku: "tea", qty: 2 }),
  headers: { "Content-Type": "application/json" },
});

new EventSource("/listen/home/receipt/*");
```

```python
# Business worker owns the workflow.
import elastik

@elastik.listen("/home/order/*")
def on_order(body, path, e):
    order_id = path.rsplit("/", 1)[-1]
    e.put_json(f"/home/receipt/{order_id}", {"status": "accepted"})

elastik.run()
```

The shared contract is only:

```text
/home/order/{id}
/home/receipt/{id}
```

Use curl to inspect either side of the handoff:

```powershell
curl.exe http://127.0.0.1:3105/home/order/123
curl.exe http://127.0.0.1:3105/home/receipt/123
```

In a source checkout, runnable examples live in `sdk/examples/`:

```powershell
python sdk/examples/01_basic.py
python sdk/examples/02_listener.py
python sdk/examples/03_metadata_and_etag.py
```

## Install

```powershell
py -m pip install elastik
```

The package ships a platform-specific `elastik-core` binary in
`elastik/_bin/`. No compile-on-install.

PyPI wheels are the normal install path. If your platform does not have a
wheel yet, build the Rust core from source and use an editable checkout.

## Starting A Core

You have two normal choices.

### 1. Start from Python

Use this in scripts, tests, notebooks, and local tools:

```python
import secrets
import elastik

e = elastik.start(
    key=secrets.token_hex(32),   # required HMAC key for the audit chain
    read_token="read-token",     # optional: omit for public reads
    write_token="write-token",   # optional: ordinary PUT/POST
    approve_token="admin-token", # optional: DELETE and protected namespaces
)
```

`read-token`, `write-token`, `admin-token`, and `dev-hmac-key` in these examples
are local placeholders only. Elastik does not ship with those credentials. Use
fresh per-deployment secrets outside throwaway demos.

Python kwargs use underscores (`read_token`). CLI flags use hyphens
(`--read-token`).

### 2. Start from a terminal

Use this when you want a long-running local service:

```powershell
py -m elastik run --key dev-hmac-key --read-token read-token --write-token write-token --approve-token admin-token
```

Then connect from another process:

```python
from elastik import Elastik

e = Elastik("http://127.0.0.1:3105", bearer_token="write-token")
```

Module-level `elastik.put/get/...` calls require either a prior
`elastik.start(...)` or explicit environment like `ELASTIK_URL` and
`ELASTIK_WRITE_TOKEN`. They do not silently assume that an unknown process on
`127.0.0.1:3105` is yours.

## Tokens

- `read_token`: gates `GET`, `HEAD`, `/listen/*`, and read-only `/proc/*`
  requests such as `/proc/worlds`, `/proc/du`, `/proc/df`, `/proc/pool`, and
  `/proc/audit/<world>/verify`. `OPTIONS` is policy-free.
- `write_token`: ordinary write token for `PUT` and `POST`.
- `approve_token`: admin token for `DELETE` and protected namespaces
  (`etc/`, `lib/`, `boot/`, `usr/`, `var/log/`). Non-log `var/` uses the
  ordinary write token.

If `read_token` is omitted, reads are public. If `write_token` is omitted,
ordinary writes are disabled. If `approve_token` is omitted, destructive/admin
operations are disabled.

Migration note: `ELASTIK_TOKEN` was the old write-token name. It still works as
a temporary fallback when `ELASTIK_WRITE_TOKEN` is unset, but the SDK warns so
you can rename it.

## CoAP / UDP Helper

The binary can expose an opt-in CoAP/UDP surface when `ELASTIK_COAP_PORT` is
set. The SDK gives humans a small translator so nobody has to hand-type CoAP
bytes:

```powershell
python -m elastik coap put 127.0.0.1 5683 home/sensor/temp "23.5" --token write-token
python -m elastik coap get 127.0.0.1 5683 home/sensor/temp --token read-token
```

Or keep the endpoint once:

```python
from elastik import CoapClient

c = CoapClient("127.0.0.1", 5683, token="write-token")
c.put("home/sensor/temp", "23.5").raise_for_status()
print(c.get("home/sensor/temp").payload)
```

This is not a full RFC 7252 CoAP stack. It is a CoAP-shaped UDP adapter:
one datagram in, one datagram out, `GET`/`PUT`, `Uri-Path`, `Content-Format`,
payload bytes, and response codes. The SDK only advertises `text/plain` and
`application/octet-stream`; JSON/CBOR content formats are intentionally not
part of the no-JSON CoAP surface. It does not implement retransmission,
dedup, Observe, Block-Wise transfer, DTLS/OSCORE, `.well-known/core`, multicast
discovery, `Max-Age`, or strict critical-option handling.

Elastik private option `65001` carries the raw auth token, like a UDP-shaped
`Authorization: Bearer ...`. It is not encryption. Use a CoAP gateway at the
edge if you need full CoAP behavior; use HTTP for reliability or large bodies.
Bodies near 1 KiB or above should use HTTP: the SDK enforces a 1152-byte
datagram limit and rejects oversize `PUT`s with `ValueError` immediately.

## Paths

`"foo"` and `"/foo"` both mean `/home/foo`.

Explicit namespaces are allowed when you want their storage policy:

- `/home/*`: durable SQLite storage.
- `/tmp/*`, `/dev/*`, `/sys/*`: memory-backed storage.
- `/proc/version`, `/proc/worlds`, `/proc/du`, `/proc/df`, `/proc/pool`: core
  introspection endpoints.

Namespace roots like `/home`, `/tmp`, `/lib`, `/etc`, `/var/log`, and `/proc/*`
internals are reserved. Store application data under a child path such as
`/home/myapp/data`.

Concrete mapping:

| Input path | Stored/read path |
|---|---|
| `"note"` | `/home/note` |
| `"/note"` | `/home/note` |
| `"tmp/scratch"` | `/tmp/scratch` |
| `"/tmp/scratch"` | `/tmp/scratch` |
| `"proc/worlds"` | `/proc/worlds` |
| `"proc/pool"` | `/proc/pool` |
| `"proc/audit/home/note/verify"` | `/proc/audit/home/note/verify` |
| `"/proc/unknown"` | rejected |

`list_paths()` is the preferred name. `list_keys()` and the older
`list_worlds()` name remain as aliases; all three read `/proc/worlds`.

```python
print(e.get_text("/proc/version"))  # core version string
print(e.list_paths())               # /proc/worlds, one path per line
```

## Metadata

Standard representation metadata has named arguments:

```python
e.put(
    "report.pdf",
    pdf_bytes,
    content_type="application/pdf",
    content_disposition='attachment; filename="report.pdf"',
    cache_control="max-age=60",
)
```

Extra keyword arguments become plain `X-Meta-*` headers:

```python
e.put("note", "hello", project="demo")
# X-Meta-Project is sent on the wire. Whether it round-trips depends on
# the core's persist policy (see below). On a default v7.2+ core the
# next line raises KeyError unless you start the core with
# ELASTIK_PERSIST_HEADERS=x-meta-* (or pass persist_allow=... to a
# FakeElastik fixture).
assert e.head("note")["x-meta-project"] == "demo"
```

Any safe response header that does not have a named argument can be sent through
`headers=`:

```python
e.put(
    "logo.png",
    png_bytes,
    content_type="image/png",
    headers={"Access-Control-Allow-Origin": "*"},
)
# CORS family is in the built-in default-allow set; no env config needed.
assert e.head("logo.png")["access-control-allow-origin"] == "*"
```

### Persist policy (v7.2+)

The core's persist decision is four layers:

1. **Hard deny** (hardcoded): credentials, hop-by-hop, distributed-tracing
   context (`traceparent` / `x-b3-*` / `x-amzn-*` / `cf-*`), IP-leak
   headers, HTTP/2+3 pseudo-headers, and core-owned response headers
   (`ETag`, `Content-Length`, `Link`, `Allow`, `X-Request-Id`, ...).
   Operators cannot turn this off.
2. **User deny** (`ELASTIK_DENY_HEADERS`): operator subtracts from the
   allow layers below — beats both layer 3 (default allow) and layer 4
   (user allow). Affects future writes only; already-persisted headers
   round-trip until the world is re-`PUT`.
3. **Default allow** (hardcoded): standard representation headers
   (`Content-Disposition` / `Content-Encoding` / `Content-Language` /
   `Content-MD5` / `Cache-Control` / `Expires` / full CORS family /
   CSP / `X-Frame-Options` / `Permissions-Policy` / COEP/COOP/CORP /
   `Referrer-Policy` / `X-Robots-Tag`).
4. **User allow** (`ELASTIK_PERSIST_HEADERS`): operator opts in custom
   names like `X-Author` or `X-Meta-*`.

Default empty layer 4 means **no custom headers round-trip without
configuration**. To restore the v7.1 default for `X-Meta-*`:

```bash
export ELASTIK_PERSIST_HEADERS=x-meta-*
```

`Content-Type` is special: stored as the representation media type, not as
generic persisted metadata. When `X-Meta-*` is allowlisted, durable worlds
audit it as persisted representation metadata (`meta_sha256` / `event_headers`).

The SDK also refuses wire-level headers that `urllib` must compute itself:
`Content-Length`, `Transfer-Encoding`, `Host`, `Connection`, `Keep-Alive`,
`TE`, `Trailer`, `Upgrade`, and `HTTP2-Settings`. Passing those through
`headers=` raises `ValueError` instead of letting a bad length hang the request.

`Authorization` is allowed as an explicit escape hatch. If you pass it in
`headers=`, it takes precedence over the client's `bearer_token`.

## Bytes, Text, JSON

`get()` is byte-exact:

```python
e.put("x", "hello")
assert e.get("x") == b"hello"
```

`get()` raises `ElastikError(404, ...)` when a path is missing. `None` only
means `304 Not Modified` from an `if_none_match` cache check; it never means
"missing".

Use helpers when you want decoding:

```python
e.put_text("note", "hello")
e.put_json("config", {"debug": True})
e.get_text("x")          # str
e.get_json("config")     # parsed JSON
```

`head()` returns a typed header dict (`WorldMeta`) for editor help:

```python
meta = e.head("x")
print(meta["etag"])
print(meta["content-type"])
```

Common `WorldMeta` keys are optional HTTP headers: `etag`, `content-type`,
`content-length`, `content-encoding`, `content-language`,
`content-disposition`, `cache-control`, `accept-ranges`, and `link`.

## Conditional And Partial Reads

The SDK exposes common HTTP controls directly:

```python
etag = e.head("config")["etag"]
e.put("config", b"new", if_match=etag)     # optimistic update
e.put("lock", b"mine", create_only=True)   # If-None-Match: *
chunk = e.get("big.bin", range=(0, 1023))  # Range: bytes=0-1023
```

`if_none_match` is for ETag strings only. Use `create_only=True` for
`If-None-Match: *`.

For anything not sugared, use the raw HTTP escape hatch:

```python
r = e.request("OPTIONS", "note")
print(r.status, r.headers, r.body)
```

## Python Ergonomics

The `elastik-core` binary exposes HTTP; the SDK adds small Python-shaped
conveniences without hiding the wire.

```python
e["note"] = "hello"             # PUT /home/note
assert e["note"] == b"hello"    # GET /home/note
assert "note" in e              # HEAD /home/note
assert e.exists("note")
assert e.sizeof("note") == 5
e.copy("note", "note-copy")      # GET + HEAD + PUT
del e["note"]                   # DELETE /home/note
```

Stored paths are canonicalized to `<namespace>/<rest>` with no leading slash:
`e["src"]`, `e["/src"]`, and `e["home/src"]` all index the same path.
Iteration returns that canonical core form from `/proc/worlds`, such as
`home/src` or `tmp/scratch`.

The core store is flat: `home/sensor/kitchen/temp` is one key, not three real
directories. The SDK gives Python users a virtual hierarchy by splitting paths
on `/`, like `pathlib`, `os`, and `shutil`:

```python
e.ls("home/sensor")              # immediate children; virtual dirs end in /
e.ls("home/sensor", depth=-1)    # all descendants
print(e.tree("home"))
e.du("home/sensor")              # {path: content_length}
e.mv("home/draft", "home/final") # copy+delete; refuses overwrite by default
e.rm("home/old", recursive=True) # refuses "" or namespace roots without force=True
```

`mv()` is copy+delete, not an atomic filesystem rename. Partial failures can
leave source and destination paths side by side. `rm("home", recursive=True)`
and `rm("", recursive=True)` are guarded footguns; pass `force=True` only when
you really mean to delete a namespace or the whole store.

`copy()` buffers the source body in Python memory. That is fine for ordinary
objects; for huge blobs, use a streaming tool or curl pipeline.

`Elastik` implements `collections.abc.MutableMapping[str, bytes]`, so
`update()`, `pop(k, default)`, `setdefault()`, `keys()`, `values()`, and
`items()` work too. Each mapping operation is still one HTTP request; there is
no hidden transaction or batch endpoint.

More stdlib-shaped helpers are thin wrappers over HTTP:

```python
e.get_cached("note")                  # GET + If-None-Match cache
e.checksum("note")                    # HEAD -> ETag
e.is_audited("note")                  # True if ETag is hmac-backed
e.verify("note")                      # HEAD /proc/audit/home/note/verify
e.diff("note", "new text")            # local unified diff
e.preview("note", max_bytes=512)      # Range GET + text preview
e.put_gzip("log.gz", "hello")         # Content-Encoding: gzip
e.put_csv("table.csv", [["t", "v"]])  # text/csv
e.put_struct("dev/s0", ">ff", 1.0, 2.0)
e.get_many(["a", "b"])                # concurrent GETs, no batch endpoint
```

`is_audited()` is only a storage-mode check. It tells you whether the current
ETag is HMAC-backed, not whether the full audit chain has been replayed.
`verify()` asks the core to replay the durable audit chain via
`HEAD /proc/audit/{path}/verify`. It returns `True` only for `200 OK` with
`X-Audit-Valid: true`; memory worlds (`204 No Content`) and broken chains
(`409 Conflict`) return `False`.

`open(path, "rb")` returns a read-only file-like object backed by Range GETs:

```python
with e.open("report.pdf") as f:
    header = f.read(8)
    f.seek(1024)
    chunk = f.read(512)
```

Pathlib-shaped references are available when they make code clearer:

```python
report = e / "home" / "reports" / "q1"
report.write("revenue up")
print(report.read_text())
print(report.stat()["etag"])

for child in (e / "home" / "reports").iterdir():
    print(child.name, child.suffix)

for pdf in (e / "home").rglob("*.pdf"):
    print(pdf.path)
```

Temporary paths are just `/tmp/*` paths with best-effort cleanup:

```python
with e.tmp("scratch") as path:
    e.put(path, "working...")
```

Errors have subclasses when you want precise handling:

```python
try:
    e.get("missing")
except elastik.NotFound:
    print("not there")
except elastik.PreconditionFailed:
    print("etag changed")
```

For bug reports and shell sanity checks:

```python
import elastik
print(elastik.__version__)
elastik.show_config()
```

If you look directly inside the durable `data/` directory, names are percent
encoded because the core stores a flat keyspace safely on Windows and POSIX:

```text
home/note.txt  -> data/home%2Fnote%2Etxt/universe.db
```

Use the ops helpers when you need to translate that layout:

```powershell
python -m elastik decode-path "home%2Fnote%2Etxt"
python -m elastik ls-data .\data
```

## Listening For Changes

`@listen` is optional. Do not call `elastik.run()` unless you registered at
least one handler.

```python
import elastik

e = elastik.start(key="dev-key", write_token="write-token")

@elastik.listen("/home/inbox/*")
def on_inbox(body, path, meta, e):
    if b"urgent" in body:
        e.put("/home/alerts/latest", body)

elastik.run(e)
```

Handler rules:

- The first positional argument is always `body`.
- Extra context is injected by name: `path`, `etag`, `pattern`, `meta`, `e`,
  `method`, and `event`.
- `world` is still accepted as a compatibility alias for `path`.
- You can do normal Python side effects inside the handler.
- Advanced users may return `Reply`, `Archive`, `MoveTo`, or `Drop` action
  objects, but they are not required.

Use `clear_routes()` or `unlisten(pattern)` in tests or notebooks to reset
handler state. Registering the same pattern twice raises unless you use
`listen(pattern, replace=True)`.

`run()` retries forever by default and logs failures to stderr. For supervised
processes, prefer `elastik.run(e, reconnect=False)` and let your supervisor
restart the process. For demos/tests, `max_events=1` runs until one matching
event is handled.

## Environment Loading

`import elastik` loads a local `.env` once and fills only missing environment
variables. Existing process env wins. Set `ELASTIK_NO_DOTENV=1` before import
to disable this, or call `elastik.load_dotenv(path)` explicitly when you want
manual control.

## Advanced Helpers

These are exported but not part of the beginner path:

- `request()`: raw HTTP escape hatch.
- `binary_info()`, `is_running()`, `default_url()`: launcher diagnostics.
- `TrustedShellPool`: warm local shell process pool for trusted `@listen`
  handlers. It can execute arbitrary commands; do not feed it untrusted input.
- `MoveTo`, `Reply`, `Archive`, `Drop`, `Action`, `Ctx`: optional reactor
  action vocabulary.

## Stateless By Default

The SDK intentionally uses one-shot stdlib HTTP requests by default: no
`requests`, no `urllib3`, no connection pool, no hidden keep-alive state.

That is slower than a tuned keep-alive client, but it is boring and hard to
leak. High-frequency callers can use `curl`, `ab -k`, `http.client`, or a custom
transport when they have measured a real bottleneck.

## Testing Without A Core

For unit tests that only need SDK behavior, use the in-memory fake:

```python
from elastik import FakeElastik

e = FakeElastik()
e.put("note", "hello")
assert e.get_text("note") == "hello"
```

`FakeElastik` is not a protocol test. Use the black-box tests or a real
`elastik.start(...)` when you need wire-level HTTP behavior.

## Source Checkout

```powershell
git clone https://github.com/rangersui/Elastik
cd Elastik
python -m pip install -e .\sdk
python -m elastik run --key dev-hmac-key --read-token read-token --write-token write-token --approve-token admin-token
```

For the full project README, see:

<https://github.com/rangersui/Elastik>
