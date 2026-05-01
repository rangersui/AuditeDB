# elastik Python SDK

Tiny Python client and launcher for `elastik-core`: an HTTP byte store with
metadata and change events.

The beginner surface is five ideas:

```python
import secrets
import elastik

e = elastik.start(key=secrets.token_hex(32), token="write-token")
e.put("note", "hello")
print(e.get("note"))       # b"hello"
print(e.get_text("note"))  # hello
print(e.head("note"))      # lowercased HTTP headers
elastik.stop()
```

No hidden object model: `put()` replaces bytes, `post()` appends bytes,
`get()` returns bytes, and `head()` returns headers.

Runnable examples live in `sdk/examples/`:

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
    token="write-token",         # optional: ordinary PUT/POST
    approve_token="admin-token", # optional: DELETE and system namespaces
)
```

Python kwargs use underscores (`read_token`). CLI flags use hyphens
(`--read-token`).

### 2. Start from a terminal

Use this when you want a long-running local service:

```powershell
py -m elastik run --key dev-hmac-key --read-token read-token --token write-token --approve-token admin-token
```

Then connect from another process:

```python
from elastik import Elastik

e = Elastik("http://127.0.0.1:3105", token="write-token")
```

Module-level `elastik.put/get/...` calls require either a prior
`elastik.start(...)` or explicit environment like `ELASTIK_URL` and
`ELASTIK_TOKEN`. They do not silently assume that an unknown process on
`127.0.0.1:3105` is yours.

## Tokens

- `read_token`: gates `GET`, `HEAD`, `OPTIONS`, `/listen/*`, and `/proc/worlds`.
- `token`: ordinary write token for `PUT` and `POST`.
- `approve_token`: admin token for `DELETE` and system namespaces.

If `read_token` is omitted, reads are public. If `token` is omitted, ordinary
writes are disabled. If `approve_token` is omitted, destructive/admin operations
are disabled.

## Paths

`"foo"` and `"/foo"` both mean `/home/foo`.

Explicit namespaces are allowed when you want their storage policy:

- `/home/*`: durable SQLite storage.
- `/tmp/*`, `/dev/*`, `/sys/*`: memory-backed storage.
- `/proc/version`, `/proc/worlds`: core introspection endpoints.

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
| `"/proc/anything-else"` | rejected |

`list_paths()` and `list_keys()` are aliases for the older `list_worlds()` name.
All three read `/proc/worlds`.

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
assert e.head("note")["x-meta-project"] == "demo"
```

Those `X-Meta-*` fields are just metadata. They do not affect auth, auditing,
or routing unless your own SDK/userland code gives them meaning.

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

## Conditional And Partial Reads

The SDK exposes common HTTP controls directly:

```python
etag = e.head("config")["etag"]
e.put("config", b"new", if_match=etag)     # optimistic update
e.put("lock", b"mine", create_only=True)   # If-None-Match: *
chunk = e.get("big.bin", range=(0, 1023))  # Range: bytes=0-1023
```

The older `if_none_match=True` spelling is accepted for 6.0 compatibility, but
new code should use `create_only=True`.

For anything not sugared, use the raw HTTP escape hatch:

```python
r = e.request("OPTIONS", "note")
print(r.status, r.headers, r.body)
```

## Python Ergonomics

The core is HTTP; the SDK adds small Python-shaped conveniences without hiding
the wire.

```python
e["note"] = "hello"             # PUT /home/note
assert e["note"] == b"hello"    # GET /home/note
assert "note" in e              # HEAD /home/note
del e["note"]                   # DELETE /home/note
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

## Listening For Changes

`@listen` is optional. Do not call `elastik.run()` unless you registered at
least one handler.

```python
import elastik

e = elastik.start(key="dev-key", token="write-token")

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

Use `clear_routes()` or `unlisten(pattern)` in tests/notebooks to reset handler
state. Registering the same pattern twice raises unless you use
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

## Source Checkout

```powershell
git clone https://github.com/rangersui/Elastik
cd Elastik
python -m pip install -e .\sdk
python -m elastik run --key dev-hmac-key --read-token read-token --token write-token --approve-token admin-token
```

For the full project README, see:

<https://github.com/rangersui/Elastik>
