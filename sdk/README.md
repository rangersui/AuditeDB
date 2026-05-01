# elastik

Python SDK and launcher for the Phoenix `elastik-core`.

This package is intentionally thin:

- `elastik.start()` launches the bundled Rust core binary.
- `Elastik.put()` writes bytes over HTTP.
- `Elastik.get()` reads bytes over HTTP.
- `Elastik.head()` inspects HTTP metadata.
- `@elastik.listen(...)` reacts to `/listen/*` SSE events.

The package ships a platform-specific `elastik-core` binary in
`elastik/_bin/`. For the full project README, see:

<https://github.com/rangersui/Elastik>

## Install

```powershell
py -m pip install elastik
py -m elastik run --key dev-hmac-key --read-token read-token --token write-token --approve-token approve-token
```

`--key` is required. Token flags are optional capability gates:

- omit `--read-token` to keep reads public.
- omit `--token` to disable ordinary `PUT` and `POST`.
- omit `--approve-token` to disable `DELETE` and system writes.

## Quickstart

```python
import secrets
import elastik

e = elastik.start(
    key=secrets.token_hex(32),   # required HMAC key for the audit chain
    token="write-token",         # ordinary PUT/POST
    approve_token="admin-token", # DELETE and system namespaces
)

e.put("note", "hello", actor="me")  # bare paths map to /home/note
print(e.get_text("note"))           # hello
print(e.get("note"))                # b"hello"

elastik.stop()
```

Module-level `elastik.put/get/...` calls require either a prior
`elastik.start(...)` or explicit environment like `ELASTIK_URL` and
`ELASTIK_TOKEN`. The SDK no longer silently assumes a random process on
`127.0.0.1:3105` is yours.

Extra `put()` keyword arguments become metadata headers:
`actor="me"` is stored as `X-Meta-Actor: me`. Use named arguments for standard
HTTP representation headers: `content_type`, `cache_control`,
`content_encoding`, `content_language`, and `content_disposition`.

Path rule: `"foo"` means `/home/foo`. Explicit `/tmp`, `/dev`, and `/sys`
paths are valid storage namespaces. Namespace roots and `/proc` internals are
reserved by the core.

`elastik.run()` is only for `@elastik.listen(...)` handlers. If you only need
`put/get/head/delete`, do not call it.

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
python -m elastik run --key dev-hmac-key --read-token read-token --token write-token --approve-token approve-token
```
