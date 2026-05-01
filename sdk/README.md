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
