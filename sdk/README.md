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

## Source Checkout

```powershell
git clone https://github.com/rangersui/Elastik
cd Elastik
python -m pip install -e .\sdk
python -m elastik run --key dev-hmac-key --read-token read-token --token write-token --approve-token approve-token
```
