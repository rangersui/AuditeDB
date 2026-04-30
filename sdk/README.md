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
