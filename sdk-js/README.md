# @elastikjs/client

> **fetch is all you need.**
> Six verbs. One import. Zero dependencies.

JavaScript SDK for the [Elastik V6 Engine](https://github.com/rangersui/Elastik) HTTP byte
store. Works in any environment that has `fetch` — browser, Node 18+, Deno, Bun, Cloudflare
Workers, Vercel Edge, you name it.

```js
import { Elastik } from "@elastikjs/client";

const e = new Elastik("http://127.0.0.1:3105", { token: "write-token" });

await e.put("home/note", "hello");
const body = await e.get("home/note");          // → "hello"
const meta = await e.head("home/note");         // → { etag, contentType, size, headers }
```

**Or, in Node, with no running core:**

```js
import { Elastik } from "@elastikjs/client/start";

// Spawns the bundled Rust core, picks a free port, returns a connected client.
const e = await Elastik.start({
    writeToken: "w",
    readToken: "r",
    approveToken: "a",
});

await e.put("home/note", "hello");
console.log(await e.get("home/note"));   // "hello"

await e.stop();   // kills the process, wipes the temp data dir
```

The `npm install` shipped a Rust binary too. You didn't notice. That's the
point.

The SDK does not invent new patterns. It uses what JavaScript already gives you:

| What you want | Native primitive |
| --- | --- |
| Transport          | `fetch`           |
| Async result       | `Promise`         |
| Subscribe to events| `callback`        |
| Cancel a request   | `AbortController` |
| Stream body        | `ReadableStream`  |

If a JS dev has read the MDN docs for those five things, they already know this SDK.

## Install

```bash
npm install @elastikjs/client
```

(Browser: import directly via ESM; no build step needed.)

## How `Elastik.start()` works (the Rust under the hood)

`@elastikjs/client` ships a JavaScript SDK *and* a Rust HTTP engine. You only
ever talk to the JavaScript part. The Rust part runs in the background.

```
npm install @elastikjs/client
        │
        ├─ @elastikjs/client                  (the SDK you import)
        ├─ @elastikjs/core-${platform}-${arch} (the Rust binary; only your
        │                                       platform's package installs;
        │                                       the others fail silently
        │                                       because they're optional)
        ↓
import { Elastik } from "@elastikjs/client/start"
const e = await Elastik.start({...})
        │
        ├─ resolveBinary()  → require.resolve("@elastikjs/core-${plat}-${arch}")
        ├─ spawn the binary on a free OS-assigned port
        ├─ wait until /proc/version answers
        └─ return a connected Elastik client (this SDK) bound to it
        ↓
await e.put("note", "hello")     // SDK sends PUT to the spawned core (HTTP)
await e.get("note")              // SDK sends GET (HTTP)
        ↓
await e.stop()                   // kill the process, wipe the temp data dir
```

The SDK and the core communicate over HTTP. The SDK is `fetch`-wrapped over
the core's HTTP surface — including when they live in the same process tree.
**HTTP is all you need, even between the SDK and its embedded core.**

### Supported platforms (npm install)

| Platform | npm package |
| --- | --- |
| `linux-x64`     | `@elastikjs/core-linux-x64`    |
| `linux-arm64`   | `@elastikjs/core-linux-arm64`  |
| `darwin-arm64`  | `@elastikjs/core-darwin-arm64` |
| `win32-x64`     | `@elastikjs/core-win32-x64`    |

The npm matrix matches the Rust core's release matrix
([Elastik v6.4.3](https://github.com/rangersui/Elastik/releases/tag/v6.4.3)).
Linux binaries are statically linked against musl libc for distro
compatibility. `darwin-x64` is intentionally not in the matrix (Apple
Silicon only on the Mac side).

If `start()` runs on a platform we don't ship, it throws `NoBinaryError`
with a list of workarounds: `pip install elastik`, `cargo build --release`,
or `npx @elastikjs/server@<exact>` for the slow-but-pure-JS educational
core.

### Browser users: `start()` is not for you

`@elastikjs/client/start` is Node-only. The package's `exports` map points
the `browser` condition at `false`, so bundlers (Vite, webpack, Rollup,
esbuild) do not try to follow `node:child_process` and friends through to a
browser bundle. If your build tool warns about this, add an explicit
external for `@elastikjs/client/start` — but normally you don't import it
from a browser entry point at all.

In a browser, you connect to a remote core:

```js
import { Elastik } from "@elastikjs/client";
const e = new Elastik("https://your-elastik-core.example.com", { ... });
```

The `start.mjs` machinery is silently absent from your bundle.

---

## API

### `new Elastik(url, options?)`

```js
const e = new Elastik("http://127.0.0.1:3105", {
    token: "write-token",            // default Authorization (write tier)
    readToken: "read-token",         // optional separate read token
    approveToken: "approve-token",   // optional approve token (DELETE / system writes)
    fetch: customFetch,              // optional fetch impl (testing / polyfills)
});
```

- `token` is the write token; it falls through to read and approve if those aren't set.
- `readToken` overrides for `GET` / `HEAD` / `listen`.
- `approveToken` overrides for `DELETE` and writes to system worlds.

### `await e.put(path, body, options?)` → `{ etag, status }`

Replace bytes at `path`. Status is `201 Created` for new worlds, `200 OK` for replacements.

```js
await e.put("home/note", "hello");
await e.put("home/img.png", pngBuffer);                        // ← auto MIME from .png
await e.put("home/note", "v2", { etag: previousEtag });        // If-Match
await e.put("home/note", "first", { ifNoneMatch: "*" });       // create-only
await e.put("home/note", body, { signal: controller.signal }); // cancellable
await e.put("home/note", body, { headers: { "X-Meta-Author": "ranger" } });
```

`body` accepts: `string`, `ArrayBuffer`, `TypedArray`, `Blob`, `ReadableStream` — anything
`fetch` accepts.

#### Automatic Content-Type from path extension

Browsers refuse to execute scripts served as `text/plain`, decode wrong-MIME images
as garbage, and reject `text/plain` stylesheets in strict mode. So when the path has a
recognized extension and you don't pass `contentType`, the SDK fills it in:

```js
await e.put("site/index.html", html);  // → Content-Type: text/html; charset=utf-8
await e.put("site/style.css", css);    // → Content-Type: text/css; charset=utf-8
await e.put("site/app.js", js);        // → Content-Type: application/javascript; charset=utf-8
await e.put("site/logo.png", buf);     // → Content-Type: image/png
await e.put("home/note", "hi");        // → no auto (no extension); fetch picks default
```

Recognized: `.html .htm .css .js .mjs .cjs .json .xml .txt .md .csv .yaml .yml .toml`,
`.png .jpg .jpeg .gif .webp .avif .svg .ico .bmp`,
`.mp3 .wav .ogg .flac .mp4 .webm .mov`,
`.woff .woff2 .ttf .otf`, `.pdf .zip .gz .tar .wasm .map`.

**Explicit `options.contentType` always wins.** Pass it to override.

The Python SDK doesn't do this. Python users live in terminals; their consumers are
curl scripts that don't care about MIME. JS users live in browsers; theirs do.

#### Browser-policy shortcuts — your bytes carry their own browser policy

The killer use of elastik's header persistence: **the data's author declares the
browser policy at write time.** No nginx. No proxy. No runtime config. Every
subsequent `GET` re-emits the stored headers; the browser obeys them.

```js
// Serve an HTML page with a full security/cache/SEO policy attached:
await e.put("site/index.html", html, {
    csp:            "default-src 'self'; script-src 'self'",
    frameOptions:   "DENY",
    cors:           true,
    cache:          "public, max-age=3600",
    referrerPolicy: "no-referrer",
    robots:         "noindex, nofollow",
});
```

One PUT. Bytes + content-type + CSP + frame policy + CORS + cache hint + privacy +
SEO. The browser sees the full bouquet on the next GET. No `nginx.conf`, no
deployment indirection.

**The full shortcut shelf:**

| Option | Header it expands to | Purpose |
| --- | --- | --- |
| `cors`            | `Access-Control-Allow-*` family | who can fetch this cross-origin |
| `csp`             | `Content-Security-Policy`          | what this page can load/run |
| `cspReportOnly`   | `Content-Security-Policy-Report-Only` | CSP without enforcement |
| `frameOptions`    | `X-Frame-Options`                  | iframe embedding policy |
| `coop`            | `Cross-Origin-Opener-Policy`       | window opener isolation |
| `coep`            | `Cross-Origin-Embedder-Policy`     | embedded resource policy |
| `corp`            | `Cross-Origin-Resource-Policy`     | who can load this resource |
| `cache`           | `Cache-Control`                    | browser/CDN caching |
| `expires`         | `Expires` (Date or string)         | absolute expiration |
| `disposition`     | `Content-Disposition`              | inline vs attachment + filename |
| `language`        | `Content-Language`                 | i18n hint |
| `encoding`        | `Content-Encoding`                 | pre-compressed body (gzip/br) |
| `referrerPolicy`  | `Referrer-Policy`                  | what Referer to send on links |
| `robots`          | `X-Robots-Tag`                     | search-engine indexing |

**`cors`** specifically can be a boolean or an object:

```js
// Public CORS shortcut.
await e.put("api/data.json", body, { cors: true });
// → ACAO: *, ACAM: GET HEAD OPTIONS, ACEH: ETag Content-Type Content-Length

// Precise CORS.
await e.put("api/data.json", body, {
    cors: {
        origin: "https://mysite.com",
        methods: ["GET", "HEAD"],
        allowHeaders: "Content-Type",
        exposeHeaders: ["ETag", "X-Meta-Version"],
        credentials: true,
        maxAge: 600,
    },
});
```

**`options.headers` always wins on collision:** if you want the shortcut for
everything except one field, set the shortcut and override the one:

```js
await e.put("api/data.json", body, {
    cors: true,
    headers: { "Access-Control-Allow-Origin": "https://mysite.com" },  // overrides "*"
});
```

Why this is in the JS SDK and not the Python SDK: Python users don't serve
browsers. JS users do. CORS, CSP, MIME — these are the browser's law, not the
core's job. The core just preserves what you stored. The SDK packages it into
options that read like the policies they describe.

#### Self-hosted static site, in three PUTs

```js
import { Elastik } from "@elastikjs/client";
const e = new Elastik("http://127.0.0.1:3105", { token: "w" });

await e.put("site/index.html", html, {
    csp: "default-src 'self'",
    frameOptions: "DENY",
    cache: "no-cache",
});
await e.put("site/style.css", css, { cache: "public, max-age=86400" });
await e.put("site/app.js",    js,  { cache: "public, max-age=86400" });

// Then visit http://127.0.0.1:3105/home/site/index.html in any browser.
// Same-origin → CORS not needed. Browser respects the CSP. CSS/JS execute
// because their auto-detected MIME types are correct.
```

## "I installed a JavaScript library and got a Rust HTTP engine"

`npm install @elastikjs/client` lands a JavaScript SDK plus a Rust binary on
your disk. Most users never realize. esbuild does the same thing with Go;
swc, turbo, and sharp do it with Rust. Frontend developers run native
binaries every day; the language they read is JavaScript; the language
doing the work is not.

| Audience | Install command | What they think they got | What they actually got |
| --- | --- | --- | --- |
| Python | `pip install elastik`              | a Python package          | a Python wrapper + a Rust binary |
| JavaScript | `npm install @elastikjs/client` | a JS library              | a fetch wrapper + a Rust binary |
| Rust | `cargo install elastik-core`         | a Rust binary             | a Rust binary (the only honest one) |

Three languages. Three package managers. **Same Rust binary** at the
bottom. Most users don't know it's Rust, and don't need to.

curl is all you need.        ← external interface
fetch is all you need.        ← from JavaScript
npm install is all you need. ← from a Node project
Rust is all you need.        ← but nobody needs to know.

## elastik *is* your frontend dev environment

You didn't sign up for this. elastik didn't either. But once you have a running
core, you discover that you've accidentally shipped:

- a static file server (PUT html/css/js, browse same-origin)
- a JSON mock server (PUT data, frontend `fetch`'s it, no proxy)
- a build-tool-free dev loop (overwrite a PUT, refresh)
- live-reload (subscribe to `listen("home/site/*")`, `location.reload()`)

All from one binary, on one port. No webpack, no vite, no `dev-server.config.js`,
no `proxy:` block, no separate mock server, no CORS workarounds.

### The painful way (you know this dance)

```
localhost:3000  →  webpack dev server (frontend)
localhost:8080  →  backend / API
localhost:9090  →  mock server
                    + proxy.config.js to forward /api to backend
                    + cors-proxy to bypass cross-origin
                    + when mock data drifts from real data, rewrite the mocks
                    + crash
```

### The elastik way

```bash
# bootstrap a dev env in three curl calls
curl -X PUT localhost:3105/home/app.html  --data-binary @app.html
curl -X PUT localhost:3105/home/app.js    --data-binary @app.js
curl -X PUT localhost:3105/home/api/users -d '[{"name":"Ada"}]' \
     -H "Content-Type: application/json"

# open
open http://localhost:3105/home/app.html
```

Same port. Same origin. The frontend `fetch("/home/api/users")` works because
nothing is cross-origin. Your "mock data" *is* the data — when the backend ships,
swap the PUT and nothing on the frontend changes.

### Iterate without restarting anything

```js
// edit code → re-PUT → refresh
await e.put("app.js", newCode);
location.reload();

// edit mock data → re-PUT → refresh
await e.put("api/users", newUsers);
location.reload();
```

### Five-line live reload

```js
// In your dev page:
e.listen("home/app/*", () => location.reload());
// Now any PUT under /home/app/* triggers a browser refresh.
// Run a file-watcher that PUTs on save → instant HMR-equivalent.
```

That is the whole hot-reload story. Five lines. No webpack-dev-server, no
chokidar tree, no module replacement protocol — just SSE you already had.

### How this README got tested

The browser tests for this very SDK ran like this:

```
1. PUT /home/sdk/index.mjs   (the SDK source, served as application/javascript)
2. PUT /home/sdk/test.html   (the test page, served as text/html)
3. open http://localhost:33206/home/sdk/test.html?url=http://localhost:33206&...
4. The page imports the SDK from the same origin, makes 19 fetch/listen calls,
   reports ✅ 19/19.
```

No webpack. No dev server. No CORS configuration. The elastik core was the dev
server. It's currently sitting in `19/19 ✅` in a real Chromium next to me.

elastik wasn't designed to be a frontend dev environment. It was designed to
be an HTTP-shaped disk. Those turn out to be the same thing when you give the
disk MIME-type sense, header persistence, and SSE.

### What if you can't be same-origin? Make CORS part of the data.

Your real frontend lives on `localhost:3000` (Vite, Next, whatever) and you
need a backend mock at a different port. CORS would normally be a
proxy-config nightmare. Instead, store the CORS policy ON the mock:

```js
// In a tiny dev script — runs once, dies:
import { Elastik } from "@elastikjs/client";
const e = new Elastik("http://localhost:3105", { token: "w" });

await e.put("api/users", JSON.stringify(users), {
    cors: { origin: "http://localhost:3000", methods: "GET, HEAD" },
});
await e.put("api/posts", JSON.stringify(posts), {
    cors: { origin: "http://localhost:3000" },
});
```

Now your frontend can `fetch("http://localhost:3105/home/api/users")`
cross-origin and the browser will accept the response — because the response
itself carries `Access-Control-Allow-Origin: http://localhost:3000`. The CORS
policy is **part of the mock**, not a config file somewhere else.

When the dev session ends:

```bash
^C        # stop the elastik core
rm -rf ./data    # mock data is gone
```

No `mocks/` folder lingering in `git status`. No `webpack.config.js` to
revert. Nothing to clean up. The dev environment was a directory; deleting it
deletes the dev environment.

### Born-deprecated. Used-once. Deleted.

elastik shines hardest when you don't install it:

```bash
# Spin up a temp debug server with one command:
npx @elastikjs/server@6.4.1-edu.0

# Use it. PUT data, hit it from the frontend.

# Ctrl+C, rm -rf ./data, walk away.
# Even the package gets garbage-collected from npx's cache eventually.
```

`@elastikjs/server` ships **born-deprecated** — the npm prerelease tag
`-edu.0` is exactly so a casual `npm install` can't pull it in (npm refuses
prereleases by default). The intended way to consume it is:

- read it on GitHub, OR
- `npx @elastikjs/server@<exact>` for a transient debug server, then walk away.

Born-deprecated. Used once. Deleted. Truly elastik.

> The educational implementation's lifetime: one curl, one PUT, one debug
> session. Then `rm -rf data/`, then `npx`'s cache forgets it. The package
> never accumulates production weight because production already has two
> paths — `pip install elastik` (Python) and `npm install @elastikjs/client`
> (JavaScript). Both ship the same Rust binary; the educational JS port
> is for the moments when you don't want to install anything at all.

### `await e.get(path, options?)` → body | meta object | null

Default: returns the body as a `string` (when Content-Type is text-ish) or an
`ArrayBuffer` (otherwise).

```js
const text  = await e.get("home/note");                       // → "hello"
const bytes = await e.get("home/img.png");                    // → ArrayBuffer

// Conditional read — null on 304
const cached = await e.get("home/note", { ifNoneMatch: etag });

// Range — returns the meta object so you can read Content-Range
const slice = await e.get("home/big.bin", { range: "0-1023" });
// → { body, etag, contentType, size, contentRange: "bytes 0-1023/...", status: 206 }

// Full meta on a normal read
const m = await e.get("home/note", { meta: true });
// → { body, etag, contentType, size, contentRange: null, status: 200 }
```

### `await e.head(path, options?)` → `{ etag, contentType, size, headers }`

Same metadata as GET, no body.

```js
const head = await e.head("home/note");
console.log(head.etag);           // "\"hmac-...\""
console.log(head.size);           // 5
console.log(head.headers);        // raw lower-cased header map
```

### `await e.post(path, body, options?)` → `{ etag, status }`

Append bytes. Does not change Content-Type or X-Meta-* (PUT owns metadata).

```js
await e.put("home/log", "line 1\n", { contentType: "text/plain" });
await e.post("home/log", "line 2\n");
await e.post("home/log", "line 3\n");
// GET → "line 1\nline 2\nline 3\n"
```

### `await e.delete(path, options?)` → `{ status }`

Requires the approve token. Returns `204 No Content` on success.

```js
await e.delete("home/note");
await e.delete("home/note", { etag: currentEtag });   // If-Match
```

### `e.listen(pattern, callback, options?)` → unsubscribe function

Subscribe to Server-Sent Events from `/listen/<pattern>`. The callback receives one event
per write that matches.

```js
const unsub = e.listen("home/task/*", (ev) => {
    if (ev.type === "error") {
        console.error(ev.error);
        return;
    }
    console.log(ev.method, ev.path, ev.etag);
    // → "PUT /home/task/123 hmac-..."
});

// Later:
unsub();
```

Event shape:

```js
{
    type:   "put" | "post" | "delete" | "lag" | "message" | "error",
    id:     "42",
    path:   "/home/task/123",
    method: "PUT",
    etag:   "hmac-...",
    data:   "path: /home/task/123\nmethod: PUT\netag: hmac-...",  // raw multi-line, rarely needed
}
```

Resume after a disconnect by passing `lastEventId`:

```js
e.listen("home/*", cb, { lastEventId: lastSeenId });
```

The stream is control-plane only — **the body of each write is NOT included in the event**.
If you need the bytes, follow up with `e.get(ev.path)`.

### Convenience

```js
await e.exists("home/note");   // → boolean (HEAD → 200 vs 404)
await e.version();             // → "elastik-core 6.4.3 (rust)\n"
await e.worlds();              // → "home/note\nhome/log\n..."
```

## Errors

Every non-2xx HTTP status throws `ElastikError`:

```js
import { Elastik, ElastikError } from "@elastikjs/client";

try {
    await e.put("etc/sysconfig", "x");   // requires approve
} catch (err) {
    if (err instanceof ElastikError) {
        console.log(err.status);      // 401
        console.log(err.statusText);  // "Unauthorized"
        console.log(err.path);        // "etc/sysconfig"
        console.log(err.body);        // "auth required: …"
    }
}
```

The SDK does NOT translate to other exception types or wrap things in `Error`. The
status code IS the answer; the SDK preserves it verbatim.

## Cancellation

Pass a standard `AbortSignal`:

```js
const controller = new AbortController();
const slow = e.get("home/big.bin", { signal: controller.signal });
controller.abort();   // → slow throws AbortError
```

`listen()` accepts a signal too; aborting it tears down the SSE stream.

## What this SDK is NOT

- No cache. (Add one if you need one.)
- No retry / exponential backoff. (Add one if you need one.)
- No queue / batch. (You don't.)
- No connection pool. (`fetch` handles that.)
- No JSON envelope. (Status code = result. Body = bytes.)

If you want any of the above, wrap the SDK. It's ~280 lines of straightforward fetch calls.

## Browser caveats

The browser is hostile territory. The SDK works there — verified in a real Chrome
running this exact `index.mjs` against an `@elastikjs/server` core (19/19 same-origin).
But you should know what you're walking into.

### 1. Cross-origin needs CORS — the elastik core does not provide it

`Authorization: Bearer …` is a "non-simple" header. Cross-origin browser fetch with it
triggers an `OPTIONS` preflight; the elastik core answers `OPTIONS` but does NOT send
`Access-Control-Allow-Origin` / `Access-Control-Allow-Headers`. The browser will block.
This is intentional on the core's part — CORS is browser policy, not disk policy.

**Solutions, pick one:**

- **Same-origin** (cleanest): serve your app from the elastik core itself. PUT your
  `index.html` and JS bundles into `home/...`, then visit `http://core/home/index.html`.
  The same-origin model trivially passes; we ship a working example as `browser-smoke.html`.
- **Reverse proxy**: front the core with nginx / Caddy / Cloudflare and add CORS
  headers there. The core stays a byte store; the proxy speaks browser politics.
- **Same machine, NOT mixed names**: `localhost` and `127.0.0.1` are *different* origins
  to the browser. Pick one and use it everywhere.

### 2. SSE: the SDK uses `fetch`+`ReadableStream`, not `EventSource`

Native `EventSource` cannot set `Authorization` headers — there is no API for it.
If `ELASTIK_READ_TOKEN` is set on the core, `EventSource` would always 401.

This SDK's `e.listen()` uses `fetch` with a streaming response body and a manual
SSE decoder. That gives us auth headers, AbortController cancellation, and works
identically in browsers and Node. The cost is ~50 lines of SSE parsing; the gain is
auth that actually works.

### 3. PUT bodies: prefer `string` / `ArrayBuffer` / `Uint8Array` / `Blob`

`fetch` accepts `ReadableStream` as a request body, but **only in Chrome 105+**.
Firefox and Safari still don't support uploading streams (as of late 2025). If your
SDK call is `e.put(path, readableStream)` and the user runs Firefox, the upload will
fail.

The SDK accepts whatever `fetch` accepts on a given runtime. For cross-browser
portability, materialize large bodies as `Blob` or `Uint8Array` before PUTing.

### 4. The browser adds ~20 headers you don't control

When the browser sends a PUT, it tags on `User-Agent`, `Accept`, `Accept-Language`,
`Accept-Encoding`, `Sec-Fetch-Dest`, `Sec-Fetch-Mode`, `Sec-Fetch-Site`, `Sec-CH-UA*`,
`Origin`, `Referer`, `Connection`, and more. The SDK can't strip them.

You don't need to do anything — the elastik core's never-persist blacklist already
filters these out on the server side. They reach the wire but are not stored.

The corollary: this SDK does NOT add vanity headers (`X-SDK-Version`,
`X-Client-Type`, …) on top of what fetch already sends. Every byte added is a byte
the core has to ignore. We send only what's required: `Authorization`, the user's
`Content-Type`, conditional headers (`If-Match` / `If-None-Match` / `Range`).

### 5. Content-Type — set it explicitly or accept the runtime default

If you pass `body` as a string to `fetch` and DON'T set `Content-Type`, the browser
defaults to `text/plain;charset=UTF-8`. Node's fetch makes the same default. curl
defaults to `application/x-www-form-urlencoded` with `-d`. The SDK forwards your
`options.contentType` if provided and otherwise stays out of the way.

If you care about the stored Content-Type, set it. Don't rely on defaults.

### 6. Extensions exist

Browser extensions can monkey-patch `window.fetch`. AdBlockers, privacy tools, and
the user's own dev extensions all do this. The SDK uses `globalThis.fetch` at
construction time — whatever's installed wins. Don't write code that breaks if
fetch behaves slightly differently. Keep it standard.

If you need an unmodified fetch (e.g., for a security-sensitive call), pass your
own via `options.fetch`.

## Example: a tiny pub/sub

```js
import { Elastik } from "@elastikjs/client";
const e = new Elastik("http://127.0.0.1:3105", { token: "w" });

// Worker: process tasks
e.listen("home/task/*", async (ev) => {
    if (ev.type !== "put") return;
    const body = await e.get(ev.path);
    const result = await doWork(body);
    const id = ev.path.split("/").pop();
    await e.put(`home/result/${id}`, result);
});

// Client: submit a task
await e.put("home/task/abc", JSON.stringify({ work: "..." }), {
    contentType: "application/json",
});
```

No queue. No broker. No SDK protocol. Just HTTP.

## License

MIT.
