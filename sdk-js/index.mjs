// @elastikjs/client — fetch is all you need.
//
// Audi-ted L5. One import. Zero dependencies.
//
// The SDK is a thin wrapper around native fetch. It does not invent new
// patterns; it leans on what JS already gives you:
//   - fetch    → the entire transport
//   - Promise  → every method (except listen)
//   - callback → only for listen, because subscribe is callback-shaped
//   - AbortController → cancellation, native, no custom shim
//   - options object → no positional argument soup
//
// Works in: browser, Node 18+, Deno, Bun. Anywhere fetch lives.
// EventSource is NOT used: it can't set Authorization headers, and writing
// a tiny SSE decoder over fetch+ReadableStream is shorter than wrestling it.
//
// What this file is NOT:
//   - a cache. (You add one.)
//   - a retry layer. (You add one.)
//   - a queue. (You add one.)
//   - a JSON envelope. (Status code is the answer. Body is bytes.)
//
// Status code = result. Header = detail. Body = bytes. Same as the core.
//
// Browser quirks worth knowing (see README "Browser caveats" for the full list):
//
//   1. NO VANITY HEADERS. The browser will already attach ~20 of its own
//      (Accept, User-Agent, Sec-Fetch-*, Sec-CH-UA-*, Origin, Referer, …).
//      This SDK adds only what the protocol requires: Authorization,
//      Content-Type (if you pass one), and the conditional/range headers.
//      No X-SDK-Version. No X-Client-Type. Every byte we add is a byte the
//      core has to filter out.
//
//   2. PUT body types. fetch accepts ReadableStream as a request body, but
//      only in Chrome 105+. Firefox and Safari still don't (late 2025).
//      For cross-browser portability, materialize large bodies as Blob or
//      Uint8Array before PUTing. The SDK doesn't validate this — it forwards
//      whatever you pass to fetch — but the failure mode is on you, not us.
//
//   3. SSE uses fetch+ReadableStream, NOT EventSource. EventSource has no
//      way to set Authorization, so it would 401 against any auth-gated
//      core. This implementation gives you auth + AbortController for free.
//
//   4. Cross-origin needs CORS upstream of the core. Same-origin is the
//      cleanest path; serve your app FROM the elastik core if you can.

export class ElastikError extends Error {
    constructor(status, statusText, path, body = "") {
        super(`${status} ${statusText}: ${path}${body ? ` — ${body.slice(0, 120)}` : ""}`);
        this.name = this.constructor.name;
        this.status = status;
        this.statusText = statusText;
        this.path = path;
        this.body = body;
    }
}

export class NotModified extends ElastikError {}
export class Unauthorized extends ElastikError {}
export class Forbidden extends ElastikError {}
export class NotFound extends ElastikError {}
export class PreconditionFailed extends ElastikError {}
export class PayloadTooLarge extends ElastikError {}
export class ServerError extends ElastikError {}
export class InsufficientStorage extends ServerError {}
export class NetworkError extends ElastikError {}

const ERROR_BY_STATUS = Object.freeze({
    304: NotModified,
    401: Unauthorized,
    403: Forbidden,
    404: NotFound,
    412: PreconditionFailed,
    413: PayloadTooLarge,
    507: InsufficientStorage,
});

export class Elastik {
    /**
     * @param {string} url   base URL of the elastik core, e.g. "http://127.0.0.1:3105"
     * @param {object} [options]
     * @param {string} [options.writeToken]    write token (preferred; fallthrough for read/approve)
     * @param {string} [options.token]         deprecated alias for writeToken
     * @param {string} [options.readToken]     read-only token (overrides token for GET/HEAD/listen)
     * @param {string} [options.approveToken]  approve token (DELETE + system writes)
     * @param {Function} [options.fetch]       custom fetch impl (testing, polyfill)
     */
    constructor(url, options = {}) {
        this.url = stripTrailingSlashes(String(url));
        this.writeToken = options.writeToken ?? options.token ?? "";
        this.readToken = options.readToken ?? this.writeToken;
        this.approveToken = options.approveToken ?? this.writeToken;
        // bind() so user can do `const get = e.get`. Native fetch hates being
        // detached from globalThis on some runtimes; bind defensively.
        this.fetch = (options.fetch ?? globalThis.fetch).bind(globalThis);
    }

    static start() {
        throw new Error(
            'Elastik.start() is only available from the Node-only entrypoint. ' +
            'Use: import { Elastik } from "@elastikjs/client/start"'
        );
    }

    // ─── PUT ─────────────────────────────────────────────
    // Replace bytes at path. Returns { etag, status }. 201 = new, 200/204 = replaced.
    // body: string | ArrayBuffer | TypedArray | Blob | ReadableStream
    //
    // Core HTTP options:
    //   contentType   → Content-Type header (passes through verbatim)
    //   etag          → If-Match (conditional update, 412 on stale)
    //   ifNoneMatch   → If-None-Match (use "*" for create-only)
    //   signal        → AbortSignal
    //   headers       → arbitrary extra headers (LAST-WORD; merged after policies)
    //
    // Browser-policy shortcuts (expand to stored response headers; see
    // expandPolicies() for the full mapping):
    //   cors              → Access-Control-Allow-* family
    //   csp               → Content-Security-Policy
    //   cspReportOnly     → Content-Security-Policy-Report-Only
    //   frameOptions      → X-Frame-Options
    //   coop / coep / corp→ Cross-Origin-Opener / Embedder / Resource-Policy
    //   cache             → Cache-Control
    //   expires           → Expires
    //   disposition       → Content-Disposition (inline / attachment; filename=…)
    //   language          → Content-Language
    //   encoding          → Content-Encoding (gzip/br for pre-compressed bytes)
    //   referrerPolicy    → Referrer-Policy
    //   robots            → X-Robots-Tag
    //
    // Auto Content-Type from path extension when caller doesn't set one:
    //   put("site/index.html", html) → Content-Type: text/html; charset=utf-8
    //   put("site/app.js", js)       → Content-Type: application/javascript; charset=utf-8
    //   put("site/logo.png", buf)    → Content-Type: image/png
    //   put("home/note", "hi")       → no auto (path has no recognized extension)
    // Browsers refuse to execute scripts served as text/plain; PNGs decoded as
    // text would be garbage. Python SDK ignores this because curl users set -H
    // themselves; JS SDK runs in browsers, where MIME is law.
    // Explicit options.contentType always wins.
    async put(path, body, options = {}) {
        assertBodyType(body, "put");
        const policy = expandPolicies(options);
        const merged = policy ? { ...policy, ...(options.headers || {}) } : options.headers;
        const headers = this._auth(this._writeTokenForPath(path), merged);
        const ct = options.contentType ?? mimeFromPath(path);
        if (ct) headers["Content-Type"] = ct;
        const ifMatch = options.ifMatch ?? options.etag;
        if (ifMatch) headers["If-Match"] = ifMatch;
        if (options.ifNoneMatch) headers["If-None-Match"] = options.ifNoneMatch;
        const res = await this._fetch(this._url(path), {
            method: "PUT", body, headers, signal: options.signal,
        });
        await this._throwIfError(res, path);
        return { etag: res.headers.get("etag"), status: res.status };
    }

    // ─── GET ─────────────────────────────────────────────
    // Default: returns body (string for text-ish content, ArrayBuffer for binary).
    // options.meta = true       → { body, etag, contentType, size, contentRange }
    // options.range = "0-99"    → byte range (sets Content-Range on meta result)
    // options.ifNoneMatch       → conditional read; throws NotModified on 304
    async putText(path, text, options = {}) {
        return this.put(path, String(text), {
            ...options,
            contentType: options.contentType ?? "text/plain; charset=utf-8",
        });
    }

    async putJson(path, value, options = {}) {
        return this.put(path, JSON.stringify(value), {
            ...options,
            contentType: options.contentType ?? "application/json; charset=utf-8",
        });
    }

    async get(path, options = {}) {
        const headers = this._auth(this.readToken, options.headers);
        if (options.range) headers["Range"] = `bytes=${options.range}`;
        if (options.ifNoneMatch) headers["If-None-Match"] = options.ifNoneMatch;
        if (options.ifMatch) headers["If-Match"] = options.ifMatch;
        const res = await this._fetch(this._url(path), {
            method: "GET", headers, signal: options.signal,
        });
        await this._throwIfError(res, path);
        const contentType = res.headers.get("content-type") || "";
        const body = isTextType(contentType) ? await res.text() : await res.arrayBuffer();
        if (options.meta || options.range) {
            return {
                body,
                etag: res.headers.get("etag"),
                contentType,
                size: numberOrNull(res.headers.get("content-length")),
                contentRange: res.headers.get("content-range"),
                status: res.status,
            };
        }
        return body;
    }

    // ─── HEAD ────────────────────────────────────────────
    // Metadata only. Returns { etag, contentType, size, headers }.
    async getText(path, options = {}) {
        const body = await this.get(path, { ...options, meta: false });
        return typeof body === "string" ? body : new TextDecoder("utf-8").decode(body);
    }

    async getJson(path, options = {}) {
        const text = await this.getText(path, options);
        try {
            return JSON.parse(text);
        } catch (err) {
            let contentType = "";
            try { contentType = (await this.head(path, options)).contentType; } catch { /* best-effort */ }
            throw new TypeError(
                `getJson(${JSON.stringify(path)}): body is not valid JSON` +
                (contentType ? ` (Content-Type: ${contentType})` : "") +
                `: ${err.message}`
            );
        }
    }

    async head(path, options = {}) {
        const headers = this._auth(this.readToken, options.headers);
        const res = await this._fetch(this._url(path), {
            method: "HEAD", headers, signal: options.signal,
        });
        await this._throwIfError(res, path);
        const allHeaders = {};
        res.headers.forEach((v, k) => { allHeaders[k] = v; });
        return {
            etag: res.headers.get("etag"),
            contentType: res.headers.get("content-type"),
            size: numberOrNull(res.headers.get("content-length")),
            headers: allHeaders,
        };
    }

    // ─── POST ────────────────────────────────────────────
    // Append. Does not change Content-Type or X-Meta-* (PUT owns metadata).
    // Returns { etag, status }.
    async post(path, body, options = {}) {
        assertBodyType(body, "post");
        const headers = this._auth(this._writeTokenForPath(path), options.headers);
        const ifMatch = options.ifMatch ?? options.etag;
        if (ifMatch) headers["If-Match"] = ifMatch;
        const res = await this._fetch(this._url(path), {
            method: "POST", body, headers, signal: options.signal,
        });
        await this._throwIfError(res, path);
        return { etag: res.headers.get("etag"), status: res.status };
    }

    // ─── DELETE ──────────────────────────────────────────
    // Requires approve token. Returns { status } (204 on success).
    // options.ifMatch → If-Match (conditional delete, 412 on stale)
    async delete(path, options = {}) {
        const headers = this._auth(this.approveToken, options.headers);
        const ifMatch = options.ifMatch ?? options.etag;
        if (ifMatch) headers["If-Match"] = ifMatch;
        const res = await this._fetch(this._url(path), {
            method: "DELETE", headers, signal: options.signal,
        });
        await this._throwIfError(res, path);
        return { status: res.status };
    }

    async request(method, path, options = {}) {
        assertBodyType(options.body, "request");
        const token = Object.hasOwn(options, "token") ? options.token : this._tokenForRequest(method, path);
        const headers = this._auth(token, options.headers);
        const res = await this._fetch(this._url(path), {
            method,
            body: options.body,
            headers,
            signal: options.signal,
        });
        const body = await res.arrayBuffer();
        return { status: res.status, statusText: res.statusText, headers: res.headers, body };
    }

    // ─── LISTEN ──────────────────────────────────────────
    // Subscribe to /listen/<pattern>. Calls callback(event) for each SSE event.
    // event: { type, id, path, method, etag, data }
    //   type   "put" | "post" | "delete" | "lag" | "message" | "error"
    //   data   raw multi-line data string (rarely needed; structured fields above suffice)
    // Returns: () => void (unsubscribe)
    listen(pattern, callback, options = {}) {
        const controller = new AbortController();
        if (options.signal) {
            // chain user signal into ours
            if (options.signal.aborted) controller.abort();
            else options.signal.addEventListener("abort", () => controller.abort(), { once: true });
        }
        const headers = this._auth(this.readToken, options.headers);
        headers["Accept"] = "text/event-stream";
        if (options.lastEventId != null) headers["Last-Event-ID"] = String(options.lastEventId);

        const cleanPattern = canonicalListenPattern(pattern);
        const url = `${this.url}/listen/${encodePath(cleanPattern)}`;

        // Connect + decode in the background. Errors land in the callback as
        // { type: "error", error }. The returned unsub aborts the fetch.
        (async () => {
            try {
                const res = await this._fetch(url, { headers, signal: controller.signal }, cleanPattern);
                if (!res.ok) {
                    const body = await res.text().catch(() => "");
                    safeCall(callback, { type: "error", error: makeError(res.status, res.statusText, cleanPattern, body) });
                    return;
                }
                if (!res.body) {
                    safeCall(callback, { type: "error", error: new Error("listen: response has no body stream") });
                    return;
                }
                await consumeSSE(res.body, callback, controller.signal);
            } catch (err) {
                if (err && err.name === "AbortError") return;
                safeCall(callback, { type: "error", error: err });
            }
        })();

        return () => controller.abort();
    }

    // ─── Convenience ─────────────────────────────────────
    async exists(path) {
        try { await this.head(path); return true; }
        catch (err) { if (err.status === 404) return false; throw err; }
    }
    async list(prefix = "") {
        const p = canonicalPrefix(prefix);
        const lines = (await this.worlds()).split("\n").filter(Boolean);
        return p ? lines.filter((line) => line === p || line.startsWith(`${p}/`)) : lines;
    }
    async sizeof(path) {
        return (await this.head(path)).size ?? 0;
    }
    async checksum(path) {
        return (await this.head(path)).etag ?? "";
    }
    async isAudited(path) {
        return stripQuotes(await this.checksum(path)).startsWith("hmac-");
    }
    async verify(path) {
        const world = canonicalPath(path);
        const res = await this._fetch(this._url(`/proc/audit/${world}/verify`), {
            method: "HEAD",
            headers: this._auth(this.readToken),
        }, `/proc/audit/${world}/verify`);
        if (res.status === 204) return false;
        await this._throwIfError(res, `/proc/audit/${world}/verify`);
        return res.headers.get("x-audit-valid") === "true";
    }
    async version() { return (await this._textGet("/proc/version")).trim(); }
    async worlds()  { return this._textGet("/proc/worlds"); }

    // ─── internals ───────────────────────────────────────
    _url(path) {
        const cleaned = validateRequestPath(path);
        return `${this.url}/${encodePath(cleaned)}`;
    }
    _writeTokenForPath(path) {
        return needsApproveForWrite(canonicalPath(path)) ? this.approveToken : this.writeToken;
    }
    _tokenForRequest(method, path) {
        switch (String(method || "GET").toUpperCase()) {
        case "GET":
        case "HEAD":
            return this.readToken;
        case "DELETE":
            return this.approveToken;
        case "PUT":
        case "POST":
            return this._writeTokenForPath(path);
        default:
            return this.writeToken;
        }
    }
    _auth(token, extras = {}) {
        const h = { ...(extras || {}) };
        const hasAuthorization = Object.keys(h).some((key) => key.toLowerCase() === "authorization");
        if (token && !hasAuthorization) h["Authorization"] = `Bearer ${token}`;
        return h;
    }
    async _throwIfError(res, path) {
        if (res.ok) return;
        let body = "";
        try { body = await res.text(); } catch { /* ignore */ }
        throw makeError(res.status, res.statusText, path, body);
    }
    async _textGet(path) {
        const res = await this._fetch(`${this.url}${path}`, { headers: this._auth(this.readToken) }, path);
        await this._throwIfError(res, path);
        return await res.text();
    }
    async _fetch(url, init, path = url) {
        try {
            return await this.fetch(url, init);
        } catch (err) {
            if (err?.name === "AbortError") throw err;
            const detail = err?.cause?.code === "ECONNREFUSED"
                ? `cannot reach elastik at ${this.url} — is it running?`
                : `network error: ${err?.message ?? String(err)}`;
            throw new NetworkError(0, "Network Error", path, detail);
        }
    }
}

// ─── helpers (module-private) ────────────────────────────

// Encode a path the way urllib.parse.quote(p, safe="/") does in the Python
// SDK: percent-escape everything except letters/digits/-_.~ and "/".
// encodeURIComponent per segment matches that contract; encodeURI alone
// would leave "?" and "#" un-escaped, which would break paths containing them.
function encodePath(p) {
    return p.split("/").map(encodeURIComponent).join("/");
}

// Browser-aware MIME table. The browser refuses to execute scripts unless
// they're served as application/javascript (or compatible), so getting the
// stored Content-Type right matters at PUT time, not at GET. Same for CSS
// (browsers reject text/plain stylesheets in strict mode), images (decoded
// as wrong MIME → garbage), fonts, JSON, etc.
//
// Curated to the file types people actually serve from a content store. Not
// a full RFC 6838 dump.
const MIME_TYPES = Object.freeze({
    // text
    html: "text/html; charset=utf-8",
    htm:  "text/html; charset=utf-8",
    css:  "text/css; charset=utf-8",
    js:   "application/javascript; charset=utf-8",
    mjs:  "application/javascript; charset=utf-8",
    cjs:  "application/javascript; charset=utf-8",
    json: "application/json; charset=utf-8",
    map:  "application/json; charset=utf-8",
    xml:  "application/xml; charset=utf-8",
    txt:  "text/plain; charset=utf-8",
    md:   "text/markdown; charset=utf-8",
    csv:  "text/csv; charset=utf-8",
    yaml: "application/yaml; charset=utf-8",
    yml:  "application/yaml; charset=utf-8",
    toml: "application/toml; charset=utf-8",
    // images
    png:  "image/png",
    jpg:  "image/jpeg",
    jpeg: "image/jpeg",
    gif:  "image/gif",
    webp: "image/webp",
    avif: "image/avif",
    svg:  "image/svg+xml",
    ico:  "image/x-icon",
    bmp:  "image/bmp",
    // audio / video
    mp3:  "audio/mpeg",
    wav:  "audio/wav",
    ogg:  "audio/ogg",
    flac: "audio/flac",
    mp4:  "video/mp4",
    webm: "video/webm",
    mov:  "video/quicktime",
    // fonts
    woff:  "font/woff",
    woff2: "font/woff2",
    ttf:   "font/ttf",
    otf:   "font/otf",
    // app
    pdf:  "application/pdf",
    zip:  "application/zip",
    gz:   "application/gzip",
    tar:  "application/x-tar",
    wasm: "application/wasm",
});

function mimeFromPath(path) {
    const tail = String(path).split(/[?#]/, 1)[0];
    const dot = tail.lastIndexOf(".");
    const slash = tail.lastIndexOf("/");
    if (dot < 0 || dot < slash) return null;
    const ext = tail.slice(dot + 1).toLowerCase();
    return MIME_TYPES[ext] ?? null;
}

// CORS shortcut. The killer use case for elastik header persistence: store
// the CORS policy on the world itself, at PUT time, by the data's author.
// No nginx, no proxy, no runtime config — the bytes carry their own browser
// policy, the core preserves them, every GET re-emits them.
//
//   options.cors = true                   → public CORS (Origin: *, GET/HEAD/OPTIONS)
//   options.cors = { origin, methods,
//                    allowHeaders,
//                    exposeHeaders,
//                    credentials, maxAge } → precise policy
function expandCors(cors) {
    if (cors == null || cors === false) return null;
    if (cors === true) {
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
            "Access-Control-Expose-Headers": "ETag, Content-Type, Content-Length",
        };
    }
    if (typeof cors !== "object") return null;
    const out = {};
    const list = (v) => Array.isArray(v) ? v.join(", ") : String(v);
    if (cors.origin)        out["Access-Control-Allow-Origin"]   = String(cors.origin);
    if (cors.methods)       out["Access-Control-Allow-Methods"]  = list(cors.methods);
    if (cors.allowHeaders)  out["Access-Control-Allow-Headers"]  = list(cors.allowHeaders);
    if (cors.exposeHeaders) out["Access-Control-Expose-Headers"] = list(cors.exposeHeaders);
    if (cors.credentials)   out["Access-Control-Allow-Credentials"] = "true";
    if (cors.maxAge != null)out["Access-Control-Max-Age"]        = String(cors.maxAge);
    return Object.keys(out).length ? out : null;
}

// Browser-policy shortcuts → stored response headers. The data's author
// declares the browser policy at PUT time; the core preserves the headers;
// every subsequent GET re-emits them. Python SDK doesn't bother with this
// because Python users don't serve browsers. JS SDK is the bridge.
//
// Returns null if no policy options were set, otherwise a header object.
// User-supplied options.headers (when merged after this in put()) always
// wins on collisions.
function expandPolicies(options) {
    const out = {};
    const merge = (extra) => extra && Object.assign(out, extra);

    merge(expandCors(options.cors));
    if (options.csp)            out["Content-Security-Policy"] = options.csp;
    if (options.cspReportOnly)  out["Content-Security-Policy-Report-Only"] = options.cspReportOnly;
    if (options.frameOptions)   out["X-Frame-Options"] = options.frameOptions;
    if (options.coop)           out["Cross-Origin-Opener-Policy"] = options.coop;
    if (options.coep)           out["Cross-Origin-Embedder-Policy"] = options.coep;
    if (options.corp)           out["Cross-Origin-Resource-Policy"] = options.corp;
    if (options.cache)          out["Cache-Control"] = options.cache;
    if (options.expires)        out["Expires"] = options.expires instanceof Date
                                                  ? options.expires.toUTCString()
                                                  : String(options.expires);
    if (options.disposition)    out["Content-Disposition"] = options.disposition;
    if (options.language)       out["Content-Language"] = options.language;
    if (options.encoding)       out["Content-Encoding"] = options.encoding;
    if (options.referrerPolicy) out["Referrer-Policy"] = options.referrerPolicy;
    if (options.robots)         out["X-Robots-Tag"] = options.robots;
    return Object.keys(out).length ? out : null;
}

function isTextType(ct) {
    if (!ct) return false;
    const top = ct.split(";")[0].trim().toLowerCase();
    if (top.startsWith("text/")) return true;
    if (top === "application/json") return true;
    if (top === "application/xml") return true;
    if (top.endsWith("+json")) return true;
    if (top.endsWith("+xml")) return true;
    if (top === "application/javascript" || top === "application/ecmascript") return true;
    return false;
}

function numberOrNull(v) {
    if (v == null) return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
}

function stripQuotes(v) {
    return String(v ?? "").replace(/^"|"$/g, "");
}

const RESERVED_NAMESPACES = new Set(["home", "tmp", "dev", "sys", "proc", "etc", "lib", "boot", "usr", "var"]);
const PROC_ENDPOINTS = new Set(["proc/version", "proc/worlds", "proc/du", "proc/df", "proc/pool"]);
const APPROVE_WRITE_PREFIXES = Object.freeze(["lib", "etc", "boot", "usr", "var/log"]);

function canonicalPath(path) {
    const clean = stripLeadingSlashes(String(path ?? ""));
    if (!clean) return "";
    const first = clean.split("/", 1)[0];
    const world = RESERVED_NAMESPACES.has(first) ? clean : `home/${clean}`;
    validateWorldName(world);
    return world;
}

function exactOrChild(world, prefix) {
    return world === prefix || world.startsWith(`${prefix}/`);
}

function needsApproveForWrite(world) {
    return APPROVE_WRITE_PREFIXES.some((prefix) => exactOrChild(world, prefix));
}

function canonicalPrefix(prefix) {
    const clean = stripTrailingSlashes(stripLeadingSlashes(String(prefix ?? "")));
    if (!clean) return "";
    const first = clean.split("/", 1)[0];
    const world = RESERVED_NAMESPACES.has(first) ? clean : `home/${clean}`;
    validateWorldName(world, { allowNamespaceRoot: true });
    return world;
}

function canonicalListenPattern(pattern) {
    const clean = stripTrailingSlashes(stripLeadingSlashes(String(pattern ?? "")));
    if (!clean) return "";
    if (clean === "proc" || clean.startsWith("proc/")) {
        throw new TypeError("/proc is reserved; listen patterns must target worlds");
    }
    const first = clean.split("/", 1)[0];
    const world = RESERVED_NAMESPACES.has(first) ? clean : `home/${clean}`;
    validateWorldName(world, { allowNamespaceRoot: true });
    return world;
}

function validateRequestPath(path) {
    const clean = stripLeadingSlashes(String(path ?? ""));
    if (PROC_ENDPOINTS.has(clean)) return clean;
    const prefix = "proc/audit/";
    const suffix = "/verify";
    if (clean.startsWith(prefix)) {
        if (!clean.endsWith(suffix)) throw new TypeError("/proc/audit only exposes /proc/audit/{path}/verify");
        const rawWorld = clean.slice(prefix.length, -suffix.length);
        canonicalPath(rawWorld);
        return clean;
    }
    if (clean === "proc" || clean.startsWith("proc/")) {
        throw new TypeError("/proc is reserved; only declared proc endpoints are valid");
    }
    return canonicalPath(clean);
}

function validateWorldName(world, options = {}) {
    if (!world) throw new TypeError("empty elastik path");
    if (!options.allowNamespaceRoot && RESERVED_NAMESPACES.has(world)) throw new TypeError(`/${world} is a reserved namespace root`);
    if (world.includes("\\")) throw new TypeError("backslash is not allowed in elastik paths");
    for (let i = 0; i < world.length; i++) {
        const code = world.charCodeAt(i);
        if (code < 0x20 || code === 0x7f) throw new TypeError("control bytes are not allowed in elastik paths");
    }
    for (const segment of world.split("/")) {
        if (segment === "" || isDotSegment(segment)) {
            throw new TypeError("empty, dot, and dot-dot path segments are not allowed");
        }
    }
}

function isDotSegment(segment) {
    const lower = segment.toLowerCase();
    let rest = null;
    if (lower.startsWith(".")) rest = lower.slice(1);
    else if (lower.startsWith("%2e")) rest = lower.slice(3);
    else return false;
    return rest === "" || rest === "." || rest === "%2e";
}

function stripLeadingSlashes(value) {
    let i = 0;
    while (i < value.length && value.charCodeAt(i) === 47) i++;
    return value.slice(i);
}

function stripTrailingSlashes(value) {
    let end = value.length;
    while (end > 0 && value.charCodeAt(end - 1) === 47) end--;
    return value.slice(0, end);
}

function makeError(status, statusText, path, body = "") {
    const ErrorClass = ERROR_BY_STATUS[status] ?? (status >= 500 ? ServerError : ElastikError);
    return new ErrorClass(status, statusText, path, body);
}

function assertBodyType(body, method) {
    if (body == null || typeof body === "string") return;
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return;
    if (typeof Blob !== "undefined" && body instanceof Blob) return;
    if (typeof ReadableStream !== "undefined" && body instanceof ReadableStream) return;
    const hint = method === "put" ? "putJson()" : "JSON.stringify(...) or putJson()";
    throw new TypeError(
        `${method}() body must be string | ArrayBuffer | TypedArray | Blob | ReadableStream; ` +
        `got ${Object.prototype.toString.call(body)}. Did you mean ${hint}?`
    );
}

function safeCall(cb, ev) {
    try { cb(ev); } catch (err) { /* user's callback threw — never let that kill the stream */ }
}

// Tiny SSE decoder. Reads from a Web ReadableStream (the body of a fetch
// Response), parses field/value lines, dispatches to callback at each blank
// line. Spec: https://html.spec.whatwg.org/multipage/server-sent-events.html
//
// We don't try to be a full EventSource (no auto-reconnect, no last-event-id
// tracking). The user can re-call listen() with options.lastEventId if they
// want resumption.
async function consumeSSE(body, callback, signal) {
    const reader = body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";
    let event = "message";
    let id = "";
    let data = "";

    const dispatch = () => {
        if (data === "" && event === "message") return;
        const parsed = parseElastikSseData(data);
        safeCall(callback, { type: event, id, data, ...parsed });
        event = "message"; id = ""; data = "";
    };

    while (true) {
        if (signal.aborted) { reader.cancel().catch(() => {}); return; }
        let chunk;
        try { chunk = await reader.read(); }
        catch (err) {
            if (signal.aborted || err?.name === "AbortError") return;
            throw err;
        }
        if (chunk.done) { dispatch(); return; }
        buffer += decoder.decode(chunk.value, { stream: true });

        // Split on \n; keep the trailing fragment for next read.
        let nl;
        while ((nl = buffer.indexOf("\n")) >= 0) {
            const rawLine = buffer.slice(0, nl);
            buffer = buffer.slice(nl + 1);
            const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;

            if (line === "") { dispatch(); continue; }
            if (line.startsWith(":")) continue; // comment / keepalive
            const colon = line.indexOf(":");
            const field = colon < 0 ? line : line.slice(0, colon);
            let value = colon < 0 ? "" : line.slice(colon + 1);
            if (value.startsWith(" ")) value = value.slice(1);
            if (field === "event") event = value;
            else if (field === "id") id = value;
            else if (field === "data") data = data ? data + "\n" + value : value;
            // ignore retry: and unknown fields per spec
        }
    }
}

// elastik SSE event data is structured key:value lines like:
//   path: /home/note
//   method: PUT
//   etag: hmac-abc...
// Pull them out as named fields so the callback gets event.path / .method / .etag.
function parseElastikSseData(data) {
    const out = { path: "", method: "", etag: "" };
    if (!data) return out;
    for (const line of data.split("\n")) {
        const colon = line.indexOf(":");
        if (colon < 0) continue;
        const k = line.slice(0, colon).trim().toLowerCase();
        let v = line.slice(colon + 1);
        if (v.startsWith(" ")) v = v.slice(1);
        if (k === "path") out.path = v;
        else if (k === "method") out.method = v;
        else if (k === "etag") out.etag = v;
    }
    return out;
}
