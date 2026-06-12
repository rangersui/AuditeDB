// test.mjs — exercises every public method of the SDK against a running
// Elastik core. Pass ELASTIK_URL to point at Rust (3105) or Node (3106).
//
// Usage:
//   ELASTIK_URL=http://127.0.0.1:3105 ELASTIK_KEY=0123456789abcdef0123456789abcdef \
//     ELASTIK_READ_TOKEN=r ELASTIK_WRITE_TOKEN=w ELASTIK_APPROVE_TOKEN=a \
//     node test.mjs

import {
    Elastik,
    ElastikError,
    InsufficientStorage,
    NetworkError,
    NotFound,
    NotModified,
    PreconditionFailed,
    ServerError,
} from "./index.mjs";

const URL_BASE = process.env.ELASTIK_URL || "http://127.0.0.1:3105";
const READ_TOKEN = process.env.ELASTIK_READ_TOKEN || "r";
const WRITE_TOKEN = process.env.ELASTIK_WRITE_TOKEN || "w";
const APPROVE_TOKEN = process.env.ELASTIK_APPROVE_TOKEN || "a";

let pass = 0, fail = 0;
const fails = [];
function ok(name, detail = "") {
    pass++;
    console.log(`  ok:   ${name}${detail ? ` (${detail})` : ""}`);
}
function bad(name, detail = "") {
    fail++;
    fails.push(`${name}${detail ? ` — ${detail}` : ""}`);
    console.log(`  FAIL: ${name}${detail ? ` — ${detail}` : ""}`);
}
function check(cond, name, detail = "") { (cond ? ok : bad)(name, detail); }
function eq(actual, expected, name) {
    const a = JSON.stringify(actual), e = JSON.stringify(expected);
    check(a === e, name, a === e ? a.slice(0, 60) : `expected ${e}, got ${a}`);
}

console.log(`\n=== @elastikjs/client tests vs ${URL_BASE} ===\n`);

const e        = new Elastik(URL_BASE, { token: WRITE_TOKEN, readToken: READ_TOKEN, approveToken: APPROVE_TOKEN });
const eAnon    = new Elastik(URL_BASE);
const eReadOnly = new Elastik(URL_BASE, { readToken: READ_TOKEN });
const eApprove = new Elastik(URL_BASE, { token: APPROVE_TOKEN, readToken: READ_TOKEN, approveToken: APPROVE_TOKEN });

// Idempotent cleanup so reruns are clean.
async function cleanup() {
    for (const p of [
        "sdk-test/note", "sdk-test/json", "sdk-test/log",
        "sdk-test/cond", "sdk-test/blob",
        "sdk-test/cancelled", "sdk-test/createonly",
        "sdk-test/binary", "sdk-test/exists", "sdk-test/withmeta",
        "sdk-test/json", "sdk-test/text", "sdk-test/list/a",
        "home/sdk-test/listen/a", "home/sdk-test/unrelated/x",
    ]) {
        try { await eApprove.delete(p); } catch (err) { if (err.status !== 404) throw err; }
    }
}
await cleanup();

// ─── Test 1: PUT + GET round trip ─────────────────────────────
console.log("=== put + get round trip ===");
const r1 = await e.put("sdk-test/note", "hello", { contentType: "text/plain; charset=utf-8" });
check(r1.status === 201, "put returns 201 on create", String(r1.status));
check(typeof r1.etag === "string" && r1.etag.startsWith('"hmac-'), "put returns hmac etag", r1.etag);
const body = await e.get("sdk-test/note");
eq(body, "hello", "get returns body string");

// PUT again → 200 (replace, not 201)
const r1b = await e.put("sdk-test/note", "hello again");
check(r1b.status === 200, "put returns 200 on overwrite", String(r1b.status));

// ─── Test 2: HEAD ────────────────────────────────────────────
console.log("\n=== head ===");
await e.put("sdk-test/note", "hello", { contentType: "text/plain; charset=utf-8" });
const head = await e.head("sdk-test/note");
eq(head.contentType, "text/plain; charset=utf-8", "head content-type");
eq(head.size, 5, "head size");
check(head.etag.startsWith('"hmac-'), "head etag is hmac");
check(typeof head.headers === "object" && head.headers["accept-ranges"] === "bytes", "head exposes raw headers");
check(new InsufficientStorage(507, "Insufficient Storage", "sdk-test/full") instanceof ServerError,
      "InsufficientStorage is a ServerError subclass");
const eFull = new Elastik("http://stub", {
    token: "x",
    fetch: async () => new Response("storage full", { status: 507, statusText: "Insufficient Storage" }),
});
try {
    await eFull.get("sdk-test/full");
    bad("507 should throw InsufficientStorage");
} catch (err) {
    check(err instanceof InsufficientStorage, "507 throws InsufficientStorage");
    check(err instanceof ServerError, "507 remains a ServerError");
    check(err.status === 507, "507 status preserved");
}

// ─── Test 3: POST append ─────────────────────────────────────
console.log("\n=== post append ===");
await e.post("sdk-test/note", " world");
eq(await e.get("sdk-test/note"), "hello world", "post appended bytes");
const headAfterPost = await e.head("sdk-test/note");
eq(headAfterPost.contentType, "text/plain; charset=utf-8", "POST kept Content-Type");

// ─── Test 4: DELETE ──────────────────────────────────────────
console.log("\n=== text/json helpers + body validation ===");
await e.putText("sdk-test/text", "hello text");
eq(await e.getText("sdk-test/text"), "hello text", "putText/getText round-trip");
eq((await e.head("sdk-test/text")).contentType, "text/plain; charset=utf-8", "putText content-type");
await e.putJson("sdk-test/json", { ok: true, n: 6 });
eq(await e.getJson("sdk-test/json"), { ok: true, n: 6 }, "putJson/getJson round-trip");
eq((await e.head("sdk-test/json")).contentType, "application/json; charset=utf-8", "putJson content-type");
try {
    await e.put("sdk-test/oops", { nope: true });
    bad("put object should TypeError");
} catch (err) {
    check(err instanceof TypeError, "put object throws TypeError");
    check(err.message.includes("putJson"), "TypeError suggests putJson");
}
try {
    await e.put("sdk-test/oops.json", { nope: true });
    bad("put object to .json should TypeError");
} catch (err) {
    check(err instanceof TypeError, "put object to .json throws before fetch");
    check(err.message.includes("putJson"), "json object TypeError suggests putJson");
}
for (const badPath of ["sdk-test/./x", "sdk-test/../x", "sdk-test/%2E/x", "sdk-test/%2e%2E/x"]) {
    try {
        await e.put(badPath, "x");
        bad(`invalid path ${badPath} should TypeError`);
    } catch (err) {
        check(err instanceof TypeError, `invalid path ${badPath} throws before fetch`);
    }
}
for (const badPattern of ["home/%2E%2E/x", "proc/worlds"]) {
    try {
        e.listen(badPattern, () => {});
        bad(`invalid listen pattern ${badPattern} should TypeError`);
    } catch (err) {
        check(err instanceof TypeError, `invalid listen pattern ${badPattern} throws before fetch`);
    }
}
try {
    await e.getJson("sdk-test/text");
    bad("getJson on text should TypeError");
} catch (err) {
    check(err instanceof TypeError, "getJson invalid JSON throws TypeError");
    check(err.message.includes("sdk-test/text"), "getJson error includes path");
    check(err.message.includes("text/plain"), "getJson error includes Content-Type");
}

console.log("\n=== delete ===");
const d4 = await eApprove.delete("sdk-test/note");
check(d4.status === 204, "delete returns 204", String(d4.status));
check(!(await e.exists("sdk-test/note")), "deleted world is gone");

console.log("\n=== raw request escape hatch ===");
const optionsResp = await e.request("OPTIONS", "sdk-test/request", { token: READ_TOKEN });
check(optionsResp.status === 204, "request() can send OPTIONS", String(optionsResp.status));
check(optionsResp.headers.get("allow")?.includes("PUT"), "request() exposes raw headers");
try {
    await e.request("PUT", "sdk-test/request-object", { body: { nope: true } });
    bad("request object body should TypeError");
} catch (err) {
    check(err instanceof TypeError, "request() object body throws TypeError");
}

// ─── Test 5: ElastikError shape ──────────────────────────────
console.log("\n=== ElastikError ===");
try {
    Elastik.start();
    bad("bare Elastik.start should throw helpful subpath error");
} catch (err) {
    check(err.message.includes("@elastikjs/client/start"), "bare Elastik.start points to /start entrypoint");
}
try {
    await e.get("sdk-test/missing-yo");
    bad("get missing should throw");
} catch (err) {
    check(err instanceof ElastikError, "throws ElastikError");
    check(err instanceof NotFound, "404 throws NotFound");
    check(err.status === 404, "404 status", String(err.status));
    check(typeof err.statusText === "string", "statusText present");
    check(err.path === "sdk-test/missing-yo", "error.path", err.path);
    check(typeof err.message === "string" && err.message.includes("404"), "error.message");
}
try {
    await new Elastik("http://127.0.0.1:9", { writeToken: WRITE_TOKEN }).get("home/x");
    bad("unreachable core should throw NetworkError");
} catch (err) {
    check(err instanceof NetworkError, "network failure throws NetworkError");
    check(err.status === 0, "NetworkError status=0");
}

// ─── Test 6: Conditional PUT (If-Match) ──────────────────────
console.log("\n=== If-Match ===");
await e.put("sdk-test/cond", "v1");
try {
    await e.put("sdk-test/cond", "v2", { etag: '"hmac-stale"' });
    bad("stale If-Match should throw 412");
} catch (err) {
    check(err instanceof PreconditionFailed, "stale If-Match throws PreconditionFailed");
    check(err.status === 412, "stale If-Match → 412");
}
const condEtag = (await e.head("sdk-test/cond")).etag;
const r6 = await e.put("sdk-test/cond", "v2", { ifMatch: condEtag });
check(r6.status === 200, "current If-Match → 200");
eq(await e.get("sdk-test/cond"), "v2", "If-Match write took effect");

// ─── Test 7: create-only (If-None-Match: *) ──────────────────
console.log("\n=== create-only ===");
const r7a = await e.put("sdk-test/createonly", "first", { ifNoneMatch: "*" });
check(r7a.status === 201, "create-only → 201 on missing world");
try {
    await e.put("sdk-test/createonly", "second", { ifNoneMatch: "*" });
    bad("create-only on existing should 412");
} catch (err) {
    check(err instanceof PreconditionFailed, "create-only throws PreconditionFailed");
    check(err.status === 412, "create-only on existing → 412");
}

// ─── Test 8: Conditional GET (If-None-Match → 304 → NotModified) ────
console.log("\n=== If-None-Match cache ===");
const cacheEtag = (await e.head("sdk-test/cond")).etag;
try {
    await e.get("sdk-test/cond", { ifNoneMatch: cacheEtag });
    bad("If-None-Match same etag should throw NotModified");
} catch (err) {
    check(err instanceof NotModified, "If-None-Match same etag → NotModified");
    check(err.status === 304, "NotModified status 304");
}
const fresh = await e.get("sdk-test/cond", { ifNoneMatch: '"hmac-something-else"' });
eq(fresh, "v2", "If-None-Match different etag → body returned");

// ─── Test 9: Range GET ───────────────────────────────────────
console.log("\n=== range ===");
await e.put("sdk-test/cond", "0123456789");
const partial = await e.get("sdk-test/cond", { range: "0-3" });
eq(partial.body, "0123", "range 0-3 returns 4 bytes");
check(partial.contentRange?.startsWith("bytes 0-3/"), "Content-Range present", partial.contentRange);
const tail = await e.get("sdk-test/cond", { range: "5-" });
eq(tail.body, "56789", "range 5- returns suffix");

// ─── Test 10: meta option ────────────────────────────────────
console.log("\n=== meta option ===");
const m = await e.get("sdk-test/cond", { meta: true });
eq(m.body, "0123456789", "meta.body");
check(m.etag.startsWith('"hmac-'), "meta.etag");
check(m.size === 10, "meta.size");
check(typeof m.contentType === "string", "meta.contentType present");

// ─── Test 11: Auth tiers ─────────────────────────────────────
//
// Probe whether the server is configured with ELASTIK_READ_TOKEN. If reads
// are public, the "anon read should 401" assertion legitimately doesn't
// apply — same SDK behavior, different server config. Adapt rather than
// fail.
console.log("\n=== auth tiers ===");
let readGated = true;
try { await eAnon.get("/proc/version"); /* version is always public */ }
catch { /* ignore */ }
try {
    await eAnon.head("sdk-test/cond");
    readGated = false;
} catch (err) {
    readGated = err.status === 401;
}
try {
    await eAnon.put("sdk-test/should-fail", "x");
    bad("anon write should fail");
} catch (err) {
    check(err.status === 401, "anon write → 401");
}
if (readGated) {
    try {
        await eAnon.get("sdk-test/cond");
        bad("anon read should fail (server requires read token)");
    } catch (err) {
        check(err.status === 401, "anon read → 401");
    }
} else {
    ok("anon read allowed (server has no ELASTIK_READ_TOKEN — public)");
}
try {
    await eReadOnly.put("sdk-test/should-fail-2", "x");
    bad("read-only write should fail");
} catch (err) {
    check(err.status === 401, "read-only client cannot write → 401");
}

// ─── Test 12: version + worlds + exists ──────────────────────
console.log("\n=== /proc + exists ===");
const ver = await e.version();
check(typeof ver === "string" && ver.startsWith("elastik-core "), "version starts with 'elastik-core '", ver);
check(!ver.endsWith("\n"), "version() trims trailing newline");
const worlds = await e.worlds();
check(typeof worlds === "string", "worlds is text");
const listed = await e.list("sdk-test");
check(Array.isArray(listed) && listed.includes("home/sdk-test/cond"), "list(prefix) returns canonical paths");
const listedWithSlash = await e.list("sdk-test/");
check(Array.isArray(listedWithSlash) && listedWithSlash.includes("home/sdk-test/cond"), "list(prefix/) trims trailing slash");
const homeListed = await e.list("home");
check(Array.isArray(homeListed) && homeListed.includes("home/sdk-test/cond"), "list(namespace root) is allowed");
const homeSlashListed = await e.list("home/");
check(Array.isArray(homeSlashListed) && homeSlashListed.includes("home/sdk-test/cond"), "list(namespace root/) trims trailing slash");
check(await e.exists("sdk-test/cond"), "exists() → true for existing");
check(!(await e.exists("sdk-test/never-existed")), "exists() → false for missing");
check(await e.sizeof("sdk-test/cond") > 0, "sizeof() uses HEAD content-length");
check((await e.checksum("sdk-test/cond")).startsWith('"hmac-'), "checksum() returns ETag");
check(await e.isAudited("sdk-test/cond"), "isAudited() detects durable hmac ETag");
check(await e.verify("sdk-test/cond"), "verify() checks audit chain");

// ─── Test 13: AbortController ────────────────────────────────
console.log("\n=== AbortController ===");
const controller = new AbortController();
const slow = e.get("sdk-test/cond", { signal: controller.signal });
controller.abort();
try {
    await slow;
    bad("aborted request should throw");
} catch (err) {
    check(err?.name === "AbortError" || /abort/i.test(err?.message || ""), "abort throws AbortError-like");
}

// ─── Test 14: Binary round-trip ──────────────────────────────
console.log("\n=== binary round-trip ===");
const bin = new Uint8Array(256);
for (let i = 0; i < 256; i++) bin[i] = i;
await e.put("sdk-test/binary", bin, { contentType: "application/octet-stream" });
const got = await e.get("sdk-test/binary");
check(got instanceof ArrayBuffer, "binary GET returns ArrayBuffer");
check(got.byteLength === 256, "binary size matches");
const view = new Uint8Array(got);
let allMatch = true;
for (let i = 0; i < 256; i++) if (view[i] !== i) { allMatch = false; break; }
check(allMatch, "binary bytes match");
const headBin = await e.head("sdk-test/binary");
eq(headBin.contentType, "application/octet-stream", "binary head content-type");

// ─── Test 15: listen (SSE) ───────────────────────────────────
//
// NOTE: bare paths like "sdk-test/listen/a" canonicalize to
// "home/sdk-test/listen/a" on the server. The SSE event reports the
// canonical path "/home/sdk-test/listen/a", so the listen pattern has
// to match THAT shape — not the bare write-path. Use "home/..." prefix
// in patterns explicitly. Same convention as the Python SDK e2e tests.
console.log("\n=== listen (SSE) ===");
const events = [];
const errors = [];
const unsub = e.listen("home/sdk-test/listen/*", (ev) => {
    if (ev.type === "error") errors.push(ev.error);
    else events.push(ev);
});
// Give it a moment to connect.
await sleep(300);
await e.put("home/sdk-test/listen/a", "evt-payload-secret");
await sleep(500);
unsub();
check(errors.length === 0, "listen had no errors", errors.map(e => e.message).join("; "));
check(events.length >= 1, `listen received event(s)`, `got ${events.length}`);
const ev = events[events.length - 1];
check(ev?.type === "put", "event.type is 'put'", ev?.type);
check(ev?.path === "/home/sdk-test/listen/a", "event.path", ev?.path);
check(ev?.method === "PUT", "event.method", ev?.method);
check(typeof ev?.etag === "string" && ev.etag.startsWith("hmac-"), "event.etag", ev?.etag);
check(ev?.timelineWorld === "home/sdk-test/listen/a", "event.timelineWorld", ev?.timelineWorld);
check(typeof ev?.timelineGeneration === "string" && ev.timelineGeneration.length === 32, "event.timelineGeneration", ev?.timelineGeneration);
check(ev?.timelineSeq === "1", "event.timelineSeq", ev?.timelineSeq);
check(typeof ev?.timelineBodySha256 === "string" && ev.timelineBodySha256.length === 64, "event.timelineBodySha256", ev?.timelineBodySha256);
check(typeof ev?.id === "string" && ev.id.length > 0, "event.id present", ev?.id);
check(!String(ev?.data ?? "").includes("evt-payload-secret"), "event.data does not leak body");

const appendEvents = [];
const appendUnsub = e.listen("home/sdk-test/listen/*", (appendEv) => {
    if (appendEv.type !== "error") appendEvents.push(appendEv);
});
await sleep(300);
await e.post("home/sdk-test/listen/a", "-append-secret");
await sleep(500);
appendUnsub();
const appendEv = appendEvents[appendEvents.length - 1];
check(appendEv?.type === "post", "append event.type is 'post'", appendEv?.type);
check(appendEv?.method === "POST", "append event.method", appendEv?.method);
check(appendEv?.timelineWorld === "home/sdk-test/listen/a", "append event.timelineWorld", appendEv?.timelineWorld);
check(appendEv?.timelineSeq === "2", "append event.timelineSeq", appendEv?.timelineSeq);
check(typeof appendEv?.timelineBodySha256 === "string" && appendEv.timelineBodySha256.length === 64, "append event.timelineBodySha256", appendEv?.timelineBodySha256);
check(!String(appendEv?.data ?? "").includes("-append-secret"), "append event.data does not leak body");

// ─── Test 16: listen unsubscribe terminates cleanly ──────────
console.log("\n=== unsubscribe cleanup ===");
const events2 = [];
const unsub2 = e.listen("home/sdk-test/never/*", (ev) => events2.push(ev));
await sleep(150);
unsub2();
await sleep(150);
// Trigger something the (now-cancelled) subscriber would have matched
await e.put("home/sdk-test/unrelated/x", "noise");
await sleep(150);
check(events2.length === 0, "no events delivered after unsub");

// ─── Test 17: custom fetch (stub) ────────────────────────────
console.log("\n=== custom fetch ===");
let stubCalls = 0;
let stubUrl = "";
const stubFetch = async (url, init) => {
    stubCalls++;
    stubUrl = String(url);
    return new Response("stubbed", {
        status: 200,
        headers: { "Content-Type": "text/plain", "ETag": '"hmac-stub"', "Content-Length": "8" },
    });
};
const eStub = new Elastik("http://stub", { token: "x", fetch: stubFetch });
const stubBody = await eStub.get("anywhere");
eq(stubBody, "stubbed", "custom fetch is used");
check(stubCalls === 1, "custom fetch was called once");
check(stubUrl === "http://stub/home/anywhere", "bare SDK paths canonicalize to /home", stubUrl);

let authSeen = [];
const authFetch = async (_url, init = {}) => {
    authSeen.push(init.headers?.Authorization ?? init.headers?.authorization ?? "");
    return new Response(null, { status: 204, headers: { "ETag": '"hmac-auth"' } });
};
const eAuth = new Elastik("http://stub", {
    writeToken: "WRITE",
    readToken: "READ",
    approveToken: "APPROVE",
    fetch: authFetch,
});
await eAuth.put("etc/sysconfig", "x");
await eAuth.post("var/log/audit", "x");
await eAuth.request("GET", "home/read");
await eAuth.request("PUT", "etc/raw", { body: "x" });
await eAuth.delete("home/gone");
eq(authSeen, [
    "Bearer APPROVE",
    "Bearer APPROVE",
    "Bearer READ",
    "Bearer APPROVE",
    "Bearer APPROVE",
], "method/path auth chooses read/write/approve tokens");
authSeen = [];
const approveWarnings = [];
const originalWarn = console.warn;
console.warn = (message) => { approveWarnings.push(String(message)); };
try {
    const eNoApprove = new Elastik("http://stub", { writeToken: "WRITE", fetch: authFetch });
    await eNoApprove.delete("home/gone");
    await eNoApprove.put("etc/sysconfig", "x");
} finally {
    console.warn = originalWarn;
}
eq(authSeen, ["Bearer WRITE", "Bearer WRITE"], "missing approveToken falls back to writeToken");
check(approveWarnings.length === 1, "missing approveToken warns once");
check(approveWarnings[0].includes("approveToken was not configured"), "missing approveToken warning is actionable");
authSeen = [];
await eAuth.put("etc/sysconfig", "x", { headers: { Authorization: "Bearer USER" } });
await eAuth.request("DELETE", "home/gone", { headers: { authorization: "Bearer lower-user" } });
eq(authSeen, ["Bearer USER", "Bearer lower-user"], "explicit Authorization header wins");

// ─── Test 18: template strings + nested paths ───────────────
console.log("\n=== template strings ===");
const sensor = "temperature-3";
await e.put(`sdk-test/sensor/${sensor}`, "23.5");
eq(await e.get(`sdk-test/sensor/${sensor}`), "23.5", "template string path round-trip");
await eApprove.delete(`sdk-test/sensor/${sensor}`);

// ─── Test 19: headers passthrough on PUT ────────────────────
//
// v7.2 flipped to default-deny for custom representation headers.
// `Cache-Control` is in the built-in L2 default-allow set and
// always round-trips. `X-Meta-*` is custom -- only round-trips if
// the core is started with ELASTIK_PERSIST_HEADERS that allows it.
// Detect via env so this test passes both with and without the
// allowlist, instead of forcing operators to set env to run JS
// tests.
console.log("\n=== headers passthrough ===");
const xMetaAllowed = (() => {
    // Mirror of HeaderAllowlist::parse / matches in the Rust core
    // (core/src/http_semantics.rs). Specifically: a bare `*` entry
    // is rejected by the Rust parser (length-1 prefix gets dropped),
    // so this checker must reject it too -- otherwise a
    // pathological env value would make the JS test expect a
    // round-trip the Rust core wouldn't deliver.
    const v = (process.env.ELASTIK_PERSIST_HEADERS || "").toLowerCase();
    return v.split(",").some((entry) => {
        const e = entry.trim();
        if (!e) return false;
        if (e.endsWith("*")) {
            const prefix = e.slice(0, -1);
            return prefix.length > 0 && "x-meta-author".startsWith(prefix);
        }
        return e === "x-meta-author";
    });
})();
await e.put("sdk-test/withmeta", "x", {
    contentType: "text/plain",
    headers: { "X-Meta-Author": "ranger", "Cache-Control": "max-age=3600" },
});
const metaHead = await e.head("sdk-test/withmeta");
if (xMetaAllowed) {
    eq(metaHead.headers["x-meta-author"], "ranger", "X-Meta-* persisted via headers option (env-allowed)");
} else {
    check(
        !("x-meta-author" in metaHead.headers),
        "X-Meta-* default-denies without ELASTIK_PERSIST_HEADERS opt-in",
    );
}
eq(metaHead.headers["cache-control"], "max-age=3600", "Cache-Control persisted via headers option (L2 default)");
await eApprove.delete("sdk-test/withmeta");

// ─── Test 20: auto Content-Type from path extension ────────
//
// JS SDK runs in browsers. Browsers refuse to execute scripts with the
// wrong MIME, refuse to apply text/plain stylesheets, decode wrong-MIME
// images as garbage. So the SDK detects MIME from path extension when
// the caller doesn't override.
console.log("\n=== auto Content-Type from extension ===");
const mimeFixtures = [
    ["sdk-test/auto/index.html", "<h1>hi</h1>",                      "text/html; charset=utf-8"],
    ["sdk-test/auto/style.css",  "body{color:red}",                  "text/css; charset=utf-8"],
    ["sdk-test/auto/app.js",     "console.log('hi')",                "application/javascript; charset=utf-8"],
    ["sdk-test/auto/data.json",  '{"ok":true}',                      "application/json; charset=utf-8"],
    ["sdk-test/auto/photo.png",  new Uint8Array([0x89, 0x50, 0x4e, 0x47]), "image/png"],
    ["sdk-test/auto/icon.svg",   "<svg/>",                           "image/svg+xml"],
    ["sdk-test/auto/font.woff2", new Uint8Array([0x77, 0x4f, 0x46, 0x32]), "font/woff2"],
    ["sdk-test/auto/note.md",    "# hi",                             "text/markdown; charset=utf-8"],
];
for (const [p, body, expected] of mimeFixtures) {
    await e.put(p, body);
    const got = (await e.head(p)).contentType;
    eq(got, expected, `auto MIME for ${p.split("/").pop()}`);
    try { await eApprove.delete(p); } catch {}
}
// Path without extension → SDK does NOT guess; falls through to fetch default
// (string body → text/plain). User can still override with options.contentType.
await e.put("sdk-test/auto/no-ext", "x");
const noExtCt = (await e.head("sdk-test/auto/no-ext")).contentType;
check(typeof noExtCt === "string" && !noExtCt.includes("html"),
    "no extension → SDK does not invent a MIME", noExtCt);
try { await eApprove.delete("sdk-test/auto/no-ext"); } catch {}

// User-supplied contentType always wins over auto-detection.
await e.put("sdk-test/auto/index.html", "<h1>x</h1>", { contentType: "text/plain" });
eq((await e.head("sdk-test/auto/index.html")).contentType, "text/plain",
    "explicit contentType overrides auto-detection");
try { await eApprove.delete("sdk-test/auto/index.html"); } catch {}

// ─── Test 21: stored CORS / CSP headers travel with bytes ──
//
// The PUT-time hint that lets a browser-served HTML page work cross-origin:
// store the Access-Control-Allow-Origin / Content-Security-Policy /
// X-Frame-Options as response headers ON the world. The core preserves them.
// This is HOW you serve a same-origin or controlled-cross-origin static site
// from elastik. Python SDK doesn't bother; JS SDK is the one that needs it.
console.log("\n=== stored CORS / CSP / browser-policy headers ===");
await e.put("sdk-test/policy.html", "<h1>policy</h1>", {
    headers: {
        "Access-Control-Allow-Origin": "*",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
    },
});
const polHead = await e.head("sdk-test/policy.html");
eq(polHead.headers["access-control-allow-origin"], "*", "ACAO travels with bytes");
eq(polHead.headers["content-security-policy"], "default-src 'self'", "CSP travels with bytes");
eq(polHead.headers["x-frame-options"], "DENY", "X-Frame-Options travels with bytes");
eq(polHead.contentType, "text/html; charset=utf-8", "HTML auto-MIME applied alongside policy");
try { await eApprove.delete("sdk-test/policy.html"); } catch {}

// ─── Test 22: cors shortcut ─────────────────────────────────
//
// `cors: true` expands to a public CORS policy. `cors: { origin, methods,
// exposeHeaders, ... }` expands to precise headers. User-supplied
// options.headers always win (last-word).
console.log("\n=== cors shortcut ===");
await e.put("sdk-test/cors-public.json", '{"ok":true}', { cors: true });
const corsHead1 = await e.head("sdk-test/cors-public.json");
eq(corsHead1.headers["access-control-allow-origin"], "*", "cors:true → ACAO=*");
eq(corsHead1.headers["access-control-allow-methods"], "GET, HEAD, OPTIONS", "cors:true → ACAM");
eq(corsHead1.headers["access-control-expose-headers"], "ETag, Content-Type, Content-Length", "cors:true → ACEH");
try { await eApprove.delete("sdk-test/cors-public.json"); } catch {}

await e.put("sdk-test/cors-precise.json", '{"ok":true}', {
    cors: {
        origin: "https://mysite.example",
        methods: ["GET", "HEAD"],
        exposeHeaders: "ETag",
        credentials: true,
        maxAge: 600,
    },
});
const corsHead2 = await e.head("sdk-test/cors-precise.json");
eq(corsHead2.headers["access-control-allow-origin"], "https://mysite.example", "cors object → ACAO precise");
eq(corsHead2.headers["access-control-allow-methods"], "GET, HEAD", "cors.methods array joined");
eq(corsHead2.headers["access-control-expose-headers"], "ETag", "cors.exposeHeaders single");
eq(corsHead2.headers["access-control-allow-credentials"], "true", "cors.credentials → ACAC=true");
eq(corsHead2.headers["access-control-max-age"], "600", "cors.maxAge stored");
try { await eApprove.delete("sdk-test/cors-precise.json"); } catch {}

// User options.headers must override the cors expansion when they collide.
await e.put("sdk-test/cors-override.json", '{"ok":true}', {
    cors: true,
    headers: { "Access-Control-Allow-Origin": "https://override.example" },
});
const corsHead3 = await e.head("sdk-test/cors-override.json");
eq(corsHead3.headers["access-control-allow-origin"], "https://override.example",
    "user headers override cors shortcut");
eq(corsHead3.headers["access-control-allow-methods"], "GET, HEAD, OPTIONS",
    "non-overridden cors fields still expand");
try { await eApprove.delete("sdk-test/cors-override.json"); } catch {}

// ─── Test 23: full browser-policy shortcut shelf ───────────
//
// One PUT, full bouquet of headers stored alongside the bytes. This is the
// JS-SDK-native UX for serving an HTML site from elastik with security,
// caching, and SEO declared at write time.
console.log("\n=== full browser-policy shortcut shelf ===");
await e.put("sdk-test/full-policy.html", "<h1>full</h1>", {
    csp: "default-src 'self'; script-src 'self'",
    cspReportOnly: "default-src 'none'",
    frameOptions: "DENY",
    coop: "same-origin",
    coep: "require-corp",
    corp: "same-origin",
    cache: "public, max-age=3600",
    expires: new Date("2030-01-01T00:00:00Z"),
    disposition: "inline",
    language: "zh-CN",
    referrerPolicy: "no-referrer",
    robots: "noindex, nofollow",
});
const fullHead = await e.head("sdk-test/full-policy.html");
eq(fullHead.headers["content-security-policy"], "default-src 'self'; script-src 'self'", "csp shortcut");
eq(fullHead.headers["content-security-policy-report-only"], "default-src 'none'", "cspReportOnly shortcut");
eq(fullHead.headers["x-frame-options"], "DENY", "frameOptions shortcut");
eq(fullHead.headers["cross-origin-opener-policy"], "same-origin", "coop shortcut");
eq(fullHead.headers["cross-origin-embedder-policy"], "require-corp", "coep shortcut");
eq(fullHead.headers["cross-origin-resource-policy"], "same-origin", "corp shortcut");
eq(fullHead.headers["cache-control"], "public, max-age=3600", "cache shortcut");
check(/^[A-Za-z]{3}, \d/.test(fullHead.headers["expires"] || ""), "expires Date → HTTP-date format", fullHead.headers["expires"]);
eq(fullHead.headers["content-disposition"], "inline", "disposition shortcut");
eq(fullHead.headers["content-language"], "zh-CN", "language shortcut");
eq(fullHead.headers["referrer-policy"], "no-referrer", "referrerPolicy shortcut");
eq(fullHead.headers["x-robots-tag"], "noindex, nofollow", "robots shortcut");
eq(fullHead.contentType, "text/html; charset=utf-8", "auto-MIME alongside policy shortcuts");
try { await eApprove.delete("sdk-test/full-policy.html"); } catch {}

// ─── Test 24: encoding shortcut for pre-compressed bytes ───
//
// gzip a body manually, store with encoding: "gzip" so browsers know to
// decompress on receive.
console.log("\n=== encoding shortcut (pre-compressed bytes) ===");
const { gzipSync } = await import("node:zlib");
const compressed = gzipSync(Buffer.from("hello compressed world"));
await e.put("sdk-test/compressed.txt", compressed, {
    contentType: "text/plain; charset=utf-8",
    encoding: "gzip",
});
const compHead = await e.head("sdk-test/compressed.txt");
eq(compHead.headers["content-encoding"], "gzip", "encoding shortcut → Content-Encoding");
eq(compHead.contentType, "text/plain; charset=utf-8", "explicit contentType wins over auto");
try { await eApprove.delete("sdk-test/compressed.txt"); } catch {}

await cleanup();

// ─── Summary ─────────────────────────────────────────────────
console.log(`\n=== ${pass} passed, ${fail} failed ===`);
if (fail > 0) {
    console.log("\nFailures:");
    for (const f of fails) console.log("  -", f);
    process.exit(1);
}
process.exit(0);

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
