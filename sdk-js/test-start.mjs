// test-start.mjs — Node-only. Verifies the start.mjs flow:
//   1. resolveBinary() finds the platform-package binary
//   2. start() spawns it on a free port and returns a connected Elastik
//   3. SDK can put/get/listen against the spawned core
//   4. stop() kills the process and cleans up the data dir

import { start, resolveBinary } from "./start.mjs";
import * as fs from "node:fs";

let pass = 0, fail = 0;
const ok = (n, d = "") => { pass++; console.log(`  ok:   ${n}${d ? ` (${d})` : ""}`); };
const bad = (n, d = "") => { fail++; console.log(`  FAIL: ${n}${d ? ` — ${d}` : ""}`); };
const check = (cond, n, d = "") => (cond ? ok : bad)(n, d);

console.log(`platform: ${process.platform}-${process.arch}`);
console.log(`binary:   ${resolveBinary() ?? "(not found)"}`);
if (!resolveBinary()) {
    console.error("FAIL: no bundled binary for this platform.");
    console.error("Run: npm link @elastikjs/core-" + process.platform + "-" + process.arch);
    process.exit(2);
}

console.log("\n=== start() with random key/token + ephemeral data dir ===");
const e = await start();
check(typeof e.url === "string" && e.url.startsWith("http://"), "client.url is set", e.url);
check(typeof e.dataDir === "string" && fs.existsSync(e.dataDir), "data dir exists", e.dataDir);
check(typeof e.stop === "function", "client.stop is a function");
check(e.process && !e.process.killed, "child process is alive (pid " + e.process?.pid + ")");

console.log("\n=== /proc/version (proves it's the Rust core) ===");
const ver = await e.version();
check(ver.startsWith("elastik-core ") && ver.includes("(rust)"), "version is Rust core", ver.trim());

console.log("\n=== put + get round-trip via spawned core ===");
const r1 = await e.put("hello", "from-spawned-rust", { contentType: "text/plain; charset=utf-8" });
check(r1.status === 201, "put → 201 (created)", String(r1.status));
check(r1.etag.startsWith('"hmac-'), "put → hmac etag (audit chain advanced)", r1.etag);
const body = await e.get("hello");
check(body === "from-spawned-rust", "get round-trips body");

console.log("\n=== auto-MIME from path extension still works ===");
await e.put("page.html", "<h1>x</h1>");
const head = await e.head("page.html");
check(head.contentType === "text/html; charset=utf-8", "auto MIME for .html", head.contentType);

console.log("\n=== listen (SSE) against the spawned core ===");
const events = [];
const unsub = e.listen("home/spawned/listen/*", (ev) => {
    if (ev.type === "error") { fail++; console.log("  listen error:", ev.error?.message); return; }
    events.push(ev);
});
await new Promise((r) => setTimeout(r, 250));
await e.put("home/spawned/listen/a", "evt");
await new Promise((r) => setTimeout(r, 400));
unsub();
check(events.length >= 1, "SSE event delivered", `n=${events.length}`);
check(events[0]?.method === "PUT", "event.method=PUT");
check(events[0]?.path === "/home/spawned/listen/a", "event.path");

console.log("\n=== stop() kills the process + wipes data dir ===");
const dataDir = e.dataDir;
const childPid = e.process.pid;
await e.stop();
check(e.process.killed || e.process.exitCode != null, "child process exited", `code=${e.process.exitCode}`);
// Data dir should be gone (cleanup defaulted to true since we auto-created it).
check(!fs.existsSync(dataDir), "data dir cleaned up", dataDir);

// After stop, fetch should fail.
console.log("\n=== fetch fails after stop (port released) ===");
try {
    await e.get("hello");
    bad("expected fetch to fail after stop");
} catch (err) {
    ok("fetch fails after stop", err.message.slice(0, 60));
}

console.log(`\n=== ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
