// start.mjs — Node-only. Spawns the bundled Rust core binary.
//
// "npm install @elastikjs/client" lands a JavaScript SDK PLUS a Rust HTTP
// engine. The user thinks they installed a JS library; they didn't, they
// installed a Rust process spawner. JavaScript is the front desk; Rust is
// the kitchen. The user only ever talks to the front desk.
//
// This is the same trick esbuild (Go), swc / turbo / sharp (Rust) play.
// Frontend developers run native binaries every day without knowing. The
// language they read is JavaScript; the language doing the work is not.
//
// Recursive insight: this file launches a Rust process that listens on
// HTTP, then index.mjs talks to it via fetch. The SDK and the core
// communicate through HTTP — i.e., elastik talks to elastik via elastik.
// HTTP is all you need, even between the SDK and its embedded core.
//
// Architecture:
//
//   npm install @elastikjs/client
//     ↓
//   npm reads optionalDependencies → tries every @elastikjs/core-*
//   → only the one matching `os` + `cpu` succeeds (esbuild's pattern)
//   → others fail silently because they're optional
//     ↓
//   start() at runtime:
//     ↓
//   require.resolve("@elastikjs/core-${platform}-${arch}/package.json")
//     ↓
//   spawn the binary on a port
//     ↓
//   wait for /proc/version to answer
//     ↓
//   return a connected Elastik client + .stop() lifecycle
//
// The spawned core's data lives in `dataDir` (default: a fresh temp dir,
// wiped on stop). Two first-class lifetimes:
//   - one-shot:   start() → use → stop() → temp dir gone
//                 (great for tests, CI, transient mocks)
//   - long-lived: pass an explicit `dataDir` (and optionally cleanup:false)
//                 to keep state across runs.

import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";
import * as path from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";
import { Elastik, ElastikError } from "./index.mjs";

const require = createRequire(import.meta.url);
loadDotenv();

// Map of (process.platform, process.arch) → npm package name + binary file.
// Keep in sync with the @elastikjs/core-* packages that actually exist.
// darwin-x64 was deliberately dropped from the Rust release matrix in
// 6.4.2 — Apple Silicon only on the Mac side.
const PLATFORM_PACKAGES = {
    "linux-x64":     { pkg: "@elastikjs/core-linux-x64",    file: "elastik-core" },
    "linux-arm64":   { pkg: "@elastikjs/core-linux-arm64",  file: "elastik-core" },
    "darwin-arm64":  { pkg: "@elastikjs/core-darwin-arm64", file: "elastik-core" },
    "win32-x64":     { pkg: "@elastikjs/core-win32-x64",    file: "elastik-core.exe" },
};

export class NoBinaryError extends Error {
    constructor(platform, arch) {
        const supported = Object.keys(PLATFORM_PACKAGES).join(", ");
        super(
            `No bundled elastik-core binary for ${platform}-${arch}.\n` +
            `Supported npm platforms: ${supported}.\n` +
            `Workarounds:\n` +
            `  - install the canonical Python wheel:    pip install elastik\n` +
            `    (then point the SDK at python -m elastik run)\n` +
            `  - build from source:                     cargo build --release\n` +
            `  - run @elastikjs/server (educational JS port; slower):\n` +
            `      npx @elastikjs/server@<exact-version>`
        );
        this.name = "NoBinaryError";
        this.platform = platform;
        this.arch = arch;
    }
}

/**
 * Find the bundled binary path for the running platform. Returns null if
 * the platform-specific @elastikjs/core-* package isn't installed (which is
 * the normal case when the optional dep failed to resolve, e.g. the user
 * is on a platform we don't ship).
 */
export function resolveBinary() {
    const key = `${process.platform}-${process.arch}`;
    const entry = PLATFORM_PACKAGES[key];
    if (!entry) return null;
    let pkgJsonPath;
    try {
        pkgJsonPath = require.resolve(`${entry.pkg}/package.json`);
    } catch {
        return null;
    }
    const dir = path.dirname(pkgJsonPath);
    const binary = path.join(dir, entry.file);
    if (!fs.existsSync(binary)) return null;
    // POSIX install from a Windows publisher can drop the +x bit. Restore
    // it before spawn — chmod is a no-op on Windows. Cheap and safe.
    if (process.platform !== "win32") {
        try { fs.chmodSync(binary, 0o755); } catch { /* best-effort */ }
    }
    return binary;
}

function freePort(host) {
    return new Promise((resolve, reject) => {
        // node:net `Server` will pick an OS-assigned free port if we listen on 0.
        const srv = createServer();
        srv.unref();
        srv.on("error", reject);
        srv.listen(0, host, () => {
            const { port } = srv.address();
            srv.close(() => resolve(port));
        });
    });
}

function urlHost(host) {
    if (host === "0.0.0.0") return "127.0.0.1";
    if (host === "::") return "[::1]";
    if (host.includes(":") && !host.startsWith("[")) return `[${host}]`;
    return host;
}

function spawnCore(binary, env, quiet) {
    let output = "";
    const child = spawn(binary, [], {
        env,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
    });

    const capture = (chunk, stream) => {
        const text = chunk.toString("utf8");
        output = (output + text).slice(-8192);
        if (!quiet) {
            (stream === "stderr" ? process.stderr : process.stdout).write(chunk);
        }
    };
    child.stdout?.on("data", (chunk) => capture(chunk, "stdout"));
    child.stderr?.on("data", (chunk) => capture(chunk, "stderr"));

    let exited = false;
    let exitCode = null;
    let exitSignal = null;
    let spawnError = null;
    const exitPromise = new Promise((resolve) => {
        child.on("error", (err) => {
            exited = true;
            spawnError = err;
            resolve({ error: err });
        });
        child.on("exit", (code, signal) => {
            exited = true;
            exitCode = code;
            exitSignal = signal;
            resolve({ code, signal });
        });
    });

    return {
        child,
        exitPromise,
        output: () => output.trim(),
        get exited() { return exited; },
        get exitCode() { return exitCode; },
        get exitSignal() { return exitSignal; },
        get spawnError() { return spawnError; },
    };
}

async function waitForStartup(url, core, deadlineMs = 10000) {
    const end = Date.now() + deadlineMs;
    while (Date.now() < end) {
        if (core.exited) return "exit";
        try {
            const res = await fetch(url, { signal: AbortSignal.timeout?.(500) ?? undefined });
            if (res.status > 0) return "ready";
        } catch { /* keep polling */ }
        if (core.exited) return "exit";
        await new Promise((r) => setTimeout(r, 50));
    }
    return core.exited ? "exit" : "timeout";
}

function startupError(core, host, port, reason) {
    const status = core.exited
        ? (core.spawnError
            ? `failed to spawn (${core.spawnError.message})`
            : `exited during startup (code=${core.exitCode}, signal=${core.exitSignal ?? "none"})`)
        : `failed to listen on ${host}:${port} within 10s`;
    const out = core.output();
    return new Error(
        `elastik-core ${status}${reason ? ` after ${reason}` : ""}` +
        (out ? `\n\ncore output:\n${out}` : "")
    );
}

function killCore(core) {
    try { core.child.kill("SIGKILL"); } catch { /* ignore */ }
}

/**
 * @typedef {Elastik & {
 *   url: string,
 *   dataDir: string,
 *   binary: string,
 *   process: import("node:child_process").ChildProcess,
 *   stop: () => Promise<void>
 * }} StartedElastik
 */

/**
 * Spawn a local elastik core, wait for it to listen, return an Elastik
 * client wired to it. Calling .stop() on the returned client kills the
 * child process and (by default) wipes its data directory.
 *
 * @param {object} [options]
 * @param {string} [options.key]          ELASTIK_KEY (HMAC). Defaults to .env/env or a random hex key.
 * @param {string} [options.host]         .env/env ELASTIK_HOST or "127.0.0.1"
 * @param {number} [options.port]         .env/env ELASTIK_PORT or OS-assigned if omitted
 * @param {string} [options.dataDir]      .env/env ELASTIK_DATA or a fresh temp dir
 * @param {string} [options.readToken]    .env/env ELASTIK_READ_TOKEN or writeToken; pass "" for public reads
 * @param {string} [options.writeToken]   .env/env ELASTIK_WRITE_TOKEN or a random session token; pass "" to disable writes
 * @param {string} [options.approveToken] .env/env ELASTIK_APPROVE_TOKEN or writeToken; needed for delete/admin writes
 * @param {boolean}[options.quiet]        suppress core stdout/stderr while capturing it for startup errors (default: true)
 * @param {boolean}[options.cleanup]      wipe dataDir on stop() (default: true if dataDir was auto-created)
 * @returns {Promise<StartedElastik>}
 */
export async function start(options = {}) {
    const binary = resolveBinary();
    if (!binary) throw new NoBinaryError(process.platform, process.arch);

    const host = options.host ?? process.env.ELASTIK_HOST ?? "127.0.0.1";
    // ELASTIK_KEY is mandatory for the core; pick something unique if not given.
    const key = options.key ?? process.env.ELASTIK_KEY ?? randomKey();
    const writeToken = pickOption(options, "writeToken", "ELASTIK_WRITE_TOKEN", randomToken);
    const readToken = pickOption(options, "readToken", "ELASTIK_READ_TOKEN", () => writeToken);
    const approveToken = pickOption(options, "approveToken", "ELASTIK_APPROVE_TOKEN", () => writeToken);
    const dataDirAutoCreated = options.dataDir == null && process.env.ELASTIK_DATA == null;
    const dataDir = options.dataDir ?? process.env.ELASTIK_DATA ?? fs.mkdtempSync(path.join(os.tmpdir(), "elastikjs-core-"));
    const cleanup = options.cleanup ?? dataDirAutoCreated;
    const quiet = options.quiet ?? true;
    const explicitPort = options.port != null || process.env.ELASTIK_PORT != null;
    let lastError = null;

    for (let attempt = 1; attempt <= (explicitPort ? 1 : 5); attempt++) {
        const port = explicitPort ? Number(options.port ?? process.env.ELASTIK_PORT) : await freePort(host);
        const env = {
            ...process.env,
            ELASTIK_KEY: key,
            ELASTIK_HOST: host,
            ELASTIK_PORT: String(port),
            ELASTIK_DATA: dataDir,
        };
        for (const [k, v] of [
            ["ELASTIK_READ_TOKEN", readToken],
            ["ELASTIK_WRITE_TOKEN", writeToken],
            ["ELASTIK_APPROVE_TOKEN", approveToken],
        ]) {
            if (v) env[k] = v;
            else delete env[k];
        }

        const core = spawnCore(binary, env, quiet);
        const baseUrl = `http://${urlHost(host)}:${port}`;
        const status = await waitForStartup(`${baseUrl}/proc/version`, core, 10000);
        if (status === "ready") {
            return attachClient(core, baseUrl, dataDir, binary, cleanup, {
                ...options,
                writeToken,
                readToken,
                approveToken,
            });
        }

        killCore(core);
        lastError = startupError(core, host, port, `attempt ${attempt}`);
        if (explicitPort || status !== "exit" || core.spawnError) break;
    }

    if (cleanup) safeRm(dataDir);
    throw lastError;
}

function attachClient(core, baseUrl, dataDir, binary, cleanup, options) {
    const client = new Elastik(baseUrl, {
        writeToken: options.writeToken,
        readToken: options.readToken,
        approveToken: options.approveToken,
    });

    // Lifecycle bag attached to the returned client.
    client.url = baseUrl;
    client.dataDir = dataDir;
    client.binary = binary;
    client.process = core.child;
    client.stop = async function stop() {
        if (!core.child || core.child.killed || core.exited) {
            if (cleanup) safeRm(dataDir);
            return;
        }
        await new Promise((resolve) => {
            core.child.once("exit", () => resolve());
            try { core.child.kill("SIGTERM"); } catch { resolve(); }
            // Force-kill if it doesn't go in 3 seconds.
            setTimeout(() => {
                if (!core.child.killed) try { core.child.kill("SIGKILL"); } catch { /* ignore */ }
                resolve();
            }, 3000).unref?.();
        });
        if (cleanup) safeRm(dataDir);
    };
    return client;
}

// Static-method form so users can `import { Elastik } from "@elastikjs/client/start"`
// and call Elastik.start(...) — matches the Python SDK's import-and-go feel.
Elastik.start = start;
export { Elastik, ElastikError };

function loadDotenv() {
    if (process.env.ELASTIK_NO_DOTENV === "1") return;
    const file = path.join(process.cwd(), ".env");
    let text;
    try { text = fs.readFileSync(file, "utf8"); } catch { return; }
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        const eq = line.indexOf("=");
        if (eq <= 0) continue;
        const key = line.slice(0, eq).trim();
        let value = line.slice(eq + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
            value = value.slice(1, -1);
        }
        if (process.env[key] == null) process.env[key] = value;
    }
}

function pickOption(options, optionName, envName, fallback) {
    if (Object.prototype.hasOwnProperty.call(options, optionName)) return options[optionName];
    if (process.env[envName] != null) return process.env[envName];
    return fallback();
}

function randomKey() {
    return randomBytes(32).toString("hex");
}

function randomToken() {
    return randomBytes(18).toString("base64url");
}

function safeRm(dir) {
    if (!dir) return;
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
}
