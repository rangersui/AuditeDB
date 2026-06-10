#!/usr/bin/env node
// pack-platform.mjs — populate one core-${plat}-${arch}/ dir with the binary
// CI just built, then `npm pack` it.
//
// Used by the release pipeline: cargo build --release on the matrix runner
// produces an elastik-core[.exe] artifact; this script:
//   1. takes the path to that binary,
//   2. derives the platform/arch from CLI args (or runner env),
//   3. copies the binary into sdk-js/core-${plat}-${arch}/,
//   4. ensures executable bit is set on POSIX,
//   5. optionally syncs package.json version from the release tag,
//   6. optionally runs `npm pack` to produce the publishable .tgz.
//
// Usage:
//   node scripts/pack-platform.mjs <plat> <arch> <binary-path> [--version <version>] [--pack]
// Example:
//   node scripts/pack-platform.mjs linux x64 /tmp/elastik-core --version 8.3.0 --pack
//
// On the win32 runner the binary is elastik-core.exe; everywhere else it's
// elastik-core. The script auto-detects from the source filename.

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const SDK_JS = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

function die(msg) { console.error(`pack-platform: ${msg}`); process.exit(1); }

const [, , plat, arch, src, ...rest] = process.argv;
if (!plat || !arch || !src) {
    die("usage: node scripts/pack-platform.mjs <plat> <arch> <binary-path> [--version <version>] [--pack]");
}
if (!fs.existsSync(src)) die(`binary not found: ${src}`);

function optionValue(name) {
    const index = rest.indexOf(name);
    if (index === -1) return null;
    const value = rest[index + 1];
    if (!value || value.startsWith("--")) die(`${name} requires a value`);
    return value;
}

const pkgDir = path.join(SDK_JS, `core-${plat}-${arch}`);
if (!fs.existsSync(pkgDir)) die(`no platform package dir: ${pkgDir}`);

const version = optionValue("--version");
if (version) {
    const pkgPath = path.join(pkgDir, "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    pkg.version = version;
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
    console.log(`pack-platform: set ${pkg.name} version to ${version}`);
}

const targetName = src.endsWith(".exe") || plat === "win32"
    ? "elastik-core.exe"
    : "elastik-core";
const dst = path.join(pkgDir, targetName);

fs.copyFileSync(src, dst);
if (plat !== "win32") {
    try { fs.chmodSync(dst, 0o755); } catch { /* ignore */ }
}

const size = fs.statSync(dst).size;
console.log(`pack-platform: copied ${size} bytes → ${dst}`);

if (rest.includes("--pack")) {
    const result = spawnSync("npm", ["pack"], { cwd: pkgDir, stdio: "inherit", shell: true });
    if (result.status !== 0) die("npm pack failed");
    console.log(`pack-platform: produced .tgz in ${pkgDir}`);
}
