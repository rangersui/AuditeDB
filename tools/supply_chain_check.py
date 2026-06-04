#!/usr/bin/env python3
"""Supply-chain gates for Elastik's split Rust crates.

Cargo audit catches RustSec advisories for Rust crates, but bundled native
SQLite lives inside libsqlite3-sys and needs an explicit native-version check.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = [
    ROOT / "core" / "Cargo.toml",
    ROOT / "bin" / "Cargo.toml",
    ROOT / "ffi" / "Cargo.toml",
]
LOCKS = [
    ROOT / "core" / "Cargo.lock",
    ROOT / "bin" / "Cargo.lock",
    ROOT / "ffi" / "Cargo.lock",
]
MIN_LIBSQLITE3_SYS = (0, 38, 0)
MIN_BUNDLED_SQLITE = (3, 53, 1)


def run(args: list[str]) -> None:
    print("+ " + " ".join(args), flush=True)
    subprocess.run(args, cwd=ROOT, check=True)


def parse_version(raw: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in raw.split("."))
    except ValueError as exc:
        raise SystemExit(f"invalid version string: {raw}") from exc


def version_at_least(found: tuple[int, ...], minimum: tuple[int, ...]) -> bool:
    width = max(len(found), len(minimum))
    return found + (0,) * (width - len(found)) >= minimum + (0,) * (width - len(minimum))


def find_package_versions(lock: Path, package: str) -> set[str]:
    versions: set[str] = set()
    current_name: str | None = None
    current_version: str | None = None

    for raw_line in lock.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == "[[package]]":
            if current_name == package and current_version is not None:
                versions.add(current_version)
            current_name = None
            current_version = None
            continue
        if line.startswith("name = "):
            current_name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = "):
            current_version = line.split("=", 1)[1].strip().strip('"')

    if current_name == package and current_version is not None:
        versions.add(current_version)
    return versions


def registry_roots() -> list[Path]:
    cargo_home = os.environ.get("CARGO_HOME")
    roots = []
    if cargo_home:
        roots.append(Path(cargo_home) / "registry" / "src")
    roots.append(Path.home() / ".cargo" / "registry" / "src")
    return roots


def find_crate_source(crate: str, version: str) -> Path | None:
    dirname = f"{crate}-{version}"
    for root in registry_roots():
        if not root.exists():
            continue
        for candidate in root.glob(f"*/{dirname}"):
            if candidate.is_dir():
                return candidate
    return None


def bundled_sqlite_version(crate_source: Path) -> str:
    header = crate_source / "sqlite3" / "sqlite3.h"
    if not header.exists():
        raise SystemExit(f"missing bundled sqlite header: {header}")
    match = re.search(
        r'#define\s+SQLITE_VERSION\s+"([^"]+)"',
        header.read_text(encoding="utf-8", errors="replace"),
    )
    if not match:
        raise SystemExit(f"could not read SQLITE_VERSION from {header}")
    return match.group(1)


def check_bundled_sqlite() -> None:
    print("==> bundled SQLite version check", flush=True)
    versions_by_lock: dict[Path, set[str]] = {
        lock: find_package_versions(lock, "libsqlite3-sys") for lock in LOCKS
    }
    all_versions = set().union(*versions_by_lock.values())
    if not all_versions:
        raise SystemExit("libsqlite3-sys not found in Cargo.lock files")

    for lock, versions in versions_by_lock.items():
        if not versions:
            raise SystemExit(f"libsqlite3-sys missing from {lock.relative_to(ROOT)}")
        if len(versions) != 1:
            raise SystemExit(
                f"{lock.relative_to(ROOT)} has multiple libsqlite3-sys versions: {sorted(versions)}"
            )

    for version in sorted(all_versions):
        parsed = parse_version(version)
        if not version_at_least(parsed, MIN_LIBSQLITE3_SYS):
            raise SystemExit(
                "libsqlite3-sys "
                f"{version} is below required {'.'.join(map(str, MIN_LIBSQLITE3_SYS))}"
            )
        source = find_crate_source("libsqlite3-sys", version)
        if source is None:
            print(f"libsqlite3-sys {version} source missing; running cargo fetch", flush=True)
            run(["cargo", "fetch", "--manifest-path", str(ROOT / "core" / "Cargo.toml")])
            source = find_crate_source("libsqlite3-sys", version)
        if source is None:
            raise SystemExit(f"could not locate libsqlite3-sys {version} source after cargo fetch")

        sqlite_version = bundled_sqlite_version(source)
        if not version_at_least(parse_version(sqlite_version), MIN_BUNDLED_SQLITE):
            raise SystemExit(
                "bundled SQLite "
                f"{sqlite_version} is below required {'.'.join(map(str, MIN_BUNDLED_SQLITE))}"
            )
        print(f"libsqlite3-sys {version} bundles SQLite {sqlite_version}", flush=True)


def check_audit() -> None:
    print("==> cargo audit", flush=True)
    for lock in LOCKS:
        run(["cargo", "audit", "-f", str(lock)])


def check_deny() -> None:
    print("==> cargo deny", flush=True)
    for manifest in MANIFESTS:
        run(
            [
                "cargo",
                "deny",
                "--locked",
                "--all-features",
                "--manifest-path",
                str(manifest),
                "check",
                "advisories",
                "bans",
                "sources",
                "licenses",
            ]
        )


def check_machete() -> None:
    print("==> cargo machete", flush=True)
    run(["cargo", "machete", "--skip-target-dir", "core", "bin", "ffi"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["prepush", "ci"])
    args = parser.parse_args()

    check_bundled_sqlite()
    check_audit()
    if args.mode == "ci":
        check_deny()
        check_machete()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc
