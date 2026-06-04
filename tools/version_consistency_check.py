#!/usr/bin/env python3
"""Fail if Elastik release version surfaces drift apart."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

CORE_PLATFORMS = {
    "@elastikjs/core-linux-x64": ROOT / "sdk-js" / "core-linux-x64" / "package.json",
    "@elastikjs/core-linux-arm64": ROOT / "sdk-js" / "core-linux-arm64" / "package.json",
    "@elastikjs/core-darwin-arm64": ROOT / "sdk-js" / "core-darwin-arm64" / "package.json",
    "@elastikjs/core-win32-x64": ROOT / "sdk-js" / "core-win32-x64" / "package.json",
}

ACTIVE_TEXT_SURFACES = [
    ROOT / "README.md",
    ROOT / "bin" / "src" / "server" / "http" / "README.md",
    ROOT / "bin" / "src" / "server" / "mqtt" / "README.md",
    ROOT / "bin" / "src" / "server" / "coap" / "README.md",
    ROOT / "ffi" / "README.md",
    ROOT / "sdk" / "README.md",
    ROOT / "sdk-js" / "README.md",
    ROOT / "sdk-js" / "scripts" / "pack-platform.mjs",
]

ACTIVE_TEXT_VERSION_PATTERNS = [
    ("Elastik release label", re.compile(r"\bElastik\s+v(\d+\.\d+\.\d+)\b")),
    ("GitHub release tag", re.compile(r"/releases/tag/v(\d+\.\d+\.\d+)\b")),
    ("elastik-core version", re.compile(r"\belastik-core\s+v?(\d+\.\d+\.\d+)\b")),
    ("pack-platform --version", re.compile(r"--version\s+(\d+\.\d+\.\d+)\b")),
]


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_toml(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def package_version(path: Path) -> str:
    return load_toml(path)["package"]["version"]


def pyproject_version(path: Path) -> str:
    return load_toml(path)["project"]["version"]


def lock_package_versions(path: Path, package: str) -> list[str]:
    return [
        entry["version"]
        for entry in load_toml(path).get("package", [])
        if entry.get("name") == package
    ]


def normalize_tag(raw: str) -> str:
    tag = raw.strip()
    if tag.startswith("refs/tags/"):
        tag = tag.removeprefix("refs/tags/")
    if tag.startswith("v"):
        tag = tag[1:]
    return tag


def infer_tag_arg(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    ref = os.environ.get("GITHUB_REF", "")
    name = os.environ.get("GITHUB_REF_NAME", "")
    if ref.startswith("refs/tags/v") and name:
        return name
    return None


def check_equal(errors: list[str], label: str, found: str | None, expected: str) -> None:
    if found != expected:
        errors.append(f"{label}: {found!r} != {expected!r}")


def check_lock(errors: list[str], path: Path, package: str, expected: str) -> None:
    versions = lock_package_versions(path, package)
    if versions != [expected]:
        errors.append(f"{rel(path)} package {package}: {versions!r} != [{expected!r}]")


def check_active_text_versions(errors: list[str], expected: str) -> None:
    for path in ACTIVE_TEXT_SURFACES:
        if not path.exists():
            errors.append(f"{rel(path)}: missing active text surface")
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for label, pattern in ACTIVE_TEXT_VERSION_PATTERNS:
                for match in pattern.finditer(line):
                    found = match.group(1)
                    if found != expected:
                        errors.append(
                            f"{rel(path)}:{lineno}: {label} {found!r} != {expected!r}"
                        )


def check_release_note(errors: list[str], expected: str) -> None:
    path = ROOT / f"RELEASE-NOTES-v{expected}.md"
    if not path.exists():
        errors.append(f"{rel(path)}: missing release notes for {expected}")
        return
    text = path.read_text(encoding="utf-8")
    required = [
        f"# Elastik v{expected} -",
        f"v{expected} is a",
        f"`elastik-core` `{expected}`",
        f"to resolve to {expected} after",
        f"`cargo add elastik-core` will report {expected}",
        f"`elastik-bin` `{expected}`",
        f"`elastik-ffi` `{expected}`",
        f"`elastik` `{expected}`",
        f"`@elastikjs/client` `{expected}`",
        f"`@elastikjs/core-linux-x64` `{expected}`",
        f"`@elastikjs/core-linux-arm64` `{expected}`",
        f"`@elastikjs/core-darwin-arm64` `{expected}`",
        f"`@elastikjs/core-win32-x64` `{expected}`",
    ]
    for snippet in required:
        if snippet not in text:
            errors.append(f"{rel(path)}: missing {snippet!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", help="Release tag or ref, for example v8.2.0 or refs/tags/v8.2.0")
    args = parser.parse_args()

    errors: list[str] = []
    expected = package_version(ROOT / "core" / "Cargo.toml")
    if not re.fullmatch(r"\d+\.\d+\.\d+", expected):
        errors.append(f"core/Cargo.toml version is not semver X.Y.Z: {expected!r}")

    tag = infer_tag_arg(args.tag)
    if tag:
        check_equal(errors, "release tag", normalize_tag(tag), expected)

    check_equal(errors, "bin/Cargo.toml", package_version(ROOT / "bin" / "Cargo.toml"), expected)
    check_equal(errors, "ffi/Cargo.toml", package_version(ROOT / "ffi" / "Cargo.toml"), expected)

    check_lock(errors, ROOT / "core" / "Cargo.lock", "elastik-core", expected)
    check_lock(errors, ROOT / "bin" / "Cargo.lock", "elastik-core", expected)
    check_lock(errors, ROOT / "bin" / "Cargo.lock", "elastik-bin", expected)
    check_lock(errors, ROOT / "ffi" / "Cargo.lock", "elastik-core", expected)
    check_lock(errors, ROOT / "ffi" / "Cargo.lock", "elastik-ffi", expected)

    check_equal(errors, "sdk/pyproject.toml", pyproject_version(ROOT / "sdk" / "pyproject.toml"), expected)
    init_text = (ROOT / "sdk" / "src" / "elastik" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', init_text, re.MULTILINE)
    check_equal(errors, "sdk/src/elastik/__init__.py __version__", match.group(1) if match else None, expected)

    client = load_json(ROOT / "sdk-js" / "package.json")
    check_equal(errors, "sdk-js/package.json version", client.get("version"), expected)
    optional = client.get("optionalDependencies", {})
    if set(optional) != set(CORE_PLATFORMS):
        errors.append(
            "sdk-js/package.json optionalDependencies: "
            f"{sorted(optional)} != {sorted(CORE_PLATFORMS)}"
        )
    for package_name in sorted(CORE_PLATFORMS):
        check_equal(errors, f"sdk-js/package.json optional {package_name}", optional.get(package_name), expected)
        package_json = load_json(CORE_PLATFORMS[package_name])
        check_equal(errors, f"{rel(CORE_PLATFORMS[package_name])} name", package_json.get("name"), package_name)
        check_equal(errors, f"{rel(CORE_PLATFORMS[package_name])} version", package_json.get("version"), expected)

    check_active_text_versions(errors, expected)
    check_release_note(errors, expected)

    if errors:
        print("version consistency check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"version consistency ok: {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
