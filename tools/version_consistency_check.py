#!/usr/bin/env python3
"""Fail if AuditeDB/L5 release version surfaces drift apart."""

from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

ACTIVE_TEXT_SURFACES = [
    ROOT / "README.md",
    ROOT / "bin" / "src" / "server" / "http" / "README.md",
    ROOT / "ffi" / "README.md",
]

ACTIVE_TEXT_VERSION_PATTERNS = [
    ("AuditeDB release label", re.compile(r"\bAuditeDB\s+v(\d+\.\d+\.\d+)\b")),
    ("GitHub release tag", re.compile(r"/releases/tag/v(\d+\.\d+\.\d+)\b")),
    ("AuditeDB binary version", re.compile(r"\bauditedb\s+v?(\d+\.\d+\.\d+)\b")),
    ("L5 crate version", re.compile(r"\bl5\s+v?(\d+\.\d+\.\d+)\b")),
]


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_toml(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


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
    path = ROOT / "release_notes" / f"RELEASE-NOTES-v{expected}.md"
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    first_line = text.splitlines()[0] if text.splitlines() else ""
    release_heading_prefixes = (
        f"# AuditeDB v{expected}",
    )
    if not first_line.startswith(release_heading_prefixes):
        errors.append(
            f"{rel(path)}: release heading {first_line!r} does not start with "
            f"{release_heading_prefixes!r}"
        )
    artifact_snippets = [
        f"`l5` `{expected}`",
        f"`auditedb` `{expected}`",
        f"`l5-ffi` `{expected}`",
    ]
    for snippet in artifact_snippets:
        if snippet not in text:
            errors.append(f"{rel(path)}: missing artifact version {snippet!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", help="Release tag or ref, for example v8.2.1 or refs/tags/v8.2.1")
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

    check_lock(errors, ROOT / "core" / "Cargo.lock", "l5", expected)
    check_lock(errors, ROOT / "bin" / "Cargo.lock", "l5", expected)
    check_lock(errors, ROOT / "bin" / "Cargo.lock", "auditedb", expected)
    check_lock(errors, ROOT / "ffi" / "Cargo.lock", "l5", expected)
    check_lock(errors, ROOT / "ffi" / "Cargo.lock", "l5-ffi", expected)

    check_equal(errors, "sdk/pyproject.toml", pyproject_version(ROOT / "sdk" / "pyproject.toml"), expected)
    init_text = (ROOT / "sdk" / "src" / "l5" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', init_text, re.MULTILINE)
    check_equal(errors, "sdk/src/l5/__init__.py __version__", match.group(1) if match else None, expected)

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
