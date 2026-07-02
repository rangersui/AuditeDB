"""no_json.py: zero-tolerance structured-data scanner for Rust core text.

This is a blunt doctrine gate, not a Rust parser:

    NO SCHEMA. NO JSON. BYTES STAY BYTES.
    Metadata and payload stay physically separate.

The scanner reads raw `.rs` text and flags structured-data imports, macros,
derives, and exact media-type literals. It intentionally does not understand
Rust comments, strings, raw strings, test modules, or AST boundaries. If a test
needs a forbidden literal as an expected value, split it with `concat!`.

Run:

    python no_json.py                # scan this directory tree
    python no_json.py src            # scan one subdir

CI pins Python 3.12 and invokes this as `python core/no_json.py core/src`.
On Windows developer shells, use `python` or `py` if `python3` points
at the Microsoft Store stub.

Exits 0 clean, 1 if any violation. Wire into CI alongside `cargo test` so a
structured-data regression breaks the build.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


BAD_PATTERNS = [
    ("use serde_json",
     re.compile(r"\buse\s+serde_json\b")),
    ("use structured-data crate",
     re.compile(r"\buse\s+(serde_cbor|ciborium|minicbor|rmp_serde|prost|protobuf|capnp)\b")),
    ("serde_json::* path",
     re.compile(r"\bserde_json\s*::")),
    ("structured-data crate path",
     re.compile(r"\b(serde_cbor|ciborium|minicbor|rmp_serde|prost|protobuf|capnp)\s*::")),
    ("json! macro",
     re.compile(r"\bjson!\s*[\(\{]")),
    ("#[derive(Serialize)]",
     re.compile(r"#\s*\[\s*derive\s*\([^)]*\bSerialize\b[^)]*\)")),
    ("#[derive(Deserialize)]",
     re.compile(r"#\s*\[\s*derive\s*\([^)]*\bDeserialize\b[^)]*\)")),
    ('"application/json"',
     re.compile(r'"application/json\b[^"]*"')),
    ('"application/x-ndjson"',
     re.compile(r'"application/x-ndjson\b[^"]*"')),
    ('structured media type',
     re.compile(r'"application/(cbor|msgpack|vnd\.google\.protobuf|x-protobuf|yaml|x-yaml)\b[^"]*"')),
    ('Content-Type: application/json (string)',
     re.compile(r'"Content-Type:\s*application/json[^"]*"',
                re.IGNORECASE)),
]

SKIP_DIR_PARTS = {"target", "node_modules", ".git", ".cache",
                  "incremental", "deps", ".cargo"}
SKIP_FILE_NAMES = {"no_json.py"}
ALLOWED_EXTS = {".rs"}


def should_skip(path: Path) -> bool:
    if path.name in SKIP_FILE_NAMES:
        return True
    return any(p in SKIP_DIR_PARTS for p in path.parts)


def line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


def scan_file(path: Path) -> list[tuple[int, str]]:
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return [(0, f"read failed: {exc}")]
    violations = []
    seen = set()
    for name, pat in BAD_PATTERNS:
        for m in pat.finditer(src):
            line = line_of(src, m.start())
            key = (line, name)
            if key in seen:
                continue
            seen.add(key)
            violations.append((line, name))
    violations.sort()
    return violations


def collect_files(targets: list[Path]) -> tuple[list[Path], list[Path]]:
    """Returns (matched_files, missing_targets). A typo'd path must
    not look like a clean scan."""
    out: list[Path] = []
    missing: list[Path] = []
    for t in targets:
        if not t.exists():
            missing.append(t)
            continue
        if t.is_file() and t.suffix in ALLOWED_EXTS:
            if not should_skip(t):
                out.append(t)
        elif t.is_dir():
            for f in sorted(t.rglob("*")):
                if f.is_file() and f.suffix in ALLOWED_EXTS \
                        and not should_skip(f):
                    out.append(f)
    return out, missing


def main(argv: list[str]) -> int:
    targets = ([Path(a) for a in argv[1:]]
               if len(argv) > 1
               else [Path(__file__).resolve().parent])
    files, missing = collect_files(targets)
    if missing:
        for t in missing:
            print(f"no_json: cannot stat {t} (does not exist)",
                  file=sys.stderr)
        return 2
    if not files:
        print("no_json: no .rs files found", file=sys.stderr)
        return 2

    bad: dict[Path, list[tuple[int, str]]] = {}
    for f in files:
        v = scan_file(f)
        if v:
            bad[f] = v

    if not bad:
        print(f"no_json: clean ({len(files)} rust files scanned)")
        return 0

    total = 0
    for path in sorted(bad):
        print(f"\n{path.as_posix()}")
        for lineno, msg in bad[path]:
            print(f"  line {lineno}: {msg}")
            total += 1
    print(f"\n[FAIL] {len(bad)} files have structured data, {total} violations total")
    print("       AuditeDB stores metadata separately from bodies.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
