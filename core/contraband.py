"""contraband.py: blunt Rust core scanner for non-Clippy doctrine gates.

Sibling of `core/no_json.py`. This is a raw-text grep gate, not a Rust parser.
It intentionally does not understand comments, strings, raw strings, test
modules, or AST boundaries. Production `.unwrap()` and `println!` enforcement
belongs to Clippy (`unwrap_used` / `print_stdout`), not this script.

Rules enforced here:

  no_yaml             use serde_yaml / serde_yml / yaml_rust / quick_xml.
                      Config goes through env vars, not schema files.

  no_toml_parse       use toml::from_str / toml::to_string. Cargo.toml itself
                      is fine; src/*.rs must not parse TOML at runtime.

  no_last_modified    "last-modified", header::LAST_MODIFIED, or bare
                      LAST_MODIFIED. Audit replay must be the only freshness.

  no_hardcoded_secrets  hardcoded Bearer/api_key/secret-like string literals.
                        Tests that need fake credentials should build them
                        from split literals.

Run:

  python contraband.py                    # scan from this directory
  python contraband.py src                # one subdir
  python contraband.py --only no_yaml     # one rule

CI pins Python 3.12 and invokes this as `python core/contraband.py ...`.
On Windows developer shells, use `python` or `py` if `python3` points
at the Microsoft Store stub.

Exit 0 when clean, 1 when any rule fires. Each violation prints with
the rule name so CI can route.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


RULES = [
    {
        "name": "no_yaml",
        "patterns": [
            ("use serde_yaml",    re.compile(r"\buse\s+serde_yaml\b")),
            ("use serde_yml",     re.compile(r"\buse\s+serde_yml\b")),
            ("use yaml_rust",     re.compile(r"\buse\s+yaml_rust\b")),
            ("use quick_xml",     re.compile(r"\buse\s+quick_xml\b")),
            ("use xml_rs",        re.compile(r"\buse\s+xml_rs\b")),
            ("serde_yaml::*",     re.compile(r"\bserde_yaml\s*::")),
            ("yaml_rust::*",      re.compile(r"\byaml_rust\s*::")),
        ],
        "message": ("config goes through env vars; "
                    "no schema'd files in core source"),
    },
    {
        "name": "no_toml_parse",
        "patterns": [
            ("toml::from_str",    re.compile(r"\btoml\s*::\s*from_str\b")),
            ("toml::to_string",   re.compile(r"\btoml\s*::\s*to_string\b")),
            ("toml::de::*",       re.compile(r"\btoml\s*::\s*de\s*::")),
            ("toml::ser::*",      re.compile(r"\btoml\s*::\s*ser\s*::")),
            ("use toml::",        re.compile(r"\buse\s+toml\s*::")),
        ],
        "message": ("Cargo.toml is fine; src/*.rs must not parse TOML at runtime"),
    },
    {
        "name": "no_last_modified",
        "patterns": [
            ('"last-modified" string',
             re.compile(r'"last-modified"', re.IGNORECASE)),
            ("header::LAST_MODIFIED",
             re.compile(r"\bheader\s*::\s*LAST_MODIFIED\b")),
            ("LAST_MODIFIED identifier",
             re.compile(r"(?<!:)\bLAST_MODIFIED\b")),
        ],
        "message": ("Last-Modified bypasses the audit chain as a freshness signal; "
                    "remove it from any DEFAULT_PERSIST_HEADERS list"),
    },
    {
        "name": "no_hardcoded_secrets",
        "patterns": [
            ('Bearer <hardcoded>',
             re.compile(r'"Bearer\s+[A-Za-z0-9._\-]+"')),
            ('Authorization: Bearer literal',
             re.compile(r'"Authorization:\s*Bearer\s+\S+"', re.IGNORECASE)),
            ('api_key = "..."',
             re.compile(r'\bapi[_-]?key\s*[:=]\s*"[^"]{8,}"', re.IGNORECASE)),
            ('secret = "..."',
             re.compile(r'\bsecret\s*[:=]\s*"[^"]{8,}"', re.IGNORECASE)),
        ],
        "message": ("read tokens/keys from env or boot config; "
                    "never inline a literal secret in source"),
    },
]

SKIP_DIR_PARTS = {"target", "node_modules", ".git", ".cache",
                  "incremental", "deps", ".cargo"}
SKIP_FILE_NAMES = {"contraband.py", "no_json.py"}


def should_skip(path: Path) -> bool:
    if path.name in SKIP_FILE_NAMES:
        return True
    return any(p in SKIP_DIR_PARTS for p in path.parts)


def line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


def scan_file(path: Path, rules: list) -> list[tuple[str, int, str]]:
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return [("read_error", 0, f"read failed: {exc}")]
    seen = set()
    out = []
    for rule in rules:
        for label, pat in rule["patterns"]:
            for m in pat.finditer(src):
                line = line_of(src, m.start())
                key = (rule["name"], line, label)
                if key in seen:
                    continue
                seen.add(key)
                out.append((rule["name"], line, label))
    out.sort(key=lambda t: (t[1], t[0]))
    return out


def collect_files(targets: list[Path]) -> tuple[list[Path], list[Path]]:
    """Returns (matched_files, missing_targets). A typo'd path must
    not look like a clean scan."""
    files: list[Path] = []
    missing: list[Path] = []
    for t in targets:
        if not t.exists():
            missing.append(t)
            continue
        if t.is_file() and t.suffix == ".rs":
            if not should_skip(t):
                files.append(t)
        elif t.is_dir():
            for f in sorted(t.rglob("*.rs")):
                if not should_skip(f):
                    files.append(f)
    return files, missing


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*",
                    help="files or directories to scan")
    ap.add_argument("--only", action="append", default=[],
                    help="run only these rules (repeatable). "
                         "Available: %s"
                         % ", ".join(r["name"] for r in RULES))
    args = ap.parse_args(argv[1:])

    rules = RULES
    if args.only:
        keep = set(args.only)
        unknown = keep - {r["name"] for r in RULES}
        if unknown:
            print("unknown rule(s): %s" % ", ".join(sorted(unknown)))
            return 2
        rules = [r for r in RULES if r["name"] in keep]

    targets = ([Path(p) for p in args.paths]
               if args.paths
               else [Path(__file__).resolve().parent])
    files, missing = collect_files(targets)
    if missing:
        for t in missing:
            print(f"contraband: cannot stat {t} (does not exist)",
                  file=sys.stderr)
        return 2
    if not files:
        print("contraband: no .rs files found", file=sys.stderr)
        return 2

    by_file: dict[Path, list[tuple[str, int, str]]] = {}
    for f in files:
        v = scan_file(f, rules)
        if v:
            by_file[f] = v

    if not by_file:
        print("contraband: clean (%d rust files scanned, %d rules)"
              % (len(files), len(rules)))
        return 0

    by_rule: dict[str, int] = {}
    total = 0
    for path in sorted(by_file):
        print("\n%s" % path.as_posix())
        for rule_name, line, label in by_file[path]:
            print("  line %d  [%s]  %s" % (line, rule_name, label))
            by_rule[rule_name] = by_rule.get(rule_name, 0) + 1
            total += 1

    print("\n[FAIL] %d files, %d violations across %d rules"
          % (len(by_file), total, len(by_rule)))
    print("       breakdown:")
    rule_lookup = {r["name"]: r for r in rules}
    for name in sorted(by_rule):
        print("       %-22s %d  -- %s"
              % (name, by_rule[name], rule_lookup[name]["message"]))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
