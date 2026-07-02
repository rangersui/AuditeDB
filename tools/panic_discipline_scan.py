#!/usr/bin/env python3
"""Check documented exceptions to the unwrap/expect lint gate."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


LINTS = ("clippy::unwrap_used", "clippy::expect_used")
GROUP_LINTS = ("clippy::restriction", "clippy::all")
DOC_MARKERS = ("Invariant:", "Poison means")
SUPPRESSOR_RE = re.compile(r"\b(allow|expect)\s*\(")
PANIC_METHOD = r"(?:r#)?(unwrap|expect|unwrap_err|expect_err)"
PANIC_CALL_RE = re.compile(
    rf"(?:\.\s*{PANIC_METHOD}\s*(?:::\s*<[^{{}}]*>)?\s*\("
    rf"|::\s*{PANIC_METHOD}\s*(?:::\s*<[^{{}}]*>)?\s*\()"
)
PANIC_PATH_ITEM_RE = re.compile(rf"::\s*{PANIC_METHOD}\b")
PANIC_IDENT_RE = re.compile(rf"\b{PANIC_METHOD}\b")
MACRO_INVOKE_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*!\s*([\(\{\[])")
ITEM_RE = re.compile(
    r"^(?:pub\s*(?:\([^)]*\))?\s+)?"
    r"(?:(?:async|const|unsafe|extern)\s+)*"
    r"(?:(fn|mod|struct|enum|trait|impl|type|const|static|use)\b|macro_rules\s*!)"
)
TEST_ATTR_PREFIXES = ("#[cfg(test)]", "#![cfg(test)]")
TEST_CFG_ATTR_PREFIXES = ("#[cfg_attr(test,", "#![cfg_attr(test,")
TEST_ITEM_PREFIXES = ("#[cfg(test)]", "#[test]", "#[tokio::test]")
PATH_ATTR_RE = re.compile(r"#\s*\[\s*path\s*=\s*\"([^\"]+)\"\s*\]")
MODULE_DECL_RE = re.compile(
    r"^(?:pub\s*(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
)


@dataclass(frozen=True)
class Attribute:
    start: int
    end: int
    text: str


def collect_attributes(lines: list[str]) -> list[Attribute]:
    attrs: list[Attribute] = []
    idx = 0
    while idx < len(lines):
        token_line = rust_token_text(lines[idx])
        attr_start = token_line.find("#[")
        inner_start = token_line.find("#![")
        starts = [pos for pos in (attr_start, inner_start) if pos >= 0]
        if not starts:
            idx += 1
            continue

        column = min(starts)
        start = idx
        parts = [lines[idx][column:]]
        balance = bracket_balance("\n".join(parts))
        idx += 1
        while balance > 0 and idx < len(lines):
            parts.append(lines[idx])
            balance = bracket_balance("\n".join(parts))
            idx += 1
        attrs.append(Attribute(start=start, end=idx - 1, text="\n".join(parts)))
    return attrs


def rust_token_text(text: str) -> str:
    out: list[str] = []
    idx = 0
    in_string = False
    in_char = False
    escaped = False
    raw_hashes: int | None = None
    block_depth = 0

    while idx < len(text):
        char = text[idx]
        next_char = text[idx + 1] if idx + 1 < len(text) else ""
        if block_depth:
            if char == "/" and next_char == "*":
                out.extend((" ", " "))
                block_depth += 1
                idx += 2
                continue
            if char == "*" and next_char == "/":
                out.extend((" ", " "))
                block_depth -= 1
                idx += 2
                continue
            out.append("\n" if char == "\n" else " ")
            idx += 1
            continue
        if raw_hashes is not None:
            if char == '"' and text.startswith("#" * raw_hashes, idx + 1):
                out.extend(" " * (raw_hashes + 1))
                idx += raw_hashes + 1
                raw_hashes = None
                continue
            else:
                out.append("\n" if char == "\n" else " ")
            idx += 1
            continue
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            out.append("\n" if char == "\n" else " ")
            idx += 1
            continue
        if in_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "'":
                in_char = False
            out.append("\n" if char == "\n" else " ")
            idx += 1
            continue

        if char == "/" and next_char == "/":
            out.extend((" ", " "))
            idx += 2
            while idx < len(text) and text[idx] != "\n":
                out.append(" ")
                idx += 1
            continue
        if char == "/" and next_char == "*":
            out.extend((" ", " "))
            block_depth = 1
            idx += 2
            continue
        if char == "r":
            probe = idx + 1
            while probe < len(text) and text[probe] == "#":
                probe += 1
            if probe < len(text) and text[probe] == '"':
                raw_hashes = probe - idx - 1
                out.extend(" " * (probe - idx + 1))
                idx = probe + 1
                continue
        if char == '"':
            in_string = True
            out.append(" ")
        elif char == "'":
            probe = idx + 1
            if probe < len(text) and re.match(r"[A-Za-z_]", text[probe]):
                probe += 1
                while probe < len(text) and re.match(r"[A-Za-z0-9_]", text[probe]):
                    probe += 1
                if probe < len(text) and text[probe] == "'":
                    in_char = True
                    out.append(" ")
                else:
                    out.append(char)
            else:
                in_char = True
                out.append(" ")
        else:
            out.append(char)
        idx += 1
    return "".join(out)


def bracket_balance(text: str) -> int:
    token_text = rust_token_text(text)
    return token_text.count("[") - token_text.count("]")


def normalize_inline_attributes(text: str) -> str:
    token_text = rust_token_text(text)
    out: list[str] = []
    idx = 0
    while idx < len(text):
        attr_starts = [
            pos
            for pos in (token_text.find("#[", idx), token_text.find("#![", idx))
            if pos >= 0
        ]
        if not attr_starts:
            out.append(text[idx:])
            break

        start = min(attr_starts)
        if start > idx:
            out.append(text[idx:start])
        if out and not out[-1].endswith("\n"):
            out.append("\n")

        depth = 0
        end = start
        while end < len(text):
            if token_text[end] == "[":
                depth += 1
            elif token_text[end] == "]":
                depth -= 1
                if depth == 0:
                    end += 1
                    break
            end += 1

        out.append(text[start:end])
        if end < len(text) and text[end] != "\n":
            out.append("\n")
        idx = end
    return "".join(out)


def read_rust_lines(path: Path) -> list[str]:
    return normalize_inline_attributes(path.read_text(encoding="utf-8")).splitlines()


def normalize_lint_text(text: str) -> str:
    token_text = rust_token_text(text)
    return re.sub(r"\s*::\s*", "::", token_text)


def is_lint_suppressor(attr: Attribute) -> bool:
    text = normalize_lint_text(attr.text)
    if not SUPPRESSOR_RE.search(text):
        return False
    return "$" in text or any(lint in text for lint in (*LINTS, *GROUP_LINTS))


def is_macro_metavar_suppressor(attr: Attribute) -> bool:
    return "$" in normalize_lint_text(attr.text)


def is_group_suppressor(attr: Attribute) -> bool:
    text = normalize_lint_text(attr.text)
    return any(lint in text for lint in GROUP_LINTS)


def suppressed_methods(attr: Attribute) -> set[str]:
    text = normalize_lint_text(attr.text)
    methods: set[str] = set()
    if "clippy::unwrap_used" in text:
        methods.update(("unwrap", "unwrap_err"))
    if "clippy::expect_used" in text:
        methods.update(("expect", "expect_err"))
    return methods


def is_test_only_allow(attr: Attribute, attrs: list[Attribute]) -> bool:
    text = re.sub(r"\s+", "", normalize_lint_text(attr.text))
    if text.startswith(TEST_CFG_ATTR_PREFIXES):
        return True

    for prev in reversed(attrs):
        if prev.end >= attr.start:
            continue
        gap = attr.start - prev.end
        if gap > 1:
            break
        prev_text = re.sub(r"\s+", "", normalize_lint_text(prev.text))
        if prev_text in TEST_ATTR_PREFIXES:
            return True
        if prev.text.lstrip().startswith("#["):
            continue
        break
    return False


def is_test_item_attr(attr: Attribute) -> bool:
    text = re.sub(r"\s+", "", normalize_lint_text(attr.text))
    return any(text.startswith(prefix) for prefix in TEST_ITEM_PREFIXES)


def skip_attribute(lines: list[str], idx: int) -> int:
    balance = 0
    while idx < len(lines):
        token_line = rust_token_text(lines[idx])
        attr_start = token_line.find("#[")
        inner_start = token_line.find("#![")
        starts = [pos for pos in (attr_start, inner_start) if pos >= 0]
        if starts and balance == 0:
            balance += bracket_balance(lines[idx][min(starts) :])
        else:
            balance += bracket_balance(lines[idx])
        idx += 1
        if balance <= 0:
            return idx
    return idx


def first_code_line_after_attr(lines: list[str], attr: Attribute) -> int | None:
    idx = attr.end + 1
    while idx < len(lines):
        stripped = rust_token_text(lines[idx]).strip()
        if not stripped:
            idx += 1
            continue
        if stripped.startswith("#[") or stripped.startswith("#!["):
            idx = skip_attribute(lines, idx)
            continue
        break
    if idx >= len(lines):
        return None
    return idx


def attrs_until_item(lines: list[str], attr: Attribute) -> list[Attribute]:
    attrs: list[Attribute] = []
    idx = attr.end + 1
    while idx < len(lines):
        stripped = rust_token_text(lines[idx]).strip()
        if not stripped:
            idx += 1
            continue
        if not (stripped.startswith("#[") or stripped.startswith("#![")):
            break
        start = idx
        parts = [lines[idx]]
        balance = bracket_balance("\n".join(parts))
        idx += 1
        while balance > 0 and idx < len(lines):
            parts.append(lines[idx])
            balance = bracket_balance("\n".join(parts))
            idx += 1
        attrs.append(Attribute(start=start, end=idx - 1, text="\n".join(parts)))
    return attrs


def item_token_window(lines: list[str], attr: Attribute) -> str:
    start = first_code_line_after_attr(lines, attr)
    if start is None:
        return ""

    idx = start
    parts: list[str] = []
    while idx < len(lines) and len(parts) < 8:
        stripped = rust_token_text(lines[idx]).strip()
        if stripped:
            parts.append(stripped)
        idx += 1
    return re.sub(r"\s+", " ", " ".join(parts)).strip()


def test_module_decl_after_attr(
    path: Path, lines: list[str], attr: Attribute
) -> list[Path]:
    if not is_test_item_attr(attr):
        return []
    start = first_code_line_after_attr(lines, attr)
    if start is None:
        return []

    parts: list[str] = []
    idx = start
    while idx < len(lines) and len(parts) < 4:
        stripped = rust_token_text(lines[idx]).strip()
        if stripped:
            parts.append(stripped)
        idx += 1
    item = re.sub(r"\s+", " ", " ".join(parts)).strip()
    match = MODULE_DECL_RE.match(item)
    if not match:
        return []

    path_attr: Path | None = None
    for extra in attrs_until_item(lines, attr):
        path_match = PATH_ATTR_RE.search(extra.text)
        if path_match:
            path_attr = path.parent / path_match.group(1)
    if path_attr is not None:
        return [path_attr.resolve()]

    name = match.group(1)
    return [
        (path.parent / f"{name}.rs").resolve(),
        (path.parent / name / "mod.rs").resolve(),
    ]


def module_candidates_for_item(
    path: Path, attrs: list[Attribute], item: str, base_override: Path | None = None
) -> list[Path]:
    match = MODULE_DECL_RE.match(item)
    if not match:
        return []
    for attr in attrs:
        path_match = PATH_ATTR_RE.search(attr.text)
        if path_match:
            return [(path.parent / path_match.group(1)).resolve()]

    name = match.group(1)
    base = base_override or path.parent
    if base_override is None and path.name not in ("lib.rs", "main.rs", "mod.rs", "build.rs"):
        base = path.parent / path.stem
    return [
        (base / f"{name}.rs").resolve(),
        (base / name / "mod.rs").resolve(),
    ]


def module_decl_includes(lines: list[str], path: Path) -> list[tuple[bool, list[Path]]]:
    includes: list[tuple[bool, list[Path]]] = []
    pending_attrs: list[Attribute] = []
    idx = 0
    while idx < len(lines):
        stripped = rust_token_text(lines[idx]).strip()
        if not stripped:
            idx += 1
            continue
        if stripped.startswith("#[") or stripped.startswith("#!["):
            start = idx
            parts = [lines[idx]]
            balance = bracket_balance("\n".join(parts))
            idx += 1
            while balance > 0 and idx < len(lines):
                parts.append(lines[idx])
                balance = bracket_balance("\n".join(parts))
                idx += 1
            pending_attrs.append(Attribute(start=start, end=idx - 1, text="\n".join(parts)))
            continue

        start = idx
        item_parts: list[str] = []
        depth = 0
        seen_brace = False
        while idx < len(lines) and len(item_parts) < 64:
            item_part = rust_token_text(lines[idx]).strip()
            if item_part:
                item_parts.append(item_part)
                for char in item_part:
                    if char == "{":
                        seen_brace = True
                        depth += 1
                    elif char == "}":
                        depth -= 1
            if (not seen_brace and ";" in item_part) or (seen_brace and depth <= 0):
                break
            idx += 1
        item = re.sub(r"\s+", " ", " ".join(item_parts)).strip()
        candidates = module_candidates_for_item(path, pending_attrs, item)
        if candidates:
            is_test = any(is_test_item_attr(attr) for attr in pending_attrs)
            includes.append((is_test, candidates))
        inline_match = re.match(
            r"^(?:pub\s*(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*)\}\s*$",
            item,
        )
        if inline_match:
            is_test = any(is_test_item_attr(attr) for attr in pending_attrs)
            module_name = inline_match.group(1)
            body = inline_match.group(2)
            body_path = path.parent / module_name / "mod.rs"
            for child_is_test, child_candidates in module_decl_includes(body.splitlines(), body_path):
                includes.append(
                    (
                        is_test or child_is_test,
                        [
                            candidate
                            for candidate in child_candidates
                        ],
                    )
                )
        pending_attrs = []
        idx += 1
    return includes


def is_broad_suppressor(lines: list[str], attr: Attribute) -> bool:
    if normalize_lint_text(attr.text).lstrip().startswith("#!["):
        return True
    return bool(ITEM_RE.match(item_token_window(lines, attr)))


def end_line_for_balanced_item(lines: list[str], start: int) -> int:
    text = "\n".join(rust_token_text(line) for line in lines[start:])
    first_brace = text.find("{")
    first_semicolon = text.find(";")
    if first_brace < 0 or (0 <= first_semicolon < first_brace):
        if first_semicolon < 0:
            return start
        return start + text[: first_semicolon + 1].count("\n")

    depth = 0
    for idx, char in enumerate(text[first_brace:], start=first_brace):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return start + text[: idx + 1].count("\n")
    return len(lines) - 1


def end_line_for_local_suppressor(lines: list[str], start: int) -> int:
    text = "\n".join(rust_token_text(line) for line in lines[start:])
    first_brace = text.find("{")
    first_semicolon = text.find(";")
    if 0 <= first_brace < first_semicolon or (first_brace >= 0 and first_semicolon < 0):
        return end_line_for_balanced_item(lines, start)
    if first_semicolon >= 0:
        return start + text[: first_semicolon + 1].count("\n")
    return min(len(lines) - 1, start + 8)


def test_only_ranges(lines: list[str], attrs: list[Attribute]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for attr in attrs:
        if not is_test_item_attr(attr):
            continue
        start = first_code_line_after_attr(lines, attr)
        if start is None:
            continue
        ranges.append((start, end_line_for_balanced_item(lines, start)))
    return ranges


def documented_suppressor_ranges(lines: list[str], attrs: list[Attribute]) -> list[tuple[int, int, set[str]]]:
    ranges: list[tuple[int, int, set[str]]] = []
    for attr in attrs:
        if not is_lint_suppressor(attr):
            continue
        if is_test_only_allow(attr, attrs):
            continue
        if is_macro_metavar_suppressor(attr):
            continue
        if is_group_suppressor(attr):
            continue
        if is_broad_suppressor(lines, attr):
            continue
        if not has_invariant_comment(lines, attr):
            continue
        start = first_code_line_after_attr(lines, attr)
        if start is None:
            continue
        ranges.append((attr.start, end_line_for_local_suppressor(lines, start), suppressed_methods(attr)))
    return ranges


def in_ranges(line: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= line <= end for start, end in ranges)


def in_suppressor_ranges(line: int, method: str, ranges: list[tuple[int, int, set[str]]]) -> bool:
    return any(start <= line <= end and method in methods for start, end, methods in ranges)


def iter_panic_calls(lines: list[str]) -> list[tuple[int, str]]:
    token_text = rust_token_text("\n".join(lines))
    calls: set[tuple[int, str]] = set()
    for match in PANIC_CALL_RE.finditer(token_text):
        calls.add(
            (
                token_text.count("\n", 0, match.start()),
                next(g for g in match.groups() if g).removeprefix("r#"),
            )
        )
    for match in PANIC_PATH_ITEM_RE.finditer(token_text):
        calls.add(
            (
                token_text.count("\n", 0, match.start()),
                next(g for g in match.groups() if g).removeprefix("r#"),
            )
        )
    for start, end in macro_invocation_ranges(token_text):
        body = token_text[start:end]
        for match in PANIC_IDENT_RE.finditer(body):
            calls.add(
                (
                    token_text.count("\n", 0, start + match.start()),
                    next(g for g in match.groups() if g).removeprefix("r#"),
                )
            )
    return sorted(calls)


def macro_invocation_ranges(token_text: str) -> list[tuple[int, int]]:
    pairs = {"(": ")", "{": "}", "[": "]"}
    ranges: list[tuple[int, int]] = []
    for match in MACRO_INVOKE_RE.finditer(token_text):
        open_char = match.group(1)
        close_char = pairs[open_char]
        depth = 0
        idx = match.end() - 1
        while idx < len(token_text):
            char = token_text[idx]
            if char == open_char:
                depth += 1
            elif char == close_char:
                depth -= 1
                if depth == 0:
                    ranges.append((match.end(), idx))
                    break
            idx += 1
    return ranges


def has_invariant_comment(lines: list[str], attr: Attribute) -> bool:
    for prev in range(attr.start - 1, max(-1, attr.start - 6), -1):
        stripped = lines[prev].strip()
        if not stripped:
            continue
        if stripped.startswith("#["):
            continue
        if stripped.startswith("//"):
            if any(marker in stripped for marker in DOC_MARKERS):
                return True
            continue
        break
    return False


def iter_rust_files(paths: list[Path]) -> list[Path]:
    rust_files: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix == ".rs":
            rust_files.append(path)
        elif path.is_dir():
            rust_files.extend(sorted(path.rglob("*.rs")))
    return sorted(set(rust_files))


def external_module_includes(
    rust_files: list[Path],
) -> tuple[dict[Path, list[tuple[bool, Path]]], set[Path]]:
    existing = {path.resolve() for path in rust_files}
    edges: dict[Path, list[tuple[bool, Path]]] = {}
    included: set[Path] = set()
    for path in rust_files:
        resolved = path.resolve()
        lines = read_rust_lines(path)
        for is_test, candidates in module_decl_includes(lines, path):
            for candidate in candidates:
                if candidate not in existing:
                    continue
                edges.setdefault(resolved, []).append((is_test, candidate))
                included.add(candidate)
    return edges, existing - included


def transitive_context_files(
    edges: dict[Path, list[tuple[bool, Path]]], production_roots: set[Path]
) -> tuple[set[Path], set[Path]]:
    production_files: set[Path] = set()
    stack = list(production_roots)
    while stack:
        path = stack.pop()
        if path in production_files:
            continue
        production_files.add(path)
        for is_test, child in edges.get(path, ()):
            if not is_test:
                stack.append(child)

    roots = {
        child
        for parent, children in edges.items()
        for is_test, child in children
        if is_test or parent not in production_files
    }
    test_files: set[Path] = set()
    stack = list(roots)
    while stack:
        path = stack.pop()
        if path in test_files or path in production_files:
            continue
        test_files.add(path)
        stack.extend(child for _, child in edges.get(path, ()))
    return test_files, production_files


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reject production unwrap/expect lint suppressors unless they "
            "carry a nearby invariant comment."
        )
    )
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()

    failures: list[str] = []
    rust_files = iter_rust_files(args.paths)
    edges, production_roots = external_module_includes(rust_files)
    test_files, production_files = transitive_context_files(edges, production_roots)
    for path in rust_files:
        resolved = path.resolve()
        if resolved in test_files and resolved not in production_files:
            continue
        lines = read_rust_lines(path)
        attrs = collect_attributes(lines)
        tests = test_only_ranges(lines, attrs)
        documented = documented_suppressor_ranges(lines, attrs)
        for attr in attrs:
            if not is_lint_suppressor(attr):
                continue
            if is_test_only_allow(attr, attrs):
                continue
            if is_macro_metavar_suppressor(attr):
                failures.append(
                    f"{path}:{attr.start + 1}: unwrap/expect lint suppressor "
                    "must name the exact lint, not a macro metavariable"
                )
                continue
            if is_group_suppressor(attr):
                failures.append(
                    f"{path}:{attr.start + 1}: unwrap/expect lint suppressor "
                    "must name clippy::unwrap_used or clippy::expect_used exactly"
                )
                continue
            if is_broad_suppressor(lines, attr):
                failures.append(
                    f"{path}:{attr.start + 1}: unwrap/expect lint suppressor "
                    "must be local to the statement or block that needs it"
                )
                continue
            if has_invariant_comment(lines, attr):
                continue
            failures.append(
                f"{path}:{attr.start + 1}: unwrap/expect lint suppressor "
                "needs a nearby Invariant: or Poison means comment"
            )
        for line, method in iter_panic_calls(lines):
            if in_ranges(line, tests) or in_suppressor_ranges(line, method, documented):
                continue
            failures.append(
                f"{path}:{line + 1}: naked .{method}() requires a local "
                "documented lint suppressor or exact cfg(test) scope"
            )

    if failures:
        for failure in failures:
            print(failure)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
