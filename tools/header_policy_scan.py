#!/usr/bin/env python3
"""Detect HTTP header registry drift against Elastik's reviewed baseline.

Elastik intentionally uses a denylist for persisted response metadata:
future response-policy headers should be able to travel with bytes unless they
describe request, transport, credential, browser-state, or core-owned state.

This script is the maintenance guardrail for that choice. It fetches the IANA
HTTP Field Name Registry and MDN browser-compat-data headers, compares them
with a reviewed baseline, checks Rust/Python denylist parity, and fails when
new upstream header names appear.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import textwrap
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_IANA_URL = "https://www.iana.org/assignments/http-fields/field-names.csv"
# Intentionally tracks the latest MDN browser-compat-data package. This workflow
# is a drift radar: volatility is the signal, not an accidental dependency.
DEFAULT_MDN_URL = "https://unpkg.com/@mdn/browser-compat-data/data.json"
HEADER_NAME_RE = re.compile(r"^(?:\*|[a-z][a-z0-9-]*)$")

REQUIRED_DENY = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "host",
    "connection",
    "origin",
    "transfer-encoding",
    "content-length",
    "etag",
    "vary",
    "x-request-id",
    "x-elapsed-us",
    "x-elapsed-ms",
    "x-content-type-options",
    "clear-site-data",
    # Distributed tracing context. Auto-injected by APM /
    # OpenTelemetry agents; persisting would replay the writer's
    # trace ID into every subsequent read and corrupt downstream
    # tracing systems.
    "traceparent",
    "tracestate",
    "baggage",
    "b3",
    # Client-IP forwarding from load-balancers and CDNs (Akamai,
    # legacy proxies). Same data class as `x-forwarded-for`.
    "x-real-ip",
    "true-client-ip",
    "client-ip",
    # Transport version markers + HTTP/1.0 living fossil.
    "http3-settings",
    "pragma",
}

# Required prefix denies. The drift radar fails CI if any of these
# is missing from the Rust / Python policies. Closes the blind spot
# where individual `x-b3-traceid` / `x-amzn-requestid` / `cf-ray`
# names land in IANA / MDN registries one at a time and would have
# to be hand-classified each. Prefix denies cover the vendor space
# in one rule.
REQUIRED_PREFIXES = {
    # HTTP/2 + HTTP/3 pseudo-headers (`:method`, `:path`, `:scheme`,
    # `:authority`, `:status`).
    ":",
    # Zipkin multi-header propagation.
    "x-b3-",
    # AWS ALB / CloudFront / API Gateway runtime injections.
    "x-amzn-",
    # Cloudflare runtime injections.
    "cf-",
}

REQUEST_OR_STATE_HINTS = (
    "auth",
    "cookie",
    "token",
    "secret",
    "request",
    "fetch",
    "forwarded",
    "proxy",
    "client",
    "hint",
    "storage",
    "idempotency",
)


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=root / "tools" / "header_policy_baseline.txt")
    parser.add_argument("--rust", type=Path, default=root / "core" / "src" / "http_semantics.rs")
    parser.add_argument("--python", type=Path, default=root / "sdk" / "src" / "elastik" / "sdk.py")
    parser.add_argument("--iana-url", default=DEFAULT_IANA_URL)
    parser.add_argument("--mdn-url", default=DEFAULT_MDN_URL)
    parser.add_argument("--report", type=Path, help="write a markdown report")
    parser.add_argument("--refresh-baseline", action="store_true", help="replace baseline with fetched upstream names")
    parser.add_argument("--offline", action="store_true", help="use the baseline as the upstream set")
    parser.add_argument(
        "--check-baseline",
        action="store_true",
        help="fetch upstream registries and fail if the checked-in baseline has unreviewed edits",
    )
    parser.add_argument("--self-test", action="store_true", help="run parser self-tests and exit")
    args = parser.parse_args(argv)

    if args.check_baseline and args.offline:
        raise SystemExit("--check-baseline cannot be combined with --offline")

    if args.self_test:
        self_test()
        print("header policy scanner self-test: ok")
        return 0

    if not args.refresh_baseline and not args.baseline.exists():
        raise SystemExit(f"baseline file not found: {args.baseline}")

    baseline = read_name_file(args.baseline)
    rust_deny, rust_prefixes = parse_rust_policy(args.rust)
    python_deny, python_prefixes = parse_python_policy(args.python)

    if args.offline:
        upstream = set(baseline)
        sources = {"baseline": set(baseline)}
    else:
        sources = {
            "IANA": fetch_iana(args.iana_url),
            "MDN": fetch_mdn(args.mdn_url),
        }
        upstream = set().union(*sources.values())

    if args.refresh_baseline:
        write_name_file(args.baseline, upstream)
        print(f"refreshed {args.baseline} with {len(upstream)} names")
        return 0

    if args.check_baseline:
        extra = sorted(baseline - upstream)
        missing = sorted(upstream - baseline)
        if extra or missing:
            lines = [
                "# Header Policy Baseline Check",
                "",
                "The checked-in baseline does not match the live upstream registries.",
                "Run `python tools/header_policy_scan.py --refresh-baseline` only after reviewing policy changes.",
                "",
            ]
            if missing:
                lines.extend(["## Missing From Baseline", ""])
                lines.extend(f"- `{name}`" for name in missing)
                lines.append("")
            if extra:
                lines.extend(["## Extra In Baseline", ""])
                lines.extend(f"- `{name}`" for name in extra)
                lines.append("")
            check_report = "\n".join(lines)
            if args.report:
                args.report.write_text(check_report, encoding="utf-8")
            print(check_report)
            return 1

    new_names = sorted(upstream - baseline)
    removed_names = sorted(baseline - upstream) if not args.offline else []
    parity_only_rust = sorted(rust_deny - python_deny)
    parity_only_python = sorted(python_deny - rust_deny)
    prefix_only_rust = sorted(rust_prefixes - python_prefixes)
    prefix_only_python = sorted(python_prefixes - rust_prefixes)
    missing_required = sorted(name for name in REQUIRED_DENY if name not in rust_deny)
    missing_required_prefix = sorted(p for p in REQUIRED_PREFIXES if p not in rust_prefixes)

    report = build_report(
        sources=sources,
        baseline=baseline,
        rust_deny=rust_deny,
        rust_prefixes=rust_prefixes,
        python_deny=python_deny,
        python_prefixes=python_prefixes,
        new_names=new_names,
        removed_names=removed_names,
        parity_only_rust=parity_only_rust,
        parity_only_python=parity_only_python,
        prefix_only_rust=prefix_only_rust,
        prefix_only_python=prefix_only_python,
        missing_required=missing_required,
        missing_required_prefix=missing_required_prefix,
    )

    if args.report:
        args.report.write_text(report, encoding="utf-8")
    print(report)

    if (
        new_names
        or parity_only_rust
        or parity_only_python
        or prefix_only_rust
        or prefix_only_python
        or missing_required
        or missing_required_prefix
    ):
        return 1
    return 0


def fetch_text(url: str, *, attempts: int = 2, timeout: int = 90) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "elastik-header-policy-scan"})
    last: BaseException | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except (TimeoutError, urllib.error.URLError) as exc:
            last = exc
            if attempt + 1 == attempts:
                break
            time.sleep(2**attempt)
    raise RuntimeError(f"failed to fetch {url}: {last}") from last


def fetch_iana(url: str) -> set[str]:
    rows = csv.DictReader(io.StringIO(fetch_text(url)))
    return {
        name
        for row in rows
        if row.get("Field Name")
        for name in [normalize(row["Field Name"])]
        if is_registry_name(name)
    }


def fetch_mdn(url: str) -> set[str]:
    data = json.loads(fetch_text(url))
    http = data.get("http") if isinstance(data, dict) else None
    headers = http.get("headers") if isinstance(http, dict) else None
    if not isinstance(headers, dict):
        raise SystemExit(
            "MDN browser-compat-data schema changed: expected http.headers object"
        )
    return {
        name
        for raw in headers
        if not raw.startswith("__")
        for name in [normalize(raw)]
        if is_registry_name(name)
    }


def parse_rust_policy(path: Path) -> tuple[set[str], set[str]]:
    text = path.read_text(encoding="utf-8")
    return parse_rust_policy_from_text(text, path=path)


def parse_rust_policy_from_text(
    text: str,
    *,
    path: Path | str = "<memory>",
) -> tuple[set[str], set[str]]:
    fn = extract_function(text, "is_never_persisted_header")
    matches_body = extract_matches_body(fn, path=path)
    deny = {
        normalize(name)
        for name in re.findall(r'"([A-Za-z0-9][A-Za-z0-9-]*)"', strip_rust_comments(matches_body))
    }
    # Two prefix forms:
    #   name.starts_with("x-b3-")  - alphanumeric+dash, trailing dash
    #   name.starts_with(":")       - HTTP/2+3 pseudo-header marker
    prefixes = {
        normalize(prefix)
        for prefix in re.findall(
            r'name\.starts_with\("(:|[A-Za-z0-9-]+-)"\)',
            strip_rust_comments(fn),
        )
    }
    return deny, prefixes


def parse_python_policy(path: Path) -> tuple[set[str], set[str]]:
    text = path.read_text(encoding="utf-8")
    return parse_python_policy_from_text(text, path=path)


def parse_python_policy_from_text(
    text: str,
    *,
    path: Path | str = "<memory>",
) -> tuple[set[str], set[str]]:
    match = re.search(r"_NON_PERSISTED_RESPONSE_HEADERS\s*=\s*\{(?P<body>.*?)\n\}", text, re.S)
    if not match:
        raise SystemExit(f"could not find _NON_PERSISTED_RESPONSE_HEADERS in {path}")
    # Prefix denies live in the L1 hard-deny helper after the
    # 4-layer persist policy refactor; before that they were inline
    # in `_should_persist_response_header`. Pick whichever defines
    # `n.startswith(...)` calls. (Pre-check by string presence to
    # avoid `extract_python_function`'s SystemExit on missing.)
    if re.search(r"^def\s+_is_never_persisted_header\b", text, re.M):
        fn = extract_python_function(text, "_is_never_persisted_header")
    else:
        fn = extract_python_function(text, "_should_persist_response_header")
    deny = {
        normalize(name)
        for name in re.findall(r'"([A-Za-z0-9][A-Za-z0-9-]*)"', match.group("body"))
    }
    prefixes = {
        normalize(prefix)
        # Mirror of the Rust regex: accept the `:` pseudo-header
        # marker as well as the standard `x-foo-` prefix shape.
        for prefix in re.findall(r'n\.startswith\("(:|[A-Za-z0-9-]+-)"\)', fn)
    }
    return deny, prefixes


def extract_python_function(text: str, name: str) -> str:
    match = re.search(rf"^def\s+{re.escape(name)}\b.*?(?=^def\s|\Z)", text, re.S | re.M)
    if not match:
        raise SystemExit(f"could not find Python function {name}")
    return match.group(0)


def extract_function(text: str, name: str) -> str:
    match = re.search(rf"\bfn\s+{re.escape(name)}\b", text)
    if not match:
        raise SystemExit(f"could not find Rust function {name}")
    brace = text.find("{", match.end())
    if brace < 0:
        raise SystemExit(f"could not find body for Rust function {name}")
    end = find_matching_delimiter(text, brace, "{", "}")
    if end >= 0:
        return text[brace : end + 1]
    raise SystemExit(f"unterminated Rust function {name}")


def extract_matches_body(fn: str, *, path: Path | str) -> str:
    clean = strip_rust_comments(fn)
    start = clean.find("matches!")
    if start < 0:
        raise SystemExit(f"could not find matches! deny block in {path}")
    open_paren = clean.find("(", start)
    if open_paren < 0:
        raise SystemExit(f"could not find matches! body in {path}")
    close_paren = find_matching_delimiter(clean, open_paren, "(", ")")
    if close_paren < 0:
        raise SystemExit(f"unterminated matches! deny block in {path}")
    inner = clean[open_paren + 1 : close_paren]
    first_arg, sep, rest = inner.partition(",")
    if sep != "," or first_arg.strip() != "name":
        raise SystemExit(f"unexpected matches! shape in {path}; expected matches!(name, ...)")
    return rest


def find_matching_delimiter(text: str, start: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    i = start
    in_string = False
    in_line_comment = False
    in_block_comment = False
    escaped = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def strip_rust_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    in_string = False
    in_line_comment = False
    in_block_comment = False
    escaped = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append(ch)
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                if ch == "\n":
                    out.append(ch)
                i += 1
            continue
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        out.append(ch)
        if ch == '"':
            in_string = True
        i += 1
    return "".join(out)


def read_name_file(path: Path) -> set[str]:
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(normalize(line))
    return out


def write_name_file(path: Path, names: set[str]) -> None:
    header = textwrap.dedent(
        """\
        # Reviewed HTTP header names from IANA + MDN browser-compat-data.
        # Update intentionally with:
        #   python tools/header_policy_scan.py --refresh-baseline
        #
        # Runtime policy remains in core/src/http_semantics.rs. This file is a
        # drift radar: new upstream names fail CI until a human classifies them.
        #
        # "*" is an IANA-registered field-name wildcard placeholder. Elastik does
        # not expect it as an on-wire header name; it is listed to avoid weekly
        # drift noise from the official registry.
        """
    )
    body = "\n".join(sorted(names))
    path.write_text(f"{header}\n{body}\n", encoding="utf-8")


def build_report(
    *,
    sources: dict[str, set[str]],
    baseline: set[str],
    rust_deny: set[str],
    rust_prefixes: set[str],
    python_deny: set[str],
    python_prefixes: set[str],
    new_names: list[str],
    removed_names: list[str],
    parity_only_rust: list[str],
    parity_only_python: list[str],
    prefix_only_rust: list[str],
    prefix_only_python: list[str],
    missing_required: list[str],
    missing_required_prefix: list[str],
) -> str:
    lines = [
        "# Header Policy Drift Report",
        "",
        "| Item | Count |",
        "|---|---:|",
        f"| Baseline reviewed names | {len(baseline)} |",
        f"| Rust deny names | {len(rust_deny)} |",
        f"| Rust deny prefixes | {len(rust_prefixes)} |",
        f"| Python deny names | {len(python_deny)} |",
        f"| Python deny prefixes | {len(python_prefixes)} |",
    ]
    for label, names in sources.items():
        lines.append(f"| Upstream {label} names | {len(names)} |")
    lines.extend(
        [
            f"| New upstream names | {len(new_names)} |",
            f"| Removed upstream names | {len(removed_names)} |",
            "",
        ]
    )

    if new_names:
        lines.extend(["## New Header Names", ""])
        for name in new_names:
            lines.append(f"- `{name}`: {review_hint(name, rust_prefixes)}")
        lines.append("")
    else:
        lines.extend(["## New Header Names", "", "None.", ""])

    if removed_names:
        lines.extend(["## Removed From Upstream", ""])
        for name in removed_names:
            lines.append(f"- `{name}`")
        lines.append("")

    if parity_only_rust or parity_only_python or prefix_only_rust or prefix_only_python:
        lines.extend(["## Rust/Python Denylist Drift", ""])
        if parity_only_rust:
            lines.append("Only in Rust:")
            lines.extend(f"- `{name}`" for name in parity_only_rust)
        if parity_only_python:
            lines.append("Only in Python:")
            lines.extend(f"- `{name}`" for name in parity_only_python)
        if prefix_only_rust:
            lines.append("Only in Rust prefixes:")
            lines.extend(f"- `{name}`" for name in prefix_only_rust)
        if prefix_only_python:
            lines.append("Only in Python prefixes:")
            lines.extend(f"- `{name}`" for name in prefix_only_python)
        lines.append("")
    else:
        lines.extend(["## Rust/Python Denylist Drift", "", "None.", ""])

    if missing_required:
        lines.extend(["## Missing Required Deny Entries", ""])
        lines.extend(f"- `{name}`" for name in missing_required)
        lines.append("")
    else:
        lines.extend(["## Missing Required Deny Entries", "", "None.", ""])

    if missing_required_prefix:
        lines.extend(["## Missing Required Deny Prefixes", ""])
        lines.extend(f"- `{prefix}`" for prefix in missing_required_prefix)
        lines.append("")
    else:
        lines.extend(["## Missing Required Deny Prefixes", "", "None.", ""])

    lines.extend(
        [
            "## How To Resolve",
            "",
            "For each new name, decide whether it is:",
            "",
            "- request-only / ambient client state: add to denylist",
            "- hop-by-hop / transport / proxy state: add to denylist",
            "- core-owned response state: add to denylist",
            "- representation metadata or browser policy that travels with bytes: keep allowed",
            "",
            "After review, refresh the baseline and commit the policy decision:",
            "",
            "```powershell",
            "python tools/header_policy_scan.py --refresh-baseline",
            "python tools/header_policy_scan.py --offline",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def review_hint(name: str, deny_prefixes: set[str]) -> str:
    if any(name.startswith(prefix) for prefix in deny_prefixes):
        return "already covered by a deny prefix; baseline may be stale"
    if any(part in name for part in REQUEST_OR_STATE_HINTS):
        return "review as possible request/client/browser-state header"
    if name.startswith(("content-", "access-control-allow-", "cross-origin-", "permissions-")):
        return "review as possible response representation/policy header"
    return "review manually"


def normalize(name: str) -> str:
    return name.strip().lower()


def is_registry_name(name: str) -> bool:
    return bool(HEADER_NAME_RE.fullmatch(name))


def self_test() -> None:
    fake_rust = r'''
    pub(crate) fn is_never_persisted_header_v2(name: &str) -> bool {
        matches!(name, "should-not-match")
    }

    pub(crate) fn is_never_persisted_header(name: &str) -> bool {
        // "comment-only" must not be parsed as a deny entry.
        name.starts_with("sec-")
            || name.starts_with("want-")
            || matches!(
                name,
                "authorization"
                    | "cookie"
                    /* "block-comment-only" must not be parsed either. */
                    | "set-cookie"
            )
    }
    '''
    deny, prefixes = parse_rust_policy_from_text(fake_rust)
    assert deny == {"authorization", "cookie", "set-cookie"}, deny
    assert prefixes == {"sec-", "want-"}, prefixes

    fake_python = r'''
_NON_PERSISTED_RESPONSE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
}

def _should_persist_response_header(name: str) -> bool:
    n = name.strip().lower()
    return (
        bool(n)
        and not n.startswith("sec-")
        and not n.startswith("want-")
        and n not in _NON_PERSISTED_RESPONSE_HEADERS
    )
'''
    deny, prefixes = parse_python_policy_from_text(fake_python)
    assert deny == {"authorization", "cookie", "set-cookie"}, deny
    assert prefixes == {"sec-", "want-"}, prefixes


if __name__ == "__main__":
    raise SystemExit(main())
