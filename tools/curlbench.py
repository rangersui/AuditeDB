#!/usr/bin/env python3
"""CurlBench harness: grade elastik-agent prompts against a real elastik.

Usage:
  tools/curlbench.py prompts/elastik-agent-tool.prompt.yml \\
      --model openai/gpt-4o-mini \\
      --out prompts/curlbench-$(date +%s).json

Pre-flight (one-shot, in another terminal):
  $env:ELASTIK_KEY = "test-key"
  $env:ELASTIK_WRITE_TOKEN = "write-token"
  $env:ELASTIK_APPROVE_TOKEN = "approve-token"
  $env:ELASTIK_PERSIST_HEADERS = "x-author,x-meta-*"
  cargo run --manifest-path core/Cargo.toml --release

Per-row dispatch by `grader:` metadata:
  executable -> setup curls -> ask model -> extract emitted curl ->
                safety guard (must hit 127.0.0.1:3105) -> bash ->
                grade by HTTP status vs expected_status (412/416 = 0.5).
  advisory   -> ask model -> case-insensitive substring match against
                required_anchors (AND), any_anchors (OR), anti_anchors
                (must miss).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml

NULL_DEV = os.devnull  # "NUL" on Windows, "/dev/null" elsewhere
# Resolve bash via shutil.which so subprocess.run doesn't accidentally
# route to WSL on Windows (which lives at C:\Windows\System32\bash.exe
# and ranks ahead of Git Bash in some PATH configurations). shutil.which
# respects PATHEXT and finds Git Bash; subprocess.run with bare "bash"
# uses CreateProcess resolution which can pick WSL.
BASH = shutil.which("bash") or "bash"

ELASTIK_HOST = "http://127.0.0.1:3105"
# Resolved at startup from --write-token / --approve-token, or env, or
# a sibling .env file. Fallback literal strings match the prompt's
# pedagogical defaults so models that learned `Bearer write-token` emit
# what we'll then substitute in.
WRITE_TOKEN = "write-token"
APPROVE_TOKEN = "approve-token"
PROMPT_WRITE_LITERAL = "write-token"
PROMPT_APPROVE_LITERAL = "approve-token"

CURL_BLOCK_RE = re.compile(r"```(?:bash|sh|shell)?\s*\n((?:.|\n)*?)```", re.MULTILINE)
CURL_INLINE_RE = re.compile(r"`(curl[^`]+)`")
CURL_LINE_RE = re.compile(r"(?:^|\n)\s*\$?\s*(curl[^\n]+)", re.MULTILINE)
URL_RE = re.compile(r"127\.0\.0\.1:3105(/\S*)")


def load_tokens_from_dotenv(path: Path) -> dict[str, str]:
    """Best-effort .env parser for ELASTIK_WRITE_TOKEN / ELASTIK_APPROVE_TOKEN."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _token_patterns(name: str) -> list[str]:
    """Generate fully-balanced match patterns for a token literal.

    IMPORTANT: each pattern explicitly anchors both the opening and
    closing of any placeholder syntax. Earlier versions used optional
    trailing classes like `["\\'>]?` that greedily ate the surrounding
    shell quote (turning `-H 'Bearer write-token'` into
    `-H 'Bearer REAL_TOKEN` with no closing quote), corrupting setup
    commands and producing silent 404s on dependent rows.
    """
    return [
        rf"Bearer\s+<{name}>",          # <name> placeholder
        rf'Bearer\s+"{name}"',          # double-quoted literal
        rf"Bearer\s+'{name}'",          # single-quoted literal
        rf"Bearer\s+your-{name}",       # your-write-token style
        rf"Bearer\s+{name}\b",          # bare literal (word-boundary)
    ]


_TOKEN_VAR_PATTERNS = {
    "write": [
        r"Bearer\s+\$\{?WRITE_TOKEN\}?",
        r"Bearer\s+\$\{?ELASTIK_WRITE_TOKEN\}?",
    ],
    "approve": [
        r"Bearer\s+\$\{?APPROVE_TOKEN\}?",
        r"Bearer\s+\$\{?ELASTIK_APPROVE_TOKEN\}?",
    ],
}


def substitute_tokens(cmd: str) -> str:
    """Replace prompt-placeholder tokens with real ones before execution.

    Each pattern below fully balances any placeholder delimiter so the
    surrounding shell quote is preserved. Models learn
    `Bearer write-token` / `Bearer approve-token` from the system
    prompt and re-emit them as `<write-token>`, `"write-token"`,
    `$WRITE_TOKEN`, or `your-write-token`; we cover the common shapes
    and let unrecognized placeholders fall through to 401 honestly.
    """
    for pat in _token_patterns("write-token"):
        cmd = re.sub(pat, f"Bearer {WRITE_TOKEN}", cmd)
    for pat in _TOKEN_VAR_PATTERNS["write"]:
        cmd = re.sub(pat, f"Bearer {WRITE_TOKEN}", cmd)
    for pat in _token_patterns("approve-token"):
        cmd = re.sub(pat, f"Bearer {APPROVE_TOKEN}", cmd)
    for pat in _TOKEN_VAR_PATTERNS["approve"]:
        cmd = re.sub(pat, f"Bearer {APPROVE_TOKEN}", cmd)
    return cmd


def health_check() -> bool:
    r = subprocess.run(
        ["curl", "-sS", "--max-time", "2", "-o", NULL_DEV,
         "-w", "%{http_code}", f"{ELASTIK_HOST}/proc/version"],
        capture_output=True, text=True
    )
    return r.returncode == 0 and r.stdout.strip() == "200"


def run_setup(setup: list[str]) -> None:
    for cmd in setup:
        subprocess.run([BASH, "-c", substitute_tokens(cmd)],
                       capture_output=True, timeout=15)


_RATE_LIMIT_RE = re.compile(r"retry after (\d+)s")
_BUDGET_LIMIT_RE = re.compile(r"reached its budget limit", re.IGNORECASE)


def gh_models_run(model: str, prompt_yml: Path, row_input: str,
                  max_retries: int = 2,
                  max_tokens: int = 1024,
                  row_timeout: int = 120) -> tuple[str, float]:
    """Call gh models run with rate-limit aware retry.

    Distinguishes four failure modes from gh-models:
      - rate-limit: "retry after Ns" -> sleep + retry up to max_retries
      - budget-cap: "reached its budget limit" -> fail-fast (sleeping
        won't help; user must adjust spending limit on github.com)
      - timeout: row exceeds row_timeout seconds -> fail-fast with a
        [GH_MODELS_TIMEOUT] marker. Don't retry: a model that takes
        >row_timeout once typically does so reproducibly (observed
        with microsoft/phi-4-mini-instruct on this prompt size).
        Note: on Windows, Python's `subprocess.run(..., timeout=N)`
        kills the child after N seconds but then re-runs
        `process.communicate()` to drain stdout/stderr; if the
        child's pipes stay open through a slow-dying grandchild
        the wall-clock can far exceed N before the harness moves
        on. The row still records score=-1 and the run continues;
        only the elapsed measurement is inflated.
      - other: surface raw stderr

    Catching subprocess.TimeoutExpired is critical: without it the
    harness aborts on the first slow row instead of recording -1
    for that row and continuing.

    max_tokens defaults to 1024 because gh-models's own default is
    low enough that smaller models (Llama 8B observed) truncate mid-
    URL on prompts of this size, producing "no curl emitted" /
    "off-host" failures that look like model errors but are really
    output-budget errors.
    """
    t0 = time.time()
    for attempt in range(max_retries + 1):
        try:
            r = subprocess.run(
                ["gh", "models", "run", model, "--file", str(prompt_yml),
                 "--var", f"input={row_input}",
                 "--max-tokens", str(max_tokens)],
                capture_output=True, text=True, timeout=row_timeout
            )
        except subprocess.TimeoutExpired:
            elapsed = time.time() - t0
            return (f"[GH_MODELS_TIMEOUT after {row_timeout}s] model "
                    f"did not respond within row_timeout"), elapsed
        if r.returncode == 0:
            return r.stdout.strip(), time.time() - t0
        if _BUDGET_LIMIT_RE.search(r.stderr or ""):
            return f"[GH_MODELS_BUDGET_CAP] adjust spending limit on github.com/settings", time.time() - t0
        m = _RATE_LIMIT_RE.search(r.stderr or "")
        if m and attempt < max_retries:
            wait = int(m.group(1)) + 5
            print(f"    rate limit hit; sleeping {wait}s then retrying...",
                  file=sys.stderr)
            time.sleep(wait)
            continue
        return f"[GH_MODELS_ERROR exit={r.returncode}] {r.stderr.strip()[:200]}", time.time() - t0
    return f"[GH_MODELS_ERROR retries_exhausted]", time.time() - t0


def extract_curl(response: str) -> str | None:
    """First runnable curl. Handles three response shapes:

      1. Triple-backtick code block:    ```bash\\ncurl ...\\n```
      2. Inline single backticks:       `curl ...`
      3. Bare line:                     curl ...

    Inside a fenced block, backslash-continuation lines are joined
    until a blank line or a new shell command (`echo`, `export`, ...)
    """
    # Shape 1: fenced code block
    for m in CURL_BLOCK_RE.finditer(response):
        body = m.group(1)
        block_lines = body.splitlines()
        for i, line in enumerate(block_lines):
            cleaned = line.strip().lstrip("$ ").rstrip("\\").strip()
            if not cleaned.startswith("curl"):
                continue
            parts = [cleaned]
            for cont in block_lines[i + 1:]:
                stripped = cont.rstrip("\\").strip()
                if not stripped:
                    break
                first_word = stripped.split(maxsplit=1)[0]
                if first_word in {"echo", "export", "cd", "set", "curl",
                                  "$", "#", "&&", "||", ";"}:
                    break
                parts.append(stripped)
            return " ".join(parts).rstrip("\\").strip()
    # Shape 2: inline single-backtick (Llama-style)
    m = CURL_INLINE_RE.search(response)
    if m:
        return m.group(1).strip().rstrip("\\")
    # Shape 3: bare curl line
    m = CURL_LINE_RE.search(response)
    return m.group(1).strip().rstrip("\\") if m else None


def is_safe_curl(curl: str) -> tuple[bool, str]:
    if "127.0.0.1:3105" not in curl:
        return False, "off-host (URL not localhost:3105)"
    return True, ""


def run_curl_get_status(curl: str) -> tuple[int, int]:
    """Return (shell_exit, http_status). status=0 if not captured."""
    cleaned = substitute_tokens(curl.replace("\\\n", " ").strip().rstrip("\\").strip())
    # Add timeout for SSE rows so /listen doesn't hang
    if "--max-time" not in cleaned and "/listen" in cleaned:
        cleaned += " --max-time 2"
    # bash -c on MSYS/Git-Bash auto-translates /dev/null -> NUL on
    # Windows. Direct `curl -o nul` from non-bash subprocess fails with
    # exit 23, but inside bash the POSIX path is the right form.
    wrapped = f"{cleaned} -o /dev/null -s -w '%{{http_code}}'"
    r = subprocess.run([BASH, "-c", wrapped], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        # SSE timeout (exit 28) is OK if we still got a status code
        if "/listen" in cleaned and r.returncode in (28,) and r.stdout.strip().isdigit():
            return 0, int(r.stdout.strip())
        return r.returncode, 0
    out = r.stdout.strip().splitlines()
    if not out:
        return 0, 0
    try:
        return 0, int(out[-1])
    except ValueError:
        return 0, 0


def grade_executable(row: dict, response: str) -> dict:
    curl = extract_curl(response)
    if not curl:
        return {"score": -1.0, "reason": "no curl emitted"}
    safe, why = is_safe_curl(curl)
    if not safe:
        return {"score": -1.0, "reason": why, "curl": curl[:200]}
    shell_exit, status = run_curl_get_status(curl)
    if shell_exit != 0:
        return {"score": -1.0, "reason": f"shell exit {shell_exit}",
                "shell_exit": shell_exit, "curl": curl[:200]}
    expected = row["expected_status"]
    expected_set = expected if isinstance(expected, list) else [expected]
    if status in expected_set:
        return {"score": 1.0, "reason": f"ok ({status})", "status": status}
    if status in (412, 416):
        return {"score": 0.5, "reason": f"half-pass ({status})", "status": status}
    if status == 503 and "/listen" in curl:
        return {"score": 0.0, "reason": "listen connection cap", "status": status}
    return {"score": 0.0, "reason": f"got {status} expected {expected}",
            "status": status, "curl": curl[:200]}


def grade_advisory(row: dict, response: str) -> dict:
    if response.startswith("[GH_MODELS_ERROR"):
        return {"score": -1.0, "reason": "gh models error"}
    resp = response.lower()
    required = [a.lower() for a in row.get("required_anchors", [])]
    any_a = [a.lower() for a in row.get("any_anchors", [])]
    anti = [a.lower() for a in row.get("anti_anchors", [])]
    missing_required = [a for a in required if a not in resp]
    if missing_required:
        return {"score": 0.0, "reason": f"missing required: {missing_required}"}
    if any_a and not any(a in resp for a in any_a):
        return {"score": 0.0, "reason": f"none of any_anchors hit: {any_a}"}
    anti_hit = [a for a in anti if a in resp]
    if anti_hit:
        return {"score": 0.0, "reason": f"anti_anchor hit: {anti_hit}"}
    return {"score": 1.0, "reason": "ok"}


def cleanup_world(path: str) -> None:
    if path.startswith("/var/log/") or path.startswith("/proc/") or not path.startswith("/"):
        return
    subprocess.run(
        ["curl", "-sS", "--max-time", "5", "-X", "DELETE",
         "-H", f"Authorization: Bearer {APPROVE_TOKEN}",
         f"{ELASTIK_HOST}{path}"],
        capture_output=True, timeout=10
    )


def collect_touched_paths(curl: str, touched: set[str]) -> None:
    for m in URL_RE.finditer(curl):
        path = m.group(1).rstrip(" '\"")
        # Skip listen wildcards and proc reads; only DELETE-able worlds
        if path.startswith("/listen/") or path.startswith("/proc/") or "*" in path:
            continue
        touched.add(path)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("prompt_file", type=Path)
    p.add_argument("--model", default="openai/gpt-4o-mini")
    p.add_argument("--out", type=Path, default=None,
                   help="JSON output path (stdout if omitted)")
    p.add_argument("--rows", help="1-based comma list, e.g. 1,3,13", default=None)
    p.add_argument("--no-cleanup", action="store_true",
                   help="Skip post-run DELETE of touched worlds")
    p.add_argument("--write-token",
                   help="Real ELASTIK_WRITE_TOKEN (substituted into the "
                        "prompt's `Bearer write-token` placeholder before "
                        "bash runs the curl). Falls back to env var, "
                        "then to .env in the cwd, then to literal placeholder.")
    p.add_argument("--approve-token",
                   help="Same as --write-token but for ELASTIK_APPROVE_TOKEN.")
    p.add_argument("--env-file", type=Path, default=Path(".env"),
                   help="Path to .env file for token fallback (default: ./.env)")
    p.add_argument("--row-timeout", type=int, default=120,
                   help="Per-row gh-models-run timeout in seconds. On "
                        "timeout the row records score=-1 with reason "
                        "'gh-models-timeout' and the run continues. "
                        "Default 120; lower (e.g. 30) when batch-testing "
                        "models known to stall.")
    args = p.parse_args()

    # Resolve tokens: CLI > env var > .env > literal placeholder
    global WRITE_TOKEN, APPROVE_TOKEN
    dotenv = load_tokens_from_dotenv(args.env_file)
    WRITE_TOKEN = (args.write_token
                   or os.environ.get("ELASTIK_WRITE_TOKEN")
                   or dotenv.get("ELASTIK_WRITE_TOKEN")
                   or PROMPT_WRITE_LITERAL)
    APPROVE_TOKEN = (args.approve_token
                     or os.environ.get("ELASTIK_APPROVE_TOKEN")
                     or dotenv.get("ELASTIK_APPROVE_TOKEN")
                     or PROMPT_APPROVE_LITERAL)
    print(f"  write-token resolved: {WRITE_TOKEN[:8]}... ({'real' if WRITE_TOKEN != PROMPT_WRITE_LITERAL else 'literal placeholder'})",
          file=sys.stderr)
    print(f"  approve-token resolved: {APPROVE_TOKEN[:8]}... ({'real' if APPROVE_TOKEN != PROMPT_APPROVE_LITERAL else 'literal placeholder'})",
          file=sys.stderr)

    if not health_check():
        sys.stderr.write(f"FATAL: elastik not responding at {ELASTIK_HOST}/proc/version\n")
        sys.stderr.write("Start it in another terminal:\n")
        sys.stderr.write('  $env:ELASTIK_WRITE_TOKEN = "write-token"\n')
        sys.stderr.write('  $env:ELASTIK_APPROVE_TOKEN = "approve-token"\n')
        sys.stderr.write('  $env:ELASTIK_PERSIST_HEADERS = "x-author,x-meta-*"\n')
        sys.stderr.write('  cargo run --manifest-path core/Cargo.toml --release\n')
        return 2

    doc = yaml.safe_load(args.prompt_file.read_text(encoding="utf-8"))
    rows = doc["testData"]
    indices = list(range(len(rows)))
    if args.rows:
        keep = {int(x) - 1 for x in args.rows.split(",")}
        indices = [i for i in indices if i in keep]

    results = []
    touched: set[str] = set()

    for i in indices:
        row = rows[i]
        row_id = i + 1
        grader = row.get("grader", "advisory")
        if grader == "executable":
            run_setup(row.get("setup", []))
        response, gen_seconds = gh_models_run(
            args.model, args.prompt_file, row["input"],
            row_timeout=args.row_timeout
        )

        # Short-circuit on infrastructure errors (budget cap, retries
        # exhausted, transport error) -- don't pretend the row was
        # graded; surface the actual cause.
        if response.startswith("[GH_MODELS_"):
            tag = response.split("]", 1)[0].lstrip("[").lower()
            r = {"score": -1.0, "reason": tag.replace("_", "-")}
        elif grader == "executable":
            r = grade_executable(row, response)
            if "curl" in r:
                collect_touched_paths(r["curl"], touched)
        else:
            r = grade_advisory(row, response)

        rec = {
            "row": row_id,
            "grader": grader,
            "input": row["input"][:80],
            "score": r["score"],
            "reason": r["reason"],
            "gen_seconds": round(gen_seconds, 2),
        }
        for k in ("status", "shell_exit", "curl"):
            if k in r:
                rec[k] = r[k]
        results.append(rec)
        marker = "PASS" if r["score"] == 1.0 else ("HALF" if r["score"] == 0.5 else "FAIL")
        print(f"  R{row_id:2d} [{grader[:3]}] {marker} score={r['score']:>4.1f}  "
              f"({gen_seconds:.1f}s)  {r['reason']}")

    if not args.no_cleanup:
        for w in sorted(touched):
            cleanup_world(w)

    summary = {
        "model": args.model,
        "prompt_file": str(args.prompt_file),
        "total": len(results),
        "pass": sum(1 for r in results if r["score"] == 1.0),
        "half": sum(1 for r in results if r["score"] == 0.5),
        "fail": sum(1 for r in results if 0.0 <= r["score"] < 0.5),
        "error": sum(1 for r in results if r["score"] < 0.0),
        "results": results,
    }
    payload = json.dumps(summary, indent=2)
    if args.out:
        args.out.write_text(payload, encoding="utf-8")
        print(f"\nwrote {args.out}", file=sys.stderr)
    print(f"\n{summary['pass']}/{summary['total']} pass  "
          f"{summary['half']} half  {summary['fail']} fail  "
          f"{summary['error']} error")
    return 0


if __name__ == "__main__":
    sys.exit(main())
