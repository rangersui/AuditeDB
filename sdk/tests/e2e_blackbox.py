"""Black-box Python SDK + Rust core end-to-end test.

This intentionally tests the public shape, not Rust internals:

1. Build the Rust core release binary.
2. Copy it into sdk/src/elastik/_bin, exactly like a wheel would ship it.
3. Import the Python SDK from sdk/src.
4. Start a real core subprocess via elastik.start(...).
5. Exercise SDK calls plus raw HTTP edges the SDK deliberately keeps thin.

Run from the repository root:

    python sdk/tests/e2e_blackbox.py

Or after `cargo build --release` + bundle:

    python sdk/tests/e2e_blackbox.py --no-build
"""
from __future__ import annotations

import argparse
import compileall
import contextlib
import csv
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from pathlib import Path
from collections.abc import MutableMapping


ROOT = Path(__file__).resolve().parents[2]
SDK_SRC = ROOT / "sdk" / "src"
CORE_DIR = ROOT / "core"
BIN_NAME = "elastik-core.exe" if os.name == "nt" else "elastik-core"
CORE_BIN = CORE_DIR / "target" / "release" / BIN_NAME
SDK_BIN = SDK_SRC / "elastik" / "_bin" / BIN_NAME


class Check:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self, condition: bool, name: str, detail: str = "") -> None:
        self.n += 1
        if not condition:
            suffix = f"\n  {detail}" if detail else ""
            raise AssertionError(f"FAIL {self.n}: {name}{suffix}")
        print(f"ok {self.n:02d} - {name}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def build_and_bundle() -> None:
    subprocess.run(["cargo", "build", "--release"], cwd=CORE_DIR, check=True)
    SDK_BIN.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CORE_BIN, SDK_BIN)


def http(
    method: str,
    url: str,
    *,
    token: str | None = None,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    h = dict(headers or {})
    if token:
        h.setdefault("Authorization", f"Bearer {token}")
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, (
            e.read() if e.fp else b""
        )


def world_url(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + urllib.parse.quote(path.lstrip("/"), safe="/")


def expect_error(fn, status: int, check: Check, name: str) -> None:
    import elastik

    try:
        fn()
    except elastik.ElastikError as e:
        check(e.status == status, name, f"expected {status}, got {e.status}")
        return
    raise AssertionError(f"FAIL: {name}\n  expected ElastikError({status})")


def expect_error_type(fn, exc_type, check: Check, name: str) -> None:
    try:
        fn()
    except exc_type:
        check(True, name)
        return
    raise AssertionError(f"FAIL: {name}\n  expected {exc_type.__name__}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true", help="reuse bundled binary")
    args = ap.parse_args()

    if not args.no_build:
        build_and_bundle()
    elif not SDK_BIN.exists():
        raise SystemExit(f"missing bundled binary: {SDK_BIN}")

    if not compileall.compile_dir(str(SDK_SRC), quiet=1):
        raise SystemExit("python SDK compileall failed")

    sys.path.insert(0, str(SDK_SRC))
    import elastik
    from elastik import _spawn
    from elastik.sdk import Elastik

    check = Check()
    saved_tokens = {
        name: os.environ.get(name)
        for name in (
            "ELASTIK_APPROVE_TOKEN",
            "ELASTIK_WRITE_TOKEN",
            "ELASTIK_TOKEN",
            "ELASTIK_READ_TOKEN",
        )
    }
    try:
        for name in saved_tokens:
            os.environ.pop(name, None)
        os.environ["ELASTIK_TOKEN"] = "legacy-write"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            legacy_client = Elastik("http://127.0.0.1:1")
        check(legacy_client.bearer_token == "legacy-write", "legacy ELASTIK_TOKEN still supplies bearer token")
        check(
            any("ELASTIK_TOKEN is deprecated" in str(w.message) for w in caught),
            "legacy ELASTIK_TOKEN emits migration warning",
        )
    finally:
        for name, value in saved_tokens.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    check(_spawn._connect_host("0.0.0.0") == "127.0.0.1", "wildcard IPv4 maps to loopback")
    check(_spawn._client_url("0.0.0.0", 1234) == "http://127.0.0.1:1234", "wildcard IPv4 returns usable URL")
    check(_spawn._client_url("::", 1234) == "http://[::1]:1234", "wildcard IPv6 URL is bracketed")
    check("__version__" in elastik.__all__, "__version__ is public")
    show_buf = io.StringIO()
    with contextlib.redirect_stdout(show_buf):
        elastik.show_config()
    check("elastik " in show_buf.getvalue(), "show_config prints package version")
    prior_host = os.environ.get("ELASTIK_HOST")
    prior_port = os.environ.get("ELASTIK_PORT")
    prior_url = os.environ.get("ELASTIK_URL")
    try:
        os.environ.pop("ELASTIK_URL", None)
        os.environ["ELASTIK_HOST"] = "::"
        os.environ["ELASTIK_PORT"] = "4321"
        check(_spawn.default_url() == "http://[::1]:4321", "default_url reuses IPv6 client URL helper")
    finally:
        if prior_host is None:
            os.environ.pop("ELASTIK_HOST", None)
        else:
            os.environ["ELASTIK_HOST"] = prior_host
        if prior_port is None:
            os.environ.pop("ELASTIK_PORT", None)
        else:
            os.environ["ELASTIK_PORT"] = prior_port
        if prior_url is None:
            os.environ.pop("ELASTIK_URL", None)
        else:
            os.environ["ELASTIK_URL"] = prior_url
    with elastik.TrustedShellPool(size=1, timeout=2) as pool:
        shell = pool.run("echo sdk-shell", check=True)
        check("sdk-shell" in shell.stdout, "TrustedShellPool is exported and runs")

    elastik.clear_routes()
    try:
        elastik.run(reconnect=False)
    except RuntimeError as e:
        check(
            "no @elastik.listen handlers" in str(e),
            "reactor run fails fast with no handlers",
            str(e),
        )
    else:
        raise AssertionError("FAIL: reactor run without handlers did not fail")

    @elastik.listen("/home/sdk/unit/*")
    def _unit_handler(body):
        return None

    check(elastik.has_routes(), "reactor reports registered handlers")
    try:
        @elastik.listen("/home/sdk/unit/*")
        def _duplicate_handler(body):
            return None
    except ValueError:
        check(True, "reactor rejects duplicate handler patterns")
    else:
        raise AssertionError("FAIL: duplicate reactor handler was accepted")
    elastik.unlisten("/home/sdk/unit/*")
    check(not elastik.has_routes(), "reactor unlisten removes handler")

    client_env = (
        "ELASTIK_URL",
        "ELASTIK_HOST",
        "ELASTIK_PORT",
        "ELASTIK_WRITE_TOKEN",
        "ELASTIK_READ_TOKEN",
        "ELASTIK_APPROVE_TOKEN",
    )
    saved_client_env = {name: os.environ.get(name) for name in client_env}
    saved_default_client = getattr(elastik, "_default_client", None)
    try:
        for name in client_env:
            os.environ.pop(name, None)
        elastik._default_client = None
        try:
            elastik.get("/home/no-default-client")
        except RuntimeError as e:
            check("no default elastik client" in str(e), "module-level client needs start or env")
        else:
            raise AssertionError("FAIL: module-level get without start/env did not fail")
    finally:
        elastik._default_client = saved_default_client
        for name, value in saved_client_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    read_token = "read-e2e"
    write_token = "write-e2e"
    approve_token = "approve-e2e"
    key = "e2e-key-" + os.urandom(16).hex()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        occupied_port = int(blocker.getsockname()[1])
        try:
            elastik.start(port=occupied_port, key=key, quiet=True)
        except RuntimeError as e:
            check(
                "port already in use" in str(e),
                "start refuses to attach to occupied port",
                str(e),
            )
        else:
            elastik.stop()
            raise AssertionError("FAIL: start() accepted an occupied port")

    wildcard_port = free_port()
    with tempfile.TemporaryDirectory(prefix="elastik-sdk-wildcard-") as data_dir:
        wildcard = elastik.start(
            host="0.0.0.0",
            port=wildcard_port,
            key=key,
            data_dir=data_dir,
            quiet=True,
        )
        try:
            check(
                wildcard.url == f"http://127.0.0.1:{wildcard_port}",
                "start(host=0.0.0.0) returns reachable loopback client URL",
                wildcard.url,
            )
            check(
                wildcard.get("/proc/version").startswith(b"elastik-core "),
                "wildcard-bound core is probed through loopback",
            )
        finally:
            elastik.stop()

    with tempfile.TemporaryDirectory(prefix="elastik-sdk-e2e-") as data_dir:
        os.environ["ELASTIK_URL"] = base
        e = elastik.start(
            port=port,
            key=key,
            read_token=read_token,
            write_token=write_token,
            approve_token=approve_token,
            data_dir=data_dir,
            quiet=True,
        )
        reader = Elastik(base, bearer_token=read_token)
        writer = Elastik(base, bearer_token=write_token)
        approver = Elastik(base, bearer_token=approve_token)
        anon = Elastik(base, bearer_token="")

        try:
            # Read gate is real: no token cannot read once ELASTIK_READ_TOKEN is set.
            status, headers, body = http("GET", world_url(base, "/home/missing"))
            check(status == 401, "anonymous read is gated")
            check(
                "www-authenticate" in headers,
                "401 advertises Bearer challenge",
                str(headers),
            )

            # SDK PUT/GET/HEAD round trip with stored representation headers.
            res = writer.put(
                "/home/sdk/text",
                "hello",
                content_type="text/plain; charset=utf-8",
                content_language="zh-CN",
                content_disposition='attachment; filename="hello.txt"',
                cache_control="max-age=60",
                author="ranger",
            )
            check(res["status"] == 201, "sdk put returns 201 on create", str(res))
            check(res["etag"].startswith('"hmac-'), "sdk put exposes hmac ETag", str(res))
            check(reader.get("/home/sdk/text") == b"hello", "sdk get returns bytes")
            check(reader.get_text("/home/sdk/text") == "hello", "sdk get_text returns str")
            writer.put(
                "/home/sdk/json",
                '{"ok": true}',
                content_type="application/json",
            )
            check(reader.get_json("/home/sdk/json") == {"ok": True}, "sdk get_json decodes JSON")
            writer.put_text("/home/sdk/put-text", "plain")
            check(reader.get_text("/home/sdk/put-text") == "plain", "sdk put_text writes text")
            writer.put_json("/home/sdk/put-json", {"ok": True})
            check(reader.get_json("/home/sdk/put-json") == {"ok": True}, "sdk put_json writes JSON")
            head = reader.head("/home/sdk/text")
            check(head["content-type"] == "text/plain; charset=utf-8", "head content-type")
            check(head["content-language"] == "zh-CN", "head content-language")
            check(head["content-disposition"] == 'attachment; filename="hello.txt"', "head disposition")
            check(head["cache-control"] == "max-age=60", "head cache-control")
            check(head["x-meta-author"] == "ranger", "head x-meta")
            check(head["accept-ranges"] == "bytes", "head accept-ranges")
            debug_hooks: list[tuple[str, str, int, str]] = []
            writer.enable_debug(
                level="all",
                record=True,
                verbose=3,
                slow_ms=0,
                hook=lambda method, path, status, _ms, rid: debug_hooks.append(
                    (method, path, status, rid)
                ),
            )
            panel_html = reader.get_text("/tmp/debug-panel.html")
            check("EventSource(\"/listen/tmp/debug/requests\")" in panel_html, "debug panel listens for sink wakeups")
            check("fetch(SINK" in panel_html, "debug panel reads log body via GET")
            writer.put("/home/sdk/debug", "trace")
            check(writer.debug_history[-1]["path"] == "/home/sdk/debug", "debug_history records request path")
            check(writer.debug_history[-1]["rid"] != "?", "debug_history captures X-Request-Id")
            check(
                writer.debug_history[-1]["request_headers"]["authorization"] == "<redacted>",
                "debug verbose redacts Authorization",
            )
            check(debug_hooks[-1][:3] == ("PUT", "/home/sdk/debug", 201), "debug hook receives request summary")
            secret_resp = writer.request("OPTIONS", "/home/sdk/debug", headers={"X-Api-Key": "secret"})
            check(secret_resp.status == 204, "debug redaction probe request succeeds")
            check(
                writer.debug_history[-1]["request_headers"]["x-api-key"] == "<redacted>",
                "debug verbose redacts *-key headers",
            )
            debug_log = reader.get_text("/tmp/debug/requests")
            check("/home/sdk/debug" in debug_log, "debug sink records request JSONL in /tmp")
            check("/tmp/debug/requests" not in debug_log, "debug sink does not recursively log itself")
            slow_log = reader.get_text("/tmp/debug/slow")
            check("/home/sdk/debug" in slow_log, "debug slow sink records slow-threshold matches")
            try:
                writer.get("/home/sdk/debug-missing")
            except elastik.NotFound:
                pass
            else:
                raise AssertionError("FAIL: debug missing read did not raise NotFound")
            error_log = reader.get_text("/tmp/debug/errors")
            check('"status": 404' in error_log, "debug error sink records 4xx responses")
            stats = writer.debug_stats()
            check(stats["total_requests"] >= 2, "debug_stats summarizes recorded requests")
            check(stats["by_method"].get("PUT", 0) >= 1, "debug_stats groups by method")
            check(stats["by_status"].get(404, 0) >= 1, "debug_stats groups by status")
            first_debug_event = json.loads(debug_log.splitlines()[0])
            check("core_us" in first_debug_event, "debug JSONL includes core elapsed us")
            writer._debug_set_in_progress(True)
            threaded_history_before = len(writer.debug_history)
            debug_thread = threading.Thread(
                target=lambda: writer._debug_after_response(
                    "GET",
                    "/home/sdk/thread-local-debug",
                    {},
                    elastik.Response(200, {"x-request-id": "thread", "x-elapsed-us": "1"}, b"ok"),
                    1.0,
                ),
                daemon=True,
            )
            debug_thread.start()
            debug_thread.join(5)
            writer._debug_set_in_progress(False)
            check(
                len(writer.debug_history) == threaded_history_before + 1,
                "debug recursion guard is thread-local",
            )
            sinkless = Elastik(base, bearer_token=write_token)
            sinkless.enable_debug(level="all", sink=None, record=True, slow_ms=0, panel=False)
            sinkless_writes: list[str | None] = []
            sinkless._debug_append = lambda path, line: sinkless_writes.append(path)  # type: ignore[method-assign]
            sinkless._debug_after_response(
                "GET",
                "/home/sdk/sinkless-debug",
                {},
                elastik.Response(500, {"x-request-id": "sinkless", "x-elapsed-us": "1"}, b"boom"),
                101.0,
            )
            check(sinkless.debug_history[-1]["status"] == 500, "debug sink=None still records in memory")
            check(sinkless_writes == [], "debug sink=None disables request/error/slow sink writes")
            writer.disable_debug()
            writer.put(
                "/home/sdk/logo.png",
                b"\x89PNG\r\n",
                content_type="image/png",
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Frame-Options": "DENY",
                    "X-Future-HTTP-Thing": "ok",
                },
            )
            policy_head = reader.head("/home/sdk/logo.png")
            check(
                policy_head["access-control-allow-origin"] == "*",
                "safe response policy header is stored",
            )
            check(
                policy_head["content-security-policy"] == "default-src 'self'",
                "content-security-policy is stored",
            )
            check(policy_head["x-frame-options"] == "DENY", "x-frame-options is stored")
            check(
                policy_head["x-future-http-thing"] == "ok",
                "future safe response header is stored",
            )
            check("home/sdk/text" in reader.list(), "sdk list sees world")
            check("home/sdk/text" in reader.list_paths(), "sdk list_paths aliases list")
            check("home/sdk/text" in reader.list_keys(), "sdk list_keys aliases list")
            check("home/sdk/text" in elastik.list_paths(), "module list_paths aliases list")
            check(isinstance(writer, MutableMapping), "Elastik implements MutableMapping")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                check("home/sdk/text" in elastik.list_worlds(), "module list_worlds still works")
                check(
                    any(issubclass(w.category, DeprecationWarning) for w in caught),
                    "module list_worlds emits deprecation warning",
                )
            writer["/home/sdk/mapping"] = "mapped"
            check(reader["/home/sdk/mapping"] == b"mapped", "mapping __getitem__/__setitem__ work")
            try:
                reader["/home/sdk/mapping-missing"]
            except KeyError:
                check(True, "mapping missing key raises KeyError")
            else:
                raise AssertionError("FAIL: missing mapping key did not raise KeyError")
            check("/home/sdk/mapping" in reader, "mapping __contains__ sees path")
            check(len(reader) >= 1, "mapping __len__ delegates to list_paths")
            check(reader.exists("/home/sdk/mapping"), "exists() delegates to HEAD")
            check(reader.sizeof("/home/sdk/mapping") == 6, "sizeof() reads Content-Length")
            check(reader.checksum("/home/sdk/mapping").strip('"').startswith("hmac-"), "checksum() returns ETag")
            check(reader.is_audited("/home/sdk/mapping"), "is_audited() detects hmac ETag")
            check(reader.verify("/home/sdk/mapping"), "verify() aliases is_audited")
            check(reader.get_cached("/home/sdk/mapping") == b"mapped", "get_cached first read downloads")
            check(reader.get_cached("/home/sdk/mapping") == b"mapped", "get_cached second read uses validator")
            writer.put("/home/sdk/mapping", "remapped")
            check(reader.get_cached("/home/sdk/mapping") == b"remapped", "get_cached refreshes after change")
            diff = reader.diff("/home/sdk/mapping", "final")
            check("-remapped" in diff and "+final" in diff, "diff() returns unified text diff")
            check("remapped" in reader.preview("/home/sdk/mapping", width=20), "preview() returns shortened text")
            writer["src"] = "short"
            check("home/src" in list(writer), "iter() returns canonical home path")
            check(writer["home/src"] == b"short", "canonical iter path indexes back")
            writer.put_gzip("/home/sdk/gzip", "compressed")
            check(reader.head("/home/sdk/gzip")["content-encoding"] == "gzip", "put_gzip stores Content-Encoding")
            check(reader.get_gzip("/home/sdk/gzip") == b"compressed", "get_gzip decompresses body")
            writer.put_csv("/home/sdk/table.csv", [["t", "v"], ["1", "2"]])
            check(reader.get_csv("/home/sdk/table.csv") == [["t", "v"], ["1", "2"]], "CSV helpers round-trip rows")
            writer.put_struct("/dev/sdk/sensor0", ">ff", 23.5, 6.75)
            a, b = reader.get_struct("/dev/sdk/sensor0", ">ff")
            check(round(a, 1) == 23.5 and round(b, 2) == 6.75, "struct helpers round-trip binary values")
            writer.put_many({"/home/sdk/many/a": "A", "/home/sdk/many/b": "B"})
            many = reader.get_many(["/home/sdk/many/a", "/home/sdk/many/b"])
            check(many["/home/sdk/many/a"] == b"A" and many["/home/sdk/many/b"] == b"B", "get_many/put_many use concurrent HTTP requests")
            writer.copy("/home/sdk/mapping", "/home/sdk/mapping-copy")
            check(reader.get("/home/sdk/mapping-copy") == b"remapped", "copy() uses GET HEAD PUT")
            check(elastik.decode_disk_name("home%2Fnote%2Etxt") == "home/note.txt", "decode_disk_name explains data dirs")
            check(elastik.encode_disk_name("home/note.txt") == "home%2Fnote%2Etxt", "encode_disk_name mirrors core disk naming")
            cli_env = os.environ.copy()
            cli_env["PYTHONPATH"] = str(SDK_SRC)
            decoded = subprocess.check_output(
                [sys.executable, "-m", "elastik", "decode-path", "home%2Fnote%2Etxt"],
                text=True,
                env=cli_env,
            ).strip()
            check(decoded == "home/note.txt", "CLI decode-path decodes disk names")
            approver.put("/home/sdk/tree/a.txt", "A")
            approver.put("/home/sdk/tree/sub/b.txt", "BB")
            shallow = reader.ls("home/sdk/tree")
            check("home/sdk/tree/a.txt" in shallow and "home/sdk/tree/sub/" in shallow, "ls() shows immediate virtual children")
            deep = reader.ls("home/sdk/tree", depth=-1)
            check("home/sdk/tree/sub/b.txt" in deep, "ls(depth=-1) shows descendants")
            tree_text = reader.tree("home/sdk/tree")
            check("a.txt" in tree_text and "sub" in tree_text, "tree() renders virtual hierarchy")
            tree_ref = reader / "home" / "sdk" / "tree"
            check(any(child.name == "sub" for child in tree_ref.iterdir()), "WorldRef.iterdir() returns child refs")
            check(any(ref.name == "b.txt" for ref in tree_ref.walk()), "WorldRef.walk() returns descendants")
            check(any(ref.name == "a.txt" for ref in tree_ref.glob("*.txt")), "WorldRef.glob() filters immediate leaf names")
            check(not any(ref.name == "b.txt" for ref in tree_ref.glob("*.txt")), "WorldRef.glob() does not recurse")
            check(any(ref.name == "sub" for ref in tree_ref.glob("sub*")), "WorldRef.glob() includes virtual directories")
            check(any(ref.name == "b.txt" for ref in tree_ref.rglob("*.txt")), "WorldRef.rglob() recurses")
            file_ref = reader / "home" / "sdk" / "tree" / "a.txt"
            check(file_ref.name == "a.txt" and file_ref.stem == "a" and file_ref.suffix == ".txt", "WorldRef path properties match pathlib")
            check(file_ref.parent.name == "tree", "WorldRef.parent matches pathlib")
            check(reader.du("home/sdk/tree")["home/sdk/tree/sub/b.txt"] == 2, "du() reports Content-Length by path")
            expect_error_type(
                lambda: approver.rm("", recursive=True),
                ValueError,
                check,
                "rm('', recursive=True) requires force",
            )
            expect_error_type(
                lambda: approver.rm("home", recursive=True),
                ValueError,
                check,
                "rm(namespace, recursive=True) requires force",
            )
            expect_error_type(
                lambda: approver.mv("", "home/sdk/all", recursive=True),
                ValueError,
                check,
                "mv('', recursive=True) requires non-empty source",
            )
            expect_error_type(
                lambda: approver.mv("home/sdk/tree", "", recursive=True),
                ValueError,
                check,
                "mv(recursive=True) requires non-empty destination",
            )
            expect_error_type(
                lambda: approver.mv("home/sdk/tree", "home/sdk/tree", recursive=True),
                ValueError,
                check,
                "mv(recursive=True) rejects identical source and destination",
            )
            expect_error_type(
                lambda: reader.du("home/sdk/tree", max_workers=0),
                ValueError,
                check,
                "du(max_workers=0) is rejected",
            )
            approver.mv("home/sdk/tree/a.txt", "home/sdk/tree/a2.txt")
            check(reader.get("home/sdk/tree/a2.txt") == b"A", "mv() moves one path")
            expect_error_type(
                lambda: approver.mv("home/sdk/tree/a2.txt", "home/sdk/tree/a2.txt", overwrite=True),
                ValueError,
                check,
                "mv() rejects identical source and destination",
            )
            approver.put("home/sdk/tree/existing.txt", "old")
            approver.put("home/sdk/tree/new.txt", "new")
            expect_error_type(
                lambda: approver.mv("home/sdk/tree/new.txt", "home/sdk/tree/existing.txt"),
                FileExistsError,
                check,
                "mv() refuses overwrite by default",
            )
            approver.mv("home/sdk/tree/new.txt", "home/sdk/tree/existing.txt", overwrite=True)
            check(reader.get("home/sdk/tree/existing.txt") == b"new", "mv(overwrite=True) replaces destination")
            renamed = (approver / "home" / "sdk" / "tree" / "a2.txt").rename("home/sdk/tree/a3.txt")
            check(renamed.name == "a3.txt" and reader.get("home/sdk/tree/a3.txt") == b"A", "WorldRef.rename() returns destination ref")
            expect_error_type(
                lambda: (approver / "home").rmtree(),
                ValueError,
                check,
                "WorldRef.rmtree() guards namespace roots",
            )
            removed = (approver / "home" / "sdk" / "tree").rmtree()
            check(removed >= 2 and not reader.exists("home/sdk/tree/sub/b.txt"), "WorldRef.rmtree() removes virtual subtree")
            ref = approver / "home" / "sdk" / "ref"
            ref.write("ref-body")
            check(ref.read_text() == "ref-body", "WorldRef write/read_text round-trips")
            check(ref.exists(), "WorldRef exists works")
            check(ref.stat()["content-length"] == "8", "WorldRef stat returns headers")
            check(ref.unlink(), "WorldRef unlink deletes")
            with approver.tmp("sdk-temp") as tmp_path:
                approver.put(tmp_path, "temp")
                check(reader.get(tmp_path) == b"temp", "tmp() yields writable /tmp path")
            check(not reader.exists("tmp/sdk-temp"), "tmp() cleanup removes path when allowed")
            check("running" in repr(e) and base in repr(e), "__repr__ shows live core URL")
            del approver["/home/sdk/mapping"]
            check("/home/sdk/mapping" not in reader, "mapping __delitem__ deletes")
            fake = elastik.FakeElastik()
            fake.put("fake/note", "hello")
            check(isinstance(fake, MutableMapping), "FakeElastik is also MutableMapping-shaped")
            check(fake.get_text("fake/note") == "hello", "FakeElastik get_text works")
            check(fake.head("fake/note")["etag"].startswith("fake-"), "FakeElastik returns fake ETags")
            check(fake.get_cached("fake/note") == b"hello", "FakeElastik supports get_cached")
            fake_ref = fake / "home" / "fake" / "ref"
            fake_ref.write("fake-ref")
            check(fake_ref.read() == b"fake-ref", "FakeElastik supports WorldRef")
            fake.request(
                "PUT",
                "fake/raw",
                b"raw",
                headers={
                    "Content-Type": "text/custom",
                    "X-Meta-Test": "ok",
                    "Access-Control-Allow-Origin": "*",
                    "Content-Security-Policy": "default-src 'self'",
                    "Authorization": "Bearer should-not-persist",
                },
            )
            check(fake.head("fake/raw")["content-type"] == "text/custom", "FakeElastik request preserves Content-Type")
            check(fake.head("fake/raw")["x-meta-test"] == "ok", "FakeElastik request preserves X-Meta headers")
            check(
                fake.head("fake/raw")["access-control-allow-origin"] == "*",
                "FakeElastik preserves safe response headers",
            )
            check(
                "authorization" not in fake.head("fake/raw"),
                "FakeElastik does not persist Authorization",
            )
            config_buf = io.StringIO()
            with contextlib.redirect_stdout(config_buf):
                elastik.show_config()
            check(base in config_buf.getvalue(), "show_config reports live started URL")
            check(data_dir in config_buf.getvalue(), "show_config reports live data dir")
            elastik.stop()
            check("stopped" in repr(e), "__repr__ reports stopped child after stop()")
            e = elastik.start(
                port=port,
                key=key,
                read_token=read_token,
                write_token=write_token,
                approve_token=approve_token,
                data_dir=data_dir,
                quiet=True,
            )
            writer = Elastik(base, bearer_token=write_token)
            reader = Elastik(base, bearer_token=read_token)
            approver = Elastik(base, bearer_token=approve_token)
            resp = reader.request("OPTIONS", "/home/sdk/text")
            check(resp.status == 204 and resp.ok, "request() exposes raw HTTP response")
            check(resp.headers.get("allow") == "GET, HEAD, PUT, POST, DELETE, OPTIONS", "request() exposes headers")
            check(resp.etag == "", "Response.etag defaults empty when absent")
            expect_error_type(
                lambda: writer.put(
                    "/home/sdk/bad-content-length",
                    b"hi",
                    headers={"Content-Length": "999"},
                ),
                ValueError,
                check,
                "SDK rejects user-supplied Content-Length",
            )
            expect_error_type(
                lambda: writer.request(
                    "PUT",
                    "/home/sdk/bad-transfer-encoding",
                    b"hi",
                    headers={"Transfer-Encoding": "chunked"},
                ),
                ValueError,
                check,
                "SDK rejects user-supplied Transfer-Encoding",
            )

            # Binary exactness: bytes in, bytes out, Content-Type preserved.
            binary = bytes(range(256))
            writer.put("/home/sdk/blob", binary, content_type="application/pdf")
            check(reader.get("/home/sdk/blob") == binary, "binary body round-trips")
            check(reader.head("/home/sdk/blob")["content-type"] == "application/pdf", "binary content-type")
            with reader.open("/home/sdk/blob") as f:
                check(f.read(4) == bytes(range(4)), "open() reads initial Range chunk")
                check(f.seek(10) == 10 and f.read(3) == bytes(range(10, 13)), "open() seek/read uses Range")
            with (reader / "home" / "sdk" / "blob").open() as f:
                check(f.seek(-2, io.SEEK_END) == 254 and f.read() == bytes([254, 255]), "WorldRef.open supports seek from end")
            with reader.open("/home/sdk/table.csv") as raw:
                buffered = io.BufferedReader(raw)
                text = io.TextIOWrapper(buffered, encoding="utf-8", newline="")
                check(
                    list(csv.reader(text)) == [["t", "v"], ["1", "2"]],
                    "open() supports BufferedReader/TextIOWrapper/csv.reader",
                )

            # Bare paths are home paths, not magical namespace erasure.
            writer.put("sdk/bare", b"bare")
            check(reader.get("/sdk/bare") == b"bare", "bare sdk path maps to /home")
            check("home/sdk/bare" in reader.list(), "bare path lists as home/*")

            # Memory namespaces are still HTTP worlds, just transient storage.
            writer.put("/tmp/sdk/scratch", b"temp")
            tmp_head = reader.head("/tmp/sdk/scratch")
            check(reader.get("/tmp/sdk/scratch") == b"temp", "tmp memory world reads")
            check(tmp_head["etag"].startswith('"sha256-'), "tmp world uses body ETag")

            # Tier checks.
            expect_error(lambda: reader.put("/home/sdk/nope", b"x"), 401, check, "read token cannot write")
            expect_error_type(
                lambda: reader.put("/home/sdk/type", {"bad": "dict"}),
                TypeError,
                check,
                "SDK put rejects non-bytes non-str data",
            )
            expect_error(lambda: writer.put("/etc/sdk/system", b"x"), 401, check, "write token cannot write system")
            check(approver.put("/etc/sdk/system", b"ok")["status"] == 201, "approve token writes system")

            # SDK refuses reserved path shapes before sending.
            for bad in ("/proc", "/proc/nope", "/lib", "/etc", "/var/log"):
                try:
                    writer.put(bad, b"x")
                except ValueError:
                    check(True, f"sdk rejects reserved path {bad}")
                else:
                    raise AssertionError(f"FAIL: sdk accepted reserved path {bad}")
            check(reader.get("/proc/version").strip(), "proc/version is readable")

            # Conditional reads.
            etag = reader.head("/home/sdk/text")["etag"]
            cached = reader.get("/home/sdk/text", if_none_match=etag)
            check(cached is None, "SDK get(if_none_match) returns None on 304")

            # Range reads.
            chunk = reader.get("/home/sdk/text", range=(1, 3))
            check(chunk == b"ell", "SDK get(range=...) returns byte slice", repr(chunk))
            resp = reader.request("GET", "/home/sdk/text", headers={"Range": "bytes=1-3"})
            check(resp.status == 206, "request() Range returns 206")
            check(resp.headers.get("content-range") == "bytes 1-3/5", "request() Range content-range")

            status, headers, body = http(
                "GET",
                world_url(base, "/home/sdk/text"),
                token=read_token,
                headers={"Range": "bytes=99-100"},
            )
            check(status == 416, "unsatisfied Range returns 416")
            check(headers.get("content-range") == "bytes */5", "416 content-range")

            status, headers, body = http(
                "GET",
                world_url(base, "/home/sdk/text"),
                token=read_token,
                headers={"Range": "bytes=0-1,3-4"},
            )
            check(status == 200 and body == b"hello", "multi-range is ignored as full body")

            # Conditional writes.
            stale = "hmac-stale"
            expect_error(
                lambda: writer.put("/home/sdk/text", b"bad", if_match=stale),
                412,
                check,
                "SDK put stale if_match raises 412",
            )
            check(reader.get("/home/sdk/text") == b"hello", "failed If-Match did not mutate body")

            result = writer.put("/home/sdk/text", b"HELLO", if_match=etag)
            check(result["status"] == 200, "SDK put current if_match succeeds")
            check(reader.get("/home/sdk/text") == b"HELLO", "successful If-Match mutates body")

            expect_error(
                lambda: writer.put("/home/sdk/text", b"exists", create_only=True),
                412,
                check,
                "SDK put create_only=True blocks existing world",
            )

            result = writer.put("/home/sdk/new-if-none", b"new", create_only=True)
            check(result["status"] == 201, "SDK put create_only=True allows missing world")
            try:
                writer.put("/home/sdk/compat-if-none", b"new", if_none_match=True)  # type: ignore[arg-type]
            except TypeError:
                check(True, "SDK rejects bool if_none_match; use create_only=True")
            else:
                raise AssertionError("FAIL: bool if_none_match accepted")
            try:
                writer.put(
                    "/home/sdk/bad-precondition",
                    b"x",
                    create_only=True,
                    if_none_match="etag",
                )
            except ValueError:
                check(True, "SDK put rejects ambiguous create_only and if_none_match")
            else:
                raise AssertionError("FAIL: ambiguous create_only + if_none_match accepted")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                writer.put("/home/sdk/meta-typo", b"x", cache_contol="no-store")
                check(
                    any("cache_control" in str(w.message) for w in caught),
                    "SDK warns on near-miss metadata keyword",
                    repr([str(w.message) for w in caught]),
                )

            # POST append keeps existing representation metadata.
            writer.put("/home/sdk/append", b"abc", content_type="text/custom")
            result = writer.post("/home/sdk/append", b"def")
            check(result["status"] == 200, "SDK post append succeeds")
            check(reader.get("/home/sdk/append") == b"abcdef", "POST appends bytes")
            check(reader.head("/home/sdk/append")["content-type"] == "text/custom", "POST keeps metadata")

            # DELETE with precondition.
            del_etag = reader.head("/home/sdk/append")["etag"]
            expect_error(
                lambda: writer.delete("/home/sdk/append", if_match=stale),
                401,
                check,
                "write token cannot delete ordinary world",
            )
            expect_error(
                lambda: approver.delete("/home/sdk/append", if_match=stale),
                412,
                check,
                "SDK delete stale if_match raises 412",
            )
            check(approver.delete("/home/sdk/append", if_match=del_etag), "SDK delete current if_match succeeds")
            expect_error(lambda: reader.get("/home/sdk/append"), 404, check, "deleted world is gone")
            expect_error_type(
                lambda: reader.get("/home/sdk/append"),
                elastik.NotFound,
                check,
                "404 raises NotFound subclass",
            )
            try:
                writer.put("/home/sdk/text", b"bad", if_match=stale)
            except elastik.PreconditionFailed as e:
                check(
                    e.method == "PUT" and e.path == "/home/sdk/text",
                    "ElastikError carries method and path",
                    str(e),
                )
            else:
                raise AssertionError("FAIL: stale If-Match did not raise PreconditionFailed")
            expect_error(
                lambda: approver.delete("/var/log/deletes"),
                401,
                check,
                "delete ledger is append-only",
            )

            # OPTIONS / Allow / Link headers are visible at the wire.
            status, headers, _ = http(
                "OPTIONS", world_url(base, "/home/sdk/text"), token=read_token
            )
            check(status == 204, "OPTIONS returns 204")
            check(
                headers.get("allow") == "GET, HEAD, PUT, POST, DELETE, OPTIONS",
                "OPTIONS advertises world methods",
                str(headers),
            )
            check("link" in reader.head("/home/sdk/text"), "HEAD includes monitor/collection Link")

            # SDK listen uses core SSE and stays control-plane only.
            events: list[dict[str, str]] = []
            done = threading.Event()

            def consume_one() -> None:
                for event in reader.listen("/home/sdk/listen/*"):
                    events.append(event)
                    done.set()
                    break

            t = threading.Thread(target=consume_one, daemon=True)
            t.start()
            time.sleep(0.2)
            writer.put("/home/sdk/listen/a", b"payload")
            check(done.wait(5), "sdk listen receives an SSE event")
            ev = events[0]
            check(ev.get("event") == "put", "SSE event type is put", repr(ev))
            check(ev.get("path") == "/home/sdk/listen/a", "SSE event path")
            check(ev.get("method") == "PUT", "SSE event method")
            check("etag" in ev and ev["etag"].startswith("hmac-"), "SSE event has etag")
            check("payload" not in ev.get("data", ""), "SSE event does not embed body")

            replay_events: list[dict[str, str]] = []
            replay_done = threading.Event()
            writer.put("/home/sdk/listen/b", b"payload-2")

            def consume_replay() -> None:
                for event in reader.listen(
                    "/home/sdk/listen/*",
                    last_event_id=ev.get("id"),
                ):
                    replay_events.append(event)
                    replay_done.set()
                    break

            replay_t = threading.Thread(target=consume_replay, daemon=True)
            replay_t.start()
            check(replay_done.wait(5), "Last-Event-ID replays missed SSE event")
            replay = replay_events[0]
            check(replay.get("path") == "/home/sdk/listen/b", "replayed SSE event path")
            check(int(replay.get("id", "0")) > int(ev.get("id", "0")), "replayed SSE id advances")

            elastik.clear_routes()
            handled: list[tuple[str, bytes]] = []

            @elastik.listen("/home/sdk/reactor-run/*")
            def _on_reactor_event(body, path):
                handled.append((path, body))

            threading.Timer(
                0.2,
                lambda: writer.put("/home/sdk/reactor-run/a", b"reactor"),
            ).start()
            elastik.run(reader, reconnect=False, max_events=1)
            check(
                handled == [("/home/sdk/reactor-run/a", b"reactor")],
                "reactor run dispatches path kwarg and exits with max_events",
                repr(handled),
            )
            elastik.clear_routes()

            print(f"\nPASS sdk e2e blackbox: {check.n} checks")
            return 0
        finally:
            elastik.stop()


if __name__ == "__main__":
    raise SystemExit(main())
