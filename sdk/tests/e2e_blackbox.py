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
from pathlib import Path


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
    check(_spawn._connect_host("0.0.0.0") == "127.0.0.1", "wildcard IPv4 maps to loopback")
    check(_spawn._client_url("0.0.0.0", 1234) == "http://127.0.0.1:1234", "wildcard IPv4 returns usable URL")
    check(_spawn._client_url("::", 1234) == "http://[::1]:1234", "wildcard IPv6 URL is bracketed")
    with elastik.TrustedShellPool(size=1, timeout=2) as pool:
        shell = pool.run("echo sdk-shell", check=True)
        check("sdk-shell" in shell.stdout, "TrustedShellPool is exported and runs")

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
            token=write_token,
            approve_token=approve_token,
            data_dir=data_dir,
            quiet=True,
        )
        reader = Elastik(base, token=read_token)
        writer = Elastik(base, token=write_token)
        approver = Elastik(base, token=approve_token)
        anon = Elastik(base, token="")

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
            head = reader.head("/home/sdk/text")
            check(head["content-type"] == "text/plain; charset=utf-8", "head content-type")
            check(head["content-language"] == "zh-CN", "head content-language")
            check(head["content-disposition"] == 'attachment; filename="hello.txt"', "head disposition")
            check(head["cache-control"] == "max-age=60", "head cache-control")
            check(head["x-meta-author"] == "ranger", "head x-meta")
            check(head["accept-ranges"] == "bytes", "head accept-ranges")
            check("home/sdk/text" in reader.list(), "sdk list sees world")
            resp = reader.request("OPTIONS", "/home/sdk/text")
            check(resp.status == 204 and resp.ok, "request() exposes raw HTTP response")
            check(resp.headers.get("allow") == "GET, HEAD, PUT, POST, DELETE, OPTIONS", "request() exposes headers")
            check(resp.etag == "", "Response.etag defaults empty when absent")

            # Binary exactness: bytes in, bytes out, Content-Type preserved.
            binary = bytes(range(256))
            writer.put("/home/sdk/blob", binary, content_type="application/pdf")
            check(reader.get("/home/sdk/blob") == binary, "binary body round-trips")
            check(reader.head("/home/sdk/blob")["content-type"] == "application/pdf", "binary content-type")

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
                lambda: writer.put("/home/sdk/text", b"exists", if_none_match=True),
                412,
                check,
                "SDK put if_none_match=True blocks existing world",
            )

            result = writer.put("/home/sdk/new-if-none", b"new", if_none_match=True)
            check(result["status"] == 201, "SDK put if_none_match=True allows missing world")

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

            print(f"\nPASS sdk e2e blackbox: {check.n} checks")
            return 0
        finally:
            elastik.stop()


if __name__ == "__main__":
    raise SystemExit(main())
