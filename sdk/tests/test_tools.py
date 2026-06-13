"""Stdlib tests for SDK-side warmed shell tools."""
from __future__ import annotations

import os
import re
import shlex
import socket
import sys
import time
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SDK_SRC = ROOT / "sdk" / "src"
sys.path.insert(0, str(SDK_SRC))

import elastik as elastik_module  # noqa: E402
from elastik.sdk import (  # noqa: E402
    Elastik,
    InsufficientStorage,
    Response,
    ServerError,
    TimelineCoordinate,
    _NON_PERSISTED_RESPONSE_HEADERS,
    _quote_path,
    _raise_for_response,
)
from elastik.testing import FakeElastik  # noqa: E402
from elastik._coap_client import _path_segments  # noqa: E402
from elastik._coap_client import get as coap_get  # noqa: E402
from elastik.tools import ShellPoolError, TrustedShellPool  # noqa: E402


def ps() -> bool:
    return os.name == "nt"


def q(value: str) -> str:
    if ps():
        return "'" + value.replace("'", "''") + "'"
    return shlex.quote(value)


def sleep_cmd(seconds: int) -> str:
    return f"Start-Sleep -Seconds {seconds}" if ps() else f"sleep {seconds}"


def shell_exit_cmd(code: int) -> str:
    return f"exit {code}"


def python_cmd(code: str) -> str:
    py = q(sys.executable)
    body = q(code)
    return f"& {py} -c {body}" if ps() else f"{py} -c {body}"


def check_header_blacklist_parity() -> None:
    """FakeElastik must reject the same persisted headers as the Rust core."""
    rs = (
        ROOT / "bin" / "src" / "server" / "http" / "semantics.rs"
    ).read_text(encoding="utf-8")
    arm = re.search(r"matches!\(\s*name,\s*(.*?)\s*\)", rs, re.DOTALL)
    assert arm, "could not find Rust header blacklist"
    rust_set = set(re.findall(r'"([a-z0-9-]+)"', arm.group(1)))
    assert _NON_PERSISTED_RESPONSE_HEADERS == rust_set, (
        "fake/real header policy diverged. "
        f"Only in Python: {sorted(_NON_PERSISTED_RESPONSE_HEADERS - rust_set)}; "
        f"only in Rust: {sorted(rust_set - _NON_PERSISTED_RESPONSE_HEADERS)}"
    )


def check_coap_unreachable_is_timeout() -> None:
    """UDP no-listener behavior differs by OS; expose one SDK exception."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])
    try:
        coap_get("127.0.0.1", port, "/home/no-listener", timeout=0.05)
    except TimeoutError:
        return
    raise AssertionError("CoAP no-listener path did not raise TimeoutError")


def check_coap_paths_share_http_validation() -> None:
    assert list(_path_segments("note")) == ["home", "note"]
    assert list(_path_segments("/home/note")) == ["home", "note"]
    for bad in ("/home//x", "home/x/", "/tmp//", "/home/%2E%2E/x", "/proc/version"):
        try:
            list(_path_segments(bad))
        except ValueError:
            continue
        raise AssertionError(f"CoAP SDK accepted invalid path {bad!r}")


def check_proc_paths_are_sdk_allowed() -> None:
    assert _quote_path("/proc/version") == "/proc/version"
    assert _quote_path("/proc/worlds") == "/proc/worlds"
    assert _quote_path("/proc/du") == "/proc/du"
    assert _quote_path("/proc/df") == "/proc/df"


def check_encoded_dot_segments_are_rejected() -> None:
    for bad in ("/home/%2E/x", "/home/%2e%2E/x", "/proc/audit/home/%2E%2E/x/verify"):
        try:
            _quote_path(bad)
        except ValueError:
            continue
        raise AssertionError(f"SDK accepted encoded dot segment {bad!r}")


def check_507_maps_to_insufficient_storage() -> None:
    resp = Response(507, {}, b"storage full\n")
    try:
        _raise_for_response(resp, "PUT", "home/full")
    except InsufficientStorage as exc:
        assert exc.status == 507
        return
    raise AssertionError("507 did not raise InsufficientStorage")


def check_timeline_coordinate_validation() -> None:
    event = {
        "path": "/home/timeline/sdk",
        "id": "999",
        "etag": "hmac-not-the-body-hash",
        "timeline-world": "home/timeline/sdk",
        "timeline-generation": "0" * 32,
        "timeline-seq": "7",
        "timeline-body-sha256": "a" * 64,
    }
    coord = TimelineCoordinate.from_event(event)
    assert coord.world == "home/timeline/sdk"
    assert coord.seq == 7

    try:
        TimelineCoordinate.from_parts("home/timeline/sdk", "0" * 32, 7.5, "a" * 64)
    except ValueError:
        pass
    else:
        raise AssertionError("float timeline seq was accepted")

    for bad in (
        {**event, "timeline-world": "home/other"},
        {**event, "timeline-generation": "A" * 32},
        {**event, "timeline-seq": "0"},
        {**event, "timeline-seq": str(2**63)},
        {key: value for key, value in event.items() if key != "path"},
        {key: value for key, value in event.items() if key != "timeline-seq"},
        {**event, "timeline-body-sha256": "g" * 64},
        {**event, "timeline-world": "tmp/timeline/sdk", "path": "/tmp/timeline/sdk"},
    ):
        try:
            TimelineCoordinate.from_event(bad)
        except ValueError:
            continue
        raise AssertionError(f"invalid timeline event accepted: {bad!r}")


def check_timeline_request_uses_query_not_path() -> None:
    import urllib.request

    seen: dict[str, str | list[str]] = {}
    coord = TimelineCoordinate.from_parts(
        "home/a b",
        "0" * 32,
        7,
        hashlib.sha256(b"old").hexdigest(),
    )

    class FakeHTTPResponse:
        def __init__(
            self,
            *,
            bad_proof: bool = False,
            bad_status: bool = False,
            bad_body: bool = False,
        ) -> None:
            self.status = 206 if bad_status else 200
            self.body = b"partial" if bad_body else b"old"
            self.headers = {
                "Content-Type": "text/plain",
                "Content-Length": str(len(self.body)),
                "X-Timeline-World": coord.world,
                "X-Timeline-Generation": coord.generation,
                "X-Timeline-Seq": "8" if bad_proof else str(coord.seq),
                "X-Timeline-Body-Sha256": coord.body_sha256,
            }

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return self.body

    def fake_urlopen(req, timeout=30):  # noqa: ANN001
        seen["url"] = req.full_url
        methods = seen.setdefault("methods", [])
        assert isinstance(methods, list)
        methods.append(req.get_method())
        seen["auth"] = req.headers.get("Authorization", "")
        return FakeHTTPResponse(
            bad_proof=seen.get("bad_proof") == "1",
            bad_status=seen.get("bad_status") == "1",
            bad_body=seen.get("bad_body") == "1",
        )

    prior = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        client = Elastik("http://example.test", bearer_token="reader")
        assert client.get_timeline(coord) == b"old"
        assert seen["auth"] == "Bearer reader"
        assert seen["url"].startswith("http://example.test/home/a%20b?")
        assert "?timeline=1&timeline-generation=" in seen["url"]
        assert "%3Ftimeline" not in seen["url"]
        assert "timeline-world" not in seen["url"]

        headers = client.head_timeline(coord)
        assert headers["x-timeline-seq"] == "7"
        assert seen["methods"] == ["GET", "HEAD"]

        assert "get_timeline" in elastik_module.__all__
        assert "head_timeline" in elastik_module.__all__
        elastik_module._set_default(client)
        try:
            assert elastik_module.get_timeline(coord) == b"old"
            assert elastik_module.head_timeline(coord)["x-timeline-seq"] == "7"
            assert seen["methods"] == ["GET", "HEAD", "GET", "HEAD"]
        finally:
            elastik_module._default_client = None

        try:
            FakeElastik().get_timeline(coord)
        except NotImplementedError:
            pass
        else:
            raise AssertionError("FakeElastik timeline helper should be explicit unsupported")
        try:
            FakeElastik().get_timeline("home/a b")  # type: ignore[arg-type]
        except TypeError:
            pass
        else:
            raise AssertionError("FakeElastik accepted a raw timeline coordinate")

        seen["bad_proof"] = "1"
        try:
            client.get_timeline(coord)
        except ServerError as exc:
            assert "x-timeline-seq mismatch" in str(exc), exc
        else:
            raise AssertionError("timeline proof header mismatch was accepted")
        seen.pop("bad_proof")

        seen["bad_status"] = "1"
        try:
            client.head_timeline(coord)
        except ServerError as exc:
            assert "status must be 200" in str(exc), exc
        else:
            raise AssertionError("timeline non-200 success was accepted")
        seen.pop("bad_status")

        seen["bad_body"] = "1"
        try:
            client.get_timeline(coord)
        except ServerError as exc:
            assert "body sha256 mismatch" in str(exc), exc
        else:
            raise AssertionError("timeline body hash mismatch was accepted")
    finally:
        urllib.request.urlopen = prior


def main() -> int:
    check_header_blacklist_parity()
    check_coap_unreachable_is_timeout()
    check_coap_paths_share_http_validation()
    check_proc_paths_are_sdk_allowed()
    check_encoded_dot_segments_are_rejected()
    check_507_maps_to_insufficient_storage()
    check_timeline_coordinate_validation()
    check_timeline_request_uses_query_not_path()

    with TrustedShellPool(size=1, timeout=2) as pool:
        r = pool.run("echo elastik-ready", check=True)
        assert r.ok, r
        assert "elastik-ready" in r.stdout, r

        # A size=1 pool proves the process stays warm across calls.
        if ps():
            pool.run("$env:ELASTIK_POOL_TEST = 'warm'", check=True)
            r = pool.run("echo $env:ELASTIK_POOL_TEST", check=True)
        else:
            pool.run("export ELASTIK_POOL_TEST=warm", check=True)
            r = pool.run("echo $ELASTIK_POOL_TEST", check=True)
        assert "warm" in r.stdout, r

        # Native process exit code is carried through the sentinel.
        r = pool.run(python_cmd("import sys; sys.exit(7)"))
        assert r.returncode == 7, r
        assert not r.ok, r

        try:
            pool.run(python_cmd("import sys; sys.exit(3)"), check=True)
        except ShellPoolError as e:
            assert e.result.returncode == 3, e.result
        else:
            raise AssertionError("check=True did not raise")

        # If the command kills the warm shell itself, preserve the OS
        # process exit code and replace the worker.
        r = pool.run(shell_exit_cmd(5))
        assert r.returncode == 5, r
        assert not r.ok, r
        r = pool.run("echo after-exit", check=True)
        assert "after-exit" in r.stdout, r

        # Timeout kills and replaces only the bad worker; the pool still works.
        r = pool.run(sleep_cmd(5), timeout=0.2)
        assert r.timed_out, r
        assert r.returncode == -1, r
        r = pool.run("echo after-timeout", check=True)
        assert "after-timeout" in r.stdout, r

        # Pool size is a hard concurrency bound. Callers can choose
        # fail-fast backpressure instead of blocking forever.
        worker = pool._pool.get_nowait()
        try:
            started = time.monotonic()
            try:
                pool.run("echo blocked", acquire_timeout=0.05)
            except TimeoutError:
                assert time.monotonic() - started < 1.0
            else:
                raise AssertionError("acquire_timeout did not fire")
        finally:
            pool._pool.put(worker)

    print("PASS sdk tools")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
