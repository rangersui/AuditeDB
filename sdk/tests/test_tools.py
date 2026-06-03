"""Stdlib tests for SDK-side warmed shell tools."""
from __future__ import annotations

import os
import re
import shlex
import socket
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SDK_SRC = ROOT / "sdk" / "src"
sys.path.insert(0, str(SDK_SRC))

from elastik.sdk import (  # noqa: E402
    InsufficientStorage,
    Response,
    _NON_PERSISTED_RESPONSE_HEADERS,
    _quote_path,
    _raise_for_response,
)
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


def main() -> int:
    check_header_blacklist_parity()
    check_coap_unreachable_is_timeout()
    check_coap_paths_share_http_validation()
    check_proc_paths_are_sdk_allowed()
    check_encoded_dot_segments_are_rejected()
    check_507_maps_to_insufficient_storage()

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
