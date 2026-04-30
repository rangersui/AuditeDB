"""Stdlib tests for SDK-side warmed shell tools."""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SDK_SRC = ROOT / "sdk" / "src"
sys.path.insert(0, str(SDK_SRC))

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


def main() -> int:
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

    print("PASS sdk tools")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
