"""SDK-side execution helpers for @listen handlers.

The core is the Elastik L5 storage surface behind AuditeDB. Tools live here, beside the reactor:

    pool = TrustedShellPool(size=4)

    @elastik.listen("/home/task/*")
    def handle(body, path, e):
        result = pool.run(body.decode("utf-8"))
        e.put("/home/result/" + path.rsplit("/", 1)[-1], result.stdout)

This is intentionally named "Trusted". Feeding arbitrary paths into a
shell is remote code execution. That is useful for local agent pipelines
and dangerous for public queues.
"""
from __future__ import annotations

import string
import os
import queue
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote


_DISK_SAFE = string.ascii_letters + string.digits + "-_~"


def encode_disk_name(world_name: str) -> str:
    """Return the on-disk directory name for a canonical elastik path.

    The core stores durable worlds in a flat data directory. Slashes and dots
    are part of the world key, not filesystem hierarchy, so they are percent
    encoded: ``home/note.txt`` -> ``home%2Fnote%2Etxt``.
    """
    out = []
    for byte in world_name.encode("utf-8"):
        ch = chr(byte)
        if ch in _DISK_SAFE:
            out.append(ch)
        else:
            out.append(f"%{byte:02X}")
    return "".join(out)


def decode_disk_name(disk_name: str) -> str:
    """Return the canonical elastik path for an on-disk world directory name."""
    return unquote(disk_name)


@dataclass(frozen=True)
class ShellResult:
    """Result from a warmed shell invocation."""

    command: str
    stdout: str
    returncode: int
    duration_s: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class ShellPoolError(RuntimeError):
    def __init__(self, result: ShellResult):
        self.result = result
        super().__init__(
            f"shell command failed with {result.returncode}: {result.command!r}"
        )


class _Worker:
    def __init__(
        self,
        argv: list[str],
        cwd: str | None,
        env: dict[str, str] | None,
        encoding: str,
    ) -> None:
        self.argv = argv
        self.cwd = cwd
        self.env = env
        self.encoding = encoding
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.proc = self._spawn()
        self.reader = threading.Thread(target=self._read_stdout, daemon=True)
        self.reader.start()

    def _spawn(self) -> subprocess.Popen:
        return subprocess.Popen(
            self.argv,
            cwd=self.cwd,
            env=self.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding=self.encoding,
            errors="replace",
            bufsize=1,
        )

    def _read_stdout(self) -> None:
        try:
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def terminate(self) -> None:
        if self.proc.poll() is not None:
            return
        try:
            self.proc.terminate()
            self.proc.wait(timeout=1.0)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=1.0)
            except Exception:
                pass


class TrustedShellPool:
    """A tiny warmed shell pool for trusted @listen workloads.

    Why not `subprocess.run` every event? Cold process startup costs are
    visible in bursty agent queues. This keeps a small number of shells
    alive and sends work through stdin.

    Boundary: this is not a sandbox. Only run commands from trusted
    worlds, trusted users, or private queues.
    """

    def __init__(
        self,
        size: int = 4,
        *,
        shell: str | Iterable[str] | None = None,
        timeout: float = 30.0,
        acquire_timeout: float | None = None,
        cwd: str | os.PathLike[str] | None = None,
        env: dict[str, str] | None = None,
        encoding: str = "utf-8",
    ) -> None:
        if size < 1:
            raise ValueError("size must be >= 1")
        self.size = size
        self.timeout = timeout
        self.acquire_timeout = acquire_timeout
        self.argv = _shell_argv(shell)
        self.cwd = str(Path(cwd)) if cwd is not None else None
        self.env = env
        self.encoding = encoding
        self._closed = False
        self._pool: queue.Queue[_Worker] = queue.Queue()
        for _ in range(size):
            self._pool.put(self._new_worker())

    def run(
        self,
        command: str,
        *,
        timeout: float | None = None,
        acquire_timeout: float | None = None,
        check: bool = False,
    ) -> ShellResult:
        """Run command in a warmed shell and return captured output.

        stderr is merged into stdout to avoid pipe deadlocks. The shell
        process is returned to the pool only after a unique sentinel line
        confirms this command finished. If the command times out or kills
        the shell, that worker is replaced.
        """
        if self._closed:
            raise RuntimeError("TrustedShellPool is closed")
        wait_for_worker = self.acquire_timeout if acquire_timeout is None else acquire_timeout
        try:
            worker = (
                self._pool.get()
                if wait_for_worker is None
                else self._pool.get(timeout=wait_for_worker)
            )
        except queue.Empty as exc:
            raise TimeoutError("no trusted shell worker became available") from exc
        if not worker.alive():
            worker.terminate()
            worker = self._new_worker()
        timeout = self.timeout if timeout is None else timeout
        started = time.monotonic()
        sentinel = f"__ELASTIK_DONE_{uuid.uuid4().hex}__"
        stdout: list[str] = []
        returncode = 1
        timed_out = False
        reusable = True
        try:
            self._drain(worker)
            script = self._wrap(command, sentinel)
            assert worker.proc.stdin is not None
            worker.proc.stdin.write(script)
            worker.proc.stdin.flush()

            deadline = started + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    reusable = False
                    worker.terminate()
                    returncode = -1
                    break
                try:
                    line = worker.lines.get(timeout=min(0.1, remaining))
                except queue.Empty:
                    if not worker.alive():
                        reusable = False
                        returncode = (
                            worker.proc.returncode
                            if worker.proc.returncode is not None
                            else -1
                        )
                        break
                    continue
                if line is None:
                    reusable = False
                    # EOF means the warm shell itself exited. Popen.returncode
                    # may still be None until poll()/wait(), and `0 or -1`
                    # would also lie about a clean exit. Preserve the actual
                    # process exit code when the shell dies mid-command.
                    if worker.proc.returncode is None:
                        try:
                            worker.proc.wait(timeout=0.5)
                        except subprocess.TimeoutExpired:
                            worker.terminate()
                    returncode = (
                        worker.proc.returncode
                        if worker.proc.returncode is not None
                        else -1
                    )
                    break
                stripped = line.rstrip("\r\n")
                prefix = sentinel + ":"
                if stripped.startswith(prefix):
                    try:
                        returncode = int(stripped[len(prefix) :].strip())
                    except ValueError:
                        returncode = 1
                    break
                stdout.append(line)
        except (BrokenPipeError, OSError):
            reusable = False
            worker.terminate()
            returncode = (
                worker.proc.returncode if worker.proc.returncode is not None else -1
            )
        finally:
            duration = time.monotonic() - started
            if reusable and worker.alive() and not timed_out:
                self._pool.put(worker)
            else:
                self._pool.put(self._new_worker())

        result = ShellResult(
            command=command,
            stdout="".join(stdout),
            returncode=returncode,
            duration_s=duration,
            timed_out=timed_out,
        )
        if check and not result.ok:
            raise ShellPoolError(result)
        return result

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        while True:
            try:
                worker = self._pool.get_nowait()
            except queue.Empty:
                break
            worker.terminate()

    def __enter__(self) -> "TrustedShellPool":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _new_worker(self) -> _Worker:
        return _Worker(self.argv, self.cwd, self.env, self.encoding)

    def _wrap(self, command: str, sentinel: str) -> str:
        if _is_windows_shell(self.argv):
            escaped = sentinel.replace("'", "''")
            return (
                "$global:LASTEXITCODE = 0\n"
                "$__elastik_status = 0\n"
                "try {\n"
                f"{command}\n"
                "  if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {\n"
                "    $__elastik_status = [int]$LASTEXITCODE\n"
                "  } elseif ($?) {\n"
                "    $__elastik_status = 0\n"
                "  } else {\n"
                "    $__elastik_status = 1\n"
                "  }\n"
                "} catch {\n"
                "  Write-Error $_\n"
                "  $__elastik_status = 1\n"
                "}\n"
                f"[Console]::Out.WriteLine('{escaped}:' + $__elastik_status)\n\n"
            )
        return (
            f"{command}\n"
            "__elastik_status=$?\n"
            f"printf '\\n{sentinel}:%s\\n' \"$__elastik_status\"\n"
        )

    @staticmethod
    def _drain(worker: _Worker) -> None:
        while True:
            try:
                worker.lines.get_nowait()
            except queue.Empty:
                return


def _shell_argv(shell: str | Iterable[str] | None) -> list[str]:
    if shell is None:
        if os.name == "nt":
            return [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-",
            ]
        return ["bash", "--noprofile", "--norc"]
    if isinstance(shell, str):
        return [shell]
    return list(shell)


def _is_windows_shell(argv: list[str]) -> bool:
    name = Path(argv[0]).name.lower()
    return name in {"powershell.exe", "powershell", "pwsh.exe", "pwsh"}


ShellPool = TrustedShellPool
