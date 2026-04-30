"""Spawn the bundled elastik-core Rust binary as a child process.

This is the "NumPy ships C kernels in the wheel" trick. The Rust
binary lives at `elastik/_bin/elastik-core[.exe]`, was built once on a
build machine, and is shipped as `package_data`. `elastik.start()`
launches it in a subprocess and returns a pre-bound `Elastik` client.

The user does:

    import elastik
    e = elastik.start(token="x")
    e.put("/home/note", "hi")
    print(e.get("/home/note"))
    elastik.stop()

…and never sees a Cargo.toml.
"""
from __future__ import annotations

import atexit
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional


_proc: Optional[subprocess.Popen] = None


def _load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader. KEY=VALUE per line, # comments, optional
    surrounding "..." or '...' on values. Existing env vars win — .env
    only fills in what isn't already set. No interpolation, no exports,
    no shell substitution. Stdlib-only, deliberately small.
    """
    p = Path(path)
    if not p.exists():
        return
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
            v = v[1:-1]
        os.environ.setdefault(k, v)


def _binary_path() -> Path:
    """Locate the bundled binary inside the installed package."""
    here = Path(__file__).resolve().parent / "_bin"
    name = "elastik-core.exe" if sys.platform == "win32" else "elastik-core"
    return here / name


def _wait_for_port(host: str, port: int, deadline_s: float = 10.0) -> bool:
    """Poll until the server accepts a TCP connection or we give up."""
    connect_host = _connect_host(host)
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            with socket.create_connection((connect_host, port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _connect_host(host: str) -> str:
    """Host a local client should use for follow-up probes."""
    stripped = host.strip("[]")
    if stripped in ("", "0.0.0.0"):
        return "127.0.0.1"
    if stripped == "::":
        return "::1"
    return stripped


def _url_host(host: str) -> str:
    """Format a host for an http:// URL."""
    connect_host = _connect_host(host)
    if ":" in connect_host and not connect_host.startswith("["):
        return f"[{connect_host}]"
    return connect_host


def _client_url(host: str, port: int) -> str:
    """URL a local client should use after the core binds."""
    return f"http://{_url_host(host)}:{port}"


def _port_is_free(host: str, port: int) -> bool:
    """Best-effort preflight so start() does not attach to a stranger server."""
    try:
        infos = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
            flags=socket.AI_PASSIVE,
        )
    except OSError:
        return False
    checked = False
    # Be conservative: if any address family the host may bind is occupied,
    # refuse to start. This avoids returning a client pointed at a stranger
    # server when localhost resolves to multiple loopback families.
    seen: set[tuple[int, tuple]] = set()
    for family, socktype, proto, _canon, sockaddr in infos:
        key = (family, sockaddr)
        if key in seen:
            continue
        seen.add(key)
        checked = True
        try:
            with socket.socket(family, socktype, proto) as s:
                s.bind(sockaddr)
        except OSError:
            return False
    return checked


def _probe_core(host: str, port: int, token: str = "") -> bool:
    """Confirm that the accepting socket is actually elastik-core."""
    url = f"{_client_url(host, port)}/proc/version"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            body = r.read(128)
            return r.status == 200 and body.startswith(b"elastik-core ")
    except (OSError, urllib.error.URLError):
        return False


def start(
    port: int | None = None,
    host: str | None = None,
    key: str | None = None,
    read_token: str | None = None,
    token: str | None = None,
    approve_token: str | None = None,
    data_dir: Optional[str] = None,
    quiet: bool = True,
):
    """Launch the bundled elastik-core. Returns a pre-bound Elastik client.

    All process state is the user's: token, port, key, data dir. We only
    set sane defaults so `elastik.start()` with no arguments produces a
    working instance pinned to localhost.
    """
    global _proc
    if _proc is not None and _proc.poll() is None:
        raise RuntimeError(
            "elastik already running in this process — call elastik.stop() first"
        )

    host = host or os.getenv("ELASTIK_HOST", "127.0.0.1")
    if port is None:
        port = int(os.getenv("ELASTIK_PORT", "3105"))
    # ELASTIK_KEY: no constant default. The audit chain HMAC computed
    # against a publicly-known key is meaningless — anyone could forge
    # events. Caller passes `key=...`, the env provides ELASTIK_KEY,
    # or .env (already loaded by `import elastik`) supplies it.
    # Validate before checking the binary — a missing key is a config
    # error the user can fix; a missing binary is an install error.
    key = key or os.getenv("ELASTIK_KEY")
    if not key:
        raise RuntimeError(
            "ELASTIK_KEY required — set it in .env, export it in the shell, "
            "or pass key=… to elastik.start().\n"
            "Generate one with: "
            "python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    binary = _binary_path()
    if not binary.exists():
        raise RuntimeError(
            f"bundled binary not found: {binary}\n"
            "If you're working from source, build and bundle it from the repo root:\n"
            "  cargo build --release --manifest-path core/Cargo.toml\n"
            "  mkdir -p sdk/src/elastik/_bin\n"
            "  cp core/target/release/elastik-core* sdk/src/elastik/_bin/\n"
            f"Expected binary directory: {binary.parent}"
        )
    if not _port_is_free(host, port):
        raise RuntimeError(f"port already in use before elastik start: {host}:{port}")
    read_token = (
        os.getenv("ELASTIK_READ_TOKEN", "") if read_token is None else read_token
    )
    token = os.getenv("ELASTIK_TOKEN", "") if token is None else token
    approve_token = (
        os.getenv("ELASTIK_APPROVE_TOKEN", "")
        if approve_token is None else approve_token
    )
    data_dir = data_dir if data_dir is not None else os.getenv("ELASTIK_DATA")

    env = os.environ.copy()
    env["ELASTIK_HOST"] = host
    env["ELASTIK_PORT"] = str(port)
    env["ELASTIK_KEY"] = key
    if read_token:
        env["ELASTIK_READ_TOKEN"] = read_token
    else:
        env.pop("ELASTIK_READ_TOKEN", None)
    if token:
        env["ELASTIK_TOKEN"] = token
    else:
        env.pop("ELASTIK_TOKEN", None)
    if approve_token:
        env["ELASTIK_APPROVE_TOKEN"] = approve_token
    else:
        env.pop("ELASTIK_APPROVE_TOKEN", None)
    if data_dir:
        env["ELASTIK_DATA"] = str(data_dir)
    else:
        env.pop("ELASTIK_DATA", None)

    out = subprocess.DEVNULL if quiet else None
    _proc = subprocess.Popen([str(binary)], env=env, stdout=out, stderr=out)
    atexit.register(stop)

    if not _wait_for_port(host, port):
        stop()
        raise RuntimeError(
            f"elastik-core failed to start on {host}:{port} within 10s"
        )
    if _proc is None or _proc.poll() is not None:
        code = None if _proc is None else _proc.returncode
        stop()
        raise RuntimeError(f"elastik-core exited during startup (code={code})")
    probe_token = approve_token or token or read_token
    if not _probe_core(host, port, probe_token):
        stop()
        raise RuntimeError(f"port {host}:{port} did not answer as elastik-core")

    # Re-import here to dodge a circular import at module load
    from elastik.sdk import Elastik

    return Elastik(_client_url(host, port), token=approve_token or token or read_token)


def stop() -> None:
    """Kill the launched binary, if any. Safe to call multiple times."""
    global _proc
    if _proc is None:
        return
    try:
        _proc.terminate()
        try:
            _proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _proc.kill()
            _proc.wait(timeout=2)
    except OSError:
        pass
    _proc = None


def is_running() -> bool:
    return _proc is not None and _proc.poll() is None


def default_url() -> str:
    """Where the module-level `elastik.put`/`elastik.get` calls land by
    default. Override with `ELASTIK_URL`. Otherwise derive the Rust core
    URL from `ELASTIK_HOST` + `ELASTIK_PORT`."""
    explicit = os.getenv("ELASTIK_URL")
    if explicit:
        return explicit
    host = os.getenv("ELASTIK_HOST", "127.0.0.1")
    port = int(os.getenv("ELASTIK_PORT", "3105"))
    return _client_url(host, port)


def binary_info() -> dict:
    """Where is the bundled binary? How big? Does it exist? — useful
    for `python -m elastik` debugging."""
    p = _binary_path()
    return {
        "path": str(p),
        "exists": p.exists(),
        "size_bytes": p.stat().st_size if p.exists() else None,
        "platform": sys.platform,
    }
