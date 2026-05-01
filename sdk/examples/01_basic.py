"""Basic elastik SDK round trip.

Run:
    python sdk/examples/01_basic.py
"""
from __future__ import annotations

import secrets
import socket
import tempfile
from pathlib import Path

import sys

_src = Path(__file__).resolve().parents[1] / "src"
if _src.exists():
    # Source checkout convenience. Copied examples use the installed package.
    sys.path.insert(0, str(_src))
import elastik


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="elastik-example-") as data_dir:
        e = elastik.start(
            port=free_port(),
            key=secrets.token_hex(32),
        write_token="write-token",
            data_dir=data_dir,
            quiet=True,
        )
        try:
            e.put("examples/basic", "hello from elastik")
            print(e.get("examples/basic"))
            print(e.get_text("examples/basic"))
            print(e.head("examples/basic")["content-type"])
        finally:
            elastik.stop()


if __name__ == "__main__":
    main()
