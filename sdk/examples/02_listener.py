"""One-shot @listen example.

The core emits SSE events for writes. The SDK consumes them and calls
your handler. `max_events=1` keeps this example from running forever.

Run:
    python sdk/examples/02_listener.py
"""
from __future__ import annotations

import secrets
import socket
import tempfile
import threading
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

        @elastik.listen("/home/examples/inbox/*")
        def on_inbox(body: bytes, path: str) -> None:
            print(f"{path}: {body.decode('utf-8')}")

        try:
            threading.Timer(
                0.2,
                lambda: e.put("/home/examples/inbox/one", "hello listener"),
            ).start()
            elastik.run(e, reconnect=False, max_events=1)
        finally:
            elastik.clear_routes()
            elastik.stop()


if __name__ == "__main__":
    main()
