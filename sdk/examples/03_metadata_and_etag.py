"""Metadata headers and optimistic writes.

Run:
    python sdk/examples/03_metadata_and_etag.py
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
            e.put(
                "examples/report",
                "draft",
                content_type="text/plain; charset=utf-8",
                cache_control="no-store",
                project="demo",
            )
            head = e.head("examples/report")
            etag = head["etag"]
            print(head["content-type"])
            print(head["x-meta-project"])

            e.put("examples/report", "final", if_match=etag)
            print(e.get_text("examples/report"))

            e.put("examples/lock", "mine", create_only=True)
        finally:
            elastik.stop()


if __name__ == "__main__":
    main()
