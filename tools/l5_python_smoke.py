#!/usr/bin/env python3
"""Smoke-test the in-process L5 Python SDK."""

from __future__ import annotations

import tempfile

import l5


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="l5-python-smoke-") as root:
        db = l5.open(root, key=b"0" * 32)
        try:
            db.put("home/note", b"hello", content_type="text/plain")
            assert db.get("home/note") == b"hello"
            assert db.verify("home/note") is True
        finally:
            db.close()
    print("l5 python smoke ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
