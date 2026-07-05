#!/usr/bin/env python3
"""Smoke-test the in-process L5 Python SDK."""

from __future__ import annotations

import tempfile

import l5


def assert_raises(error_type, callback) -> None:
    try:
        callback()
    except error_type:
        return
    raise AssertionError(f"expected {error_type.__name__}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="l5-python-smoke-") as root:
        db = l5.open(root, key=b"0" * 32)
        try:
            db.put("home/note", b"hello", content_type="text/plain")
            assert db.get("home/note") == b"hello"
            assert db.verify("home/note") is True

            etag1 = db.head("home/note")["etag"]
            db.put("home/note", b"hello2", if_match=etag1)
            assert db.get("home/note") == b"hello2"
            assert_raises(
                l5.PreconditionFailed,
                lambda: db.put("home/note", b"stale", if_match=etag1),
            )

            etag2 = db.head("home/note")["etag"]
            db.put("home/note", b"comma", if_match=f'"stale", "{etag2}"')
            assert db.get("home/note") == b"comma"

            db.put("home/new", b"new", if_none_match="*")
            assert_raises(
                l5.PreconditionFailed,
                lambda: db.put("home/new", b"overwrite", if_none_match="*"),
            )
            new_etag = db.head("home/new")["etag"]
            assert_raises(
                l5.PreconditionFailed,
                lambda: db.put("home/new", b"weak", if_none_match=f'w/"{new_etag}"'),
            )

            assert_raises(
                ValueError,
                lambda: db.put("home/note", b"empty-list", if_match=[]),
            )
            assert_raises(
                ValueError,
                lambda: db.put("home/note", b"bad-quote", if_match='bad"etag'),
            )

            db.append("home/log", b"line1")
            assert db.get("home/log") == b"line1"
            assert_raises(
                l5.NotFound,
                lambda: db.append("home/missing", b"line", if_none_match="*"),
            )

            note_etag = db.head("home/note")["etag"]
            db.append("home/note", b"+tail", if_match=note_etag)
            assert db.get("home/note") == b"comma+tail"
            assert_raises(
                l5.PreconditionFailed,
                lambda: db.append("home/note", b"+stale", if_match=note_etag),
            )

            delete_etag = db.head("home/new")["etag"]
            assert db.delete("home/new", if_match=delete_etag) is True
            assert "home/new" not in db
            assert_raises(
                l5.PreconditionFailed,
                lambda: db.delete("home/note", if_match=etag1),
            )
        finally:
            db.close()
    print("l5 python smoke ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
