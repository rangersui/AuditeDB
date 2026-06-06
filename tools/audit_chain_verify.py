#!/usr/bin/env python3
"""Independently verify Elastik per-world SQLite audit chains."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]

AUDIT_SELECT = """
SELECT e.id, e.event_type, e.target, e.body_sha256, e.size,
       e.content_type, e.meta_sha256, e.hmac, e.prev_hmac,
       h.name, h.value
FROM events e
LEFT JOIN event_headers h ON h.event_id=e.id
ORDER BY e.id ASC, h.name ASC, h.value ASC
"""

DISK_ENCODE_BYTES = set(range(0x20)) | set(b'%./\\:*?"<>| ')

DOMAIN_VECTOR_A = "5beb4e649f1f853eca23fde812df0a3cbab29af7c5a7a1ea02f5bd8eb5bd63c2"
DOMAIN_VECTOR_B = "2c8476f1a13782539378ba1640eb51aeb49537275e81e33f33292931641d9d83"


@dataclasses.dataclass(frozen=True)
class EventRow:
    id: int
    event_type: str
    target: str
    body_sha256: str
    size: int
    content_type: str
    meta_sha256: str
    hmac: str
    prev_hmac: str


@dataclasses.dataclass(frozen=True)
class VerifyOk:
    events: int
    genesis: str
    latest: str


@dataclasses.dataclass(frozen=True)
class VerifyBreak:
    break_at: int
    expected: str
    actual: str


@dataclasses.dataclass(frozen=True)
class WorldResult:
    world: str
    db: str
    status: str
    events: int | None = None
    genesis: str | None = None
    latest: str | None = None
    break_at: int | None = None
    expected: str | None = None
    actual: str | None = None
    error: str | None = None

    def ok(self) -> bool:
        return self.status == "valid"


class AuditVerifyError(Exception):
    pass


def disk_name(world: str) -> str:
    out: list[str] = []
    for byte in world.encode("utf-8"):
        if byte in DISK_ENCODE_BYTES or byte >= 0x7F:
            out.append(f"%{byte:02X}")
        else:
            out.append(chr(byte))
    return "".join(out)


def world_from_disk_name(name: str) -> str:
    return unquote(name)


def world_db(data_root: Path, world: str) -> Path:
    return data_root / disk_name(world) / "universe.db"


def iter_world_dbs(data_root: Path) -> list[tuple[str, Path]]:
    worlds: list[tuple[str, Path]] = []
    if not data_root.exists():
        raise AuditVerifyError(f"data root does not exist: {data_root}")
    for entry in sorted(data_root.iterdir(), key=lambda p: p.name):
        if not entry.is_dir():
            continue
        db = entry / "universe.db"
        if db.exists():
            world = world_from_disk_name(entry.name)
            canonical_db = world_db(data_root, world)
            if db != canonical_db:
                continue
            worlds.append((world, canonical_db))
    return worlds


def hmac_label(raw: str) -> str:
    if not raw:
        return "hmac-"
    if raw.startswith("hmac-"):
        return raw
    return f"hmac-{raw}"


def require_str(value: object, column: str) -> str:
    if not isinstance(value, str):
        raise AuditVerifyError(f"{column} is not TEXT")
    return value


def require_int(value: object, column: str) -> int:
    if not isinstance(value, int):
        raise AuditVerifyError(f"{column} is not INTEGER")
    return value


def meta_sha256_canonical(content_type: str, headers: list[tuple[str, str]]) -> str:
    digest = hashlib.sha256()
    digest.update(b"content-type\0")
    digest.update(content_type.encode("utf-8"))
    digest.update(b"\0")
    for name, value in headers:
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(value.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def hmac_field(mac: hmac.HMAC, label: bytes, value: str) -> None:
    encoded = value.encode("utf-8")
    mac.update(label)
    mac.update(b"\0")
    mac.update(str(len(encoded)).encode("ascii"))
    mac.update(b"\0")
    mac.update(encoded)
    mac.update(b"\0")


def event_hmac(
    key: bytes,
    *,
    prev: str,
    event_type: str,
    target: str,
    body_sha256: str,
    size: int,
    content_type: str,
    meta_sha256: str,
) -> str:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    hmac_field(mac, b"prev", prev)
    hmac_field(mac, b"type", event_type)
    hmac_field(mac, b"target", target)
    hmac_field(mac, b"body-sha256", body_sha256)
    hmac_field(mac, b"size", str(size))
    hmac_field(mac, b"content-type", content_type)
    hmac_field(mac, b"meta-sha256", meta_sha256)
    return mac.hexdigest()


def verify_event(
    row: EventRow,
    headers: list[tuple[str, str]],
    key: bytes,
    prev: str,
    idx: int,
) -> tuple[str, VerifyBreak | None]:
    if not hmac.compare_digest(row.prev_hmac.encode("utf-8"), prev.encode("utf-8")):
        return prev, VerifyBreak(idx, hmac_label(prev), hmac_label(row.prev_hmac))

    expected_meta = meta_sha256_canonical(row.content_type, headers)
    if not hmac.compare_digest(
        expected_meta.encode("utf-8"), row.meta_sha256.encode("utf-8")
    ):
        return prev, VerifyBreak(
            idx,
            f"meta-sha256-{expected_meta}",
            f"meta-sha256-{row.meta_sha256}",
        )

    expected_hmac = event_hmac(
        key,
        prev=prev,
        event_type=row.event_type,
        target=row.target,
        body_sha256=row.body_sha256,
        size=row.size,
        content_type=row.content_type,
        meta_sha256=row.meta_sha256,
    )
    if not hmac.compare_digest(expected_hmac.encode("utf-8"), row.hmac.encode("utf-8")):
        return prev, VerifyBreak(idx, hmac_label(expected_hmac), hmac_label(row.hmac))

    return row.hmac, None


def row_from_sql(row: sqlite3.Row) -> tuple[EventRow, tuple[str, str] | None]:
    event = EventRow(
        id=int(row[0]),
        event_type=require_str(row[1], "event_type"),
        target=require_str(row[2], "target"),
        body_sha256=require_str(row[3], "body_sha256"),
        size=require_int(row[4], "size"),
        content_type=require_str(row[5], "content_type"),
        meta_sha256=require_str(row[6], "meta_sha256"),
        hmac=require_str(row[7], "hmac"),
        prev_hmac=require_str(row[8], "prev_hmac"),
    )
    name = row[9]
    value = row[10]
    if name is None or value is None:
        return event, None
    return event, (require_str(name, "event_headers.name"), require_str(value, "event_headers.value"))


def verify_connection(
    conn: sqlite3.Connection, key: bytes, *, allow_empty: bool = False
) -> VerifyOk | VerifyBreak:
    prev = ""
    genesis = ""
    events = 0
    current: EventRow | None = None
    headers: list[tuple[str, str]] = []

    for sql_row in conn.execute(AUDIT_SELECT):
        row, header = row_from_sql(sql_row)
        if current is not None and current.id != row.id:
            prev, broken = verify_event(current, headers, key, prev, events)
            if broken is not None:
                return broken
            if events == 0:
                genesis = prev
            events += 1
            headers = []
        if current is None or current.id != row.id:
            current = row
        if header is not None:
            headers.append(header)

    if current is not None:
        prev, broken = verify_event(current, headers, key, prev, events)
        if broken is not None:
            return broken
        if events == 0:
            genesis = prev
        events += 1

    if events == 0:
        if allow_empty:
            return VerifyOk(0, hmac_label(""), hmac_label(""))
        return VerifyBreak(0, "at-least-one-event", "no-events")

    return VerifyOk(events, hmac_label(genesis), hmac_label(prev))


def verify_world_db(world: str, db: Path, key: bytes, *, allow_empty: bool) -> WorldResult:
    try:
        conn = sqlite3.connect(db)
        try:
            report = verify_connection(conn, key, allow_empty=allow_empty)
        finally:
            conn.close()
    except (sqlite3.Error, OSError, AuditVerifyError) as exc:
        return WorldResult(world=world, db=str(db), status="error", error=str(exc))

    if isinstance(report, VerifyOk):
        return WorldResult(
            world=world,
            db=str(db),
            status="valid",
            events=report.events,
            genesis=report.genesis,
            latest=report.latest,
        )
    return WorldResult(
        world=world,
        db=str(db),
        status="broken",
        break_at=report.break_at,
        expected=report.expected,
        actual=report.actual,
    )


def verify_data_root(
    data_root: Path,
    key: bytes,
    *,
    worlds: list[str] | None,
    allow_empty: bool,
) -> list[WorldResult]:
    if worlds:
        targets = [(world, world_db(data_root, world)) for world in worlds]
    else:
        targets = iter_world_dbs(data_root)

    results: list[WorldResult] = []
    for world, db in targets:
        if not db.exists():
            results.append(WorldResult(world=world, db=str(db), status="missing"))
            continue
        results.append(verify_world_db(world, db, key, allow_empty=allow_empty))
    return results


def print_text(results: list[WorldResult]) -> None:
    for result in results:
        if result.status == "valid":
            print(
                f"ok {result.world} events={result.events} "
                f"genesis={result.genesis} latest={result.latest}"
            )
        elif result.status == "broken":
            print(
                f"broken {result.world} at={result.break_at} "
                f"expected={result.expected} actual={result.actual}",
                file=sys.stderr,
            )
        elif result.status == "missing":
            print(f"missing {result.world} db={result.db}", file=sys.stderr)
        else:
            print(f"error {result.world} db={result.db}: {result.error}", file=sys.stderr)


def load_key(args: argparse.Namespace) -> bytes:
    if args.key is not None:
        return args.key.encode("utf-8")
    if args.key_file is not None:
        return Path(args.key_file).read_bytes()
    value = os.environ.get(args.key_env)
    if value is None or value == "":
        raise SystemExit(
            f"missing audit key: pass --key, --key-file, or set {args.key_env}"
        )
    return value.encode("utf-8")


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE stage_meta(
            id INTEGER PRIMARY KEY CHECK(id=1),
            body BLOB DEFAULT x'',
            content_type TEXT DEFAULT 'application/octet-stream'
        );
        INSERT OR IGNORE INTO stage_meta(id, body) VALUES(1, x'');
        CREATE TABLE meta_headers(
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY(name)
        );
        CREATE TABLE events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            target TEXT DEFAULT '',
            body_sha256 TEXT DEFAULT '',
            size INTEGER DEFAULT 0,
            content_type TEXT DEFAULT 'application/octet-stream',
            meta_sha256 TEXT DEFAULT '',
            hmac TEXT DEFAULT '',
            prev_hmac TEXT DEFAULT ''
        );
        CREATE TABLE event_headers(
            event_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            value TEXT NOT NULL
        );
        """
    )


def insert_event(
    conn: sqlite3.Connection,
    key: bytes,
    *,
    prev: str,
    event_type: str,
    target: str,
    body_sha256: str,
    size: int,
    content_type: str,
    headers: list[tuple[str, str]],
) -> str:
    canonical = sorted((name.lower(), value) for name, value in headers)
    meta = meta_sha256_canonical(content_type, canonical)
    digest = event_hmac(
        key,
        prev=prev,
        event_type=event_type,
        target=target,
        body_sha256=body_sha256,
        size=size,
        content_type=content_type,
        meta_sha256=meta,
    )
    conn.execute(
        """
        INSERT INTO events(timestamp, event_type, target, body_sha256, size,
                           content_type, meta_sha256, hmac, prev_hmac)
        VALUES(datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (event_type, target, body_sha256, size, content_type, meta, digest, prev),
    )
    event_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    for name, value in canonical:
        conn.execute(
            "INSERT INTO event_headers(event_id, name, value) VALUES(?, ?, ?)",
            (event_id, name, value),
        )
    return digest


def self_test() -> int:
    meta = meta_sha256_canonical("text/plain", [])
    vector_a = event_hmac(
        b"key",
        prev="",
        event_type="replace/home/",
        target="x",
        body_sha256="abc",
        size=3,
        content_type="text/plain",
        meta_sha256=meta,
    )
    vector_b = event_hmac(
        b"key",
        prev="",
        event_type="replace",
        target="/home/x",
        body_sha256="abc",
        size=3,
        content_type="text/plain",
        meta_sha256=meta,
    )
    assert vector_a == DOMAIN_VECTOR_A
    assert vector_b == DOMAIN_VECTOR_B
    assert vector_a != vector_b

    with tempfile.TemporaryDirectory(prefix="elastik-audit-verify-") as tmp:
        root = Path(tmp)
        db = world_db(root, "home/a")
        db.parent.mkdir(parents=True)
        conn = sqlite3.connect(db)
        try:
            create_schema(conn)
            h1 = insert_event(
                conn,
                b"key",
                prev="",
                event_type="put",
                target="home/a",
                body_sha256="abc",
                size=3,
                content_type="text/plain",
                headers=[("x-meta-author", "ranger")],
            )
            insert_event(
                conn,
                b"key",
                prev=h1,
                event_type="append",
                target="home/a",
                body_sha256="def",
                size=6,
                content_type="text/plain",
                headers=[],
            )
            conn.commit()
        finally:
            conn.close()

        results = verify_data_root(root, b"key", worlds=None, allow_empty=False)
        assert len(results) == 1
        assert results[0].status == "valid"
        assert results[0].events == 2

        conn = sqlite3.connect(db)
        try:
            conn.execute("UPDATE events SET hmac='bad' WHERE id=1")
            conn.commit()
        finally:
            conn.close()
        tampered = verify_data_root(root, b"key", worlds=["home/a"], allow_empty=False)
        assert tampered[0].status == "broken"
        assert tampered[0].break_at == 0

        empty = world_db(root, "home/empty")
        empty.parent.mkdir(parents=True)
        conn = sqlite3.connect(empty)
        try:
            create_schema(conn)
            conn.commit()
        finally:
            conn.close()
        empty_result = verify_data_root(root, b"key", worlds=["home/empty"], allow_empty=False)
        assert empty_result[0].status == "broken"
        assert empty_result[0].expected == "at-least-one-event"

        text_size = world_db(root, "home/text-size")
        text_size.parent.mkdir(parents=True)
        conn = sqlite3.connect(text_size)
        try:
            conn.executescript(
                """
                CREATE TABLE events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    body_sha256 TEXT NOT NULL,
                    size TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    meta_sha256 TEXT NOT NULL,
                    hmac TEXT NOT NULL,
                    prev_hmac TEXT NOT NULL
                );
                CREATE TABLE event_headers(
                    event_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    value TEXT NOT NULL
                );
                """
            )
            h = event_hmac(
                b"key",
                prev="",
                event_type="put",
                target="home/text-size",
                body_sha256="abc",
                size=3,
                content_type="text/plain",
                meta_sha256=meta,
            )
            conn.execute(
                """
                INSERT INTO events(timestamp, event_type, target, body_sha256,
                                   size, content_type, meta_sha256, hmac, prev_hmac)
                VALUES(datetime('now'), 'put', 'home/text-size', 'abc',
                       '3', 'text/plain', ?, ?, '')
                """,
                (meta, h),
            )
            conn.commit()
        finally:
            conn.close()
        text_size_result = verify_data_root(root, b"key", worlds=["home/text-size"], allow_empty=False)
        assert text_size_result[0].status == "error"
        assert "size is not INTEGER" in (text_size_result[0].error or "")

        half_null = world_db(root, "home/half-null")
        half_null.parent.mkdir(parents=True)
        conn = sqlite3.connect(half_null)
        try:
            conn.executescript(
                """
                CREATE TABLE stage_meta(
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    body BLOB DEFAULT x'',
                    content_type TEXT DEFAULT 'application/octet-stream'
                );
                INSERT OR IGNORE INTO stage_meta(id, body) VALUES(1, x'');
                CREATE TABLE events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    body_sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content_type TEXT NOT NULL,
                    meta_sha256 TEXT NOT NULL,
                    hmac TEXT NOT NULL,
                    prev_hmac TEXT NOT NULL
                );
                CREATE TABLE event_headers(
                    event_id INTEGER,
                    name TEXT,
                    value TEXT
                );
                """
            )
            insert_event(
                conn,
                b"key",
                prev="",
                event_type="put",
                target="home/half-null",
                body_sha256="abc",
                size=3,
                content_type="text/plain",
                headers=[],
            )
            conn.execute(
                "INSERT INTO event_headers(event_id, name, value) VALUES(1, NULL, 'ignored')"
            )
            conn.commit()
        finally:
            conn.close()
        half_null_result = verify_data_root(root, b"key", worlds=["home/half-null"], allow_empty=False)
        assert half_null_result[0].status == "valid"

        off_canonical = root / "home%2flower" / "universe.db"
        off_canonical.parent.mkdir(parents=True)
        conn = sqlite3.connect(off_canonical)
        try:
            create_schema(conn)
            insert_event(
                conn,
                b"key",
                prev="",
                event_type="put",
                target="home/a",
                body_sha256="abc",
                size=3,
                content_type="text/plain",
                headers=[],
            )
            conn.commit()
        finally:
            conn.close()
        scanned = verify_data_root(root, b"key", worlds=None, allow_empty=False)
        assert all(result.db != str(off_canonical) for result in scanned)

    print("audit chain verifier self-test ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_root", nargs="?", help="Elastik data root to verify")
    parser.add_argument("--world", action="append", help="Canonical world path to verify")
    parser.add_argument("--key", help="Audit HMAC key as UTF-8 text")
    parser.add_argument("--key-file", help="File containing audit HMAC key bytes")
    parser.add_argument("--key-env", default="ELASTIK_KEY", help="Environment variable for key")
    parser.add_argument("--allow-empty", action="store_true", help="Accept empty audit chains")
    parser.add_argument(
        "--require-worlds",
        action="store_true",
        help="Fail if the selected scan finds no world databases",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON results")
    parser.add_argument("--self-test", action="store_true", help="Run verifier self-test")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if args.data_root is None:
        parser.error("data_root is required unless --self-test is used")

    key = load_key(args)
    results = verify_data_root(
        Path(args.data_root),
        key,
        worlds=args.world,
        allow_empty=args.allow_empty,
    )
    if args.json:
        print(json.dumps([dataclasses.asdict(result) for result in results], indent=2))
    else:
        print_text(results)
    if args.require_worlds and not results:
        print("no world databases found", file=sys.stderr)
        return 1
    return 0 if all(result.ok() for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
