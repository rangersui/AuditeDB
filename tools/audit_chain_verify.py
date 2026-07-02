#!/usr/bin/env python3
"""Independently verify L5 per-world SQLite audit chains.

The verifier mirrors the Engine audit frame. Event HMAC fields and
``meta_sha256`` metadata fields are length-framed as
``label\\0len\\0value\\0``.
"""

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
from urllib.parse import unquote_to_bytes


ROOT = Path(__file__).resolve().parents[1]

AUDIT_SELECT = """
SELECT e.id, e.timestamp, e.event_type, e.target, e.body_sha256, e.size,
       e.content_type, e.meta_sha256, e.hmac, e.prev_hmac,
       h.name, h.value
FROM events e
LEFT JOIN event_headers h ON h.event_id=e.id
ORDER BY e.id ASC, h.name ASC, h.value ASC
"""

DISK_ENCODE_BYTES = set(range(0x20)) | set(b'%./\\:*?"<>| ')
CURRENT_WORLD_FORMAT_VERSION = 2
WORLD_FORMAT_VERSION_HEADER = "auditedb-world-format-version"
DELETE_SUBJECT_WORLD = "auditedb-delete-subject-world"
DELETE_SUBJECT_GENERATION = "auditedb-delete-subject-generation"
DELETE_SUBJECT_SEQ = "auditedb-delete-subject-seq"
DELETE_SUBJECT_BODY_SHA256 = "auditedb-delete-subject-body-sha256"
DELETE_SUBJECT_HMAC = "auditedb-delete-subject-hmac"
DELETE_SUBJECT_PREFIX = "auditedb-delete-subject-"
DELETE_SUBJECT_HEADERS = (
    DELETE_SUBJECT_WORLD,
    DELETE_SUBJECT_GENERATION,
    DELETE_SUBJECT_SEQ,
    DELETE_SUBJECT_BODY_SHA256,
    DELETE_SUBJECT_HMAC,
)
DELETE_EVENT_TYPES = {"delete_intent", "delete_commit", "delete_commit_failed"}
MEMORY_WORLD_PREFIXES = ("tmp/", "dev/", "sys/")
WORLD_PREFIXES = ("home/", "tmp/", "dev/", "sys/", "etc/", "lib/", "boot/", "usr/", "var/")
NAMESPACE_PREFIXES = tuple(prefix[:-1] for prefix in WORLD_PREFIXES)
MAX_DISK_WORLD_NAME_BYTES = 200

DOMAIN_VECTOR_A = "f9fcb41b1447d4338dd73b83ea6c2088fb9112258bfd562898a1218b053fbae9"
DOMAIN_VECTOR_B = "13f7ddeb942620b992b40957496b89147617c0db1342c52a500895c10463cdbb"


@dataclasses.dataclass(frozen=True)
class EventRow:
    id: int
    timestamp: str
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
    try:
        world = unquote_to_bytes(name).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditVerifyError(
            f"invalid world directory {name!r}: invalid percent UTF-8: {exc}"
        ) from exc
    if not is_canonical_world(world):
        raise AuditVerifyError(
            f"invalid world directory {name!r}: decoded world path failed validation"
        )
    canonical = disk_name(world)
    if canonical != name:
        raise AuditVerifyError(
            f"invalid world directory {name!r}: non-canonical disk name for {world}"
        )
    return world


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
            worlds.append((world, world_db(data_root, world)))
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


def is_lower_hex(value: str, length: int) -> bool:
    return len(value) == length and all(ch in "0123456789abcdef" for ch in value)


def require_generation(value: object) -> str:
    raw = require_str(value, "stage_meta.generation")
    if not is_lower_hex(raw, 32):
        raise AuditVerifyError("stage_meta.generation is not 128-bit lower hex")
    return raw


def require_timestamp(value: str) -> None:
    if len(value) != 24:
        raise AuditVerifyError(f"timestamp is not canonical SQLite UTC ms: {value}")
    punctuation = {4: "-", 7: "-", 10: "T", 13: ":", 16: ":", 19: ".", 23: "Z"}
    for idx, ch in enumerate(value):
        expected = punctuation.get(idx)
        if expected is not None:
            if ch != expected:
                raise AuditVerifyError(f"timestamp is not canonical SQLite UTC ms: {value}")
        elif not ch.isdigit():
            raise AuditVerifyError(f"timestamp is not canonical SQLite UTC ms: {value}")


def is_control_char(ch: str) -> bool:
    code = ord(ch)
    return code <= 0x1F or 0x7F <= code <= 0x9F


def disk_world_name_len(value: str) -> int:
    size = 0
    for byte in value.encode("utf-8"):
        size += 3 if byte in DISK_ENCODE_BYTES or byte >= 0x7F else 1
    return size


def strip_dot_token(segment: str) -> str | None:
    if segment.startswith("."):
        return segment[1:]
    if len(segment) >= 3 and segment[:3].lower() == "%2e":
        return segment[3:]
    return None


def is_dot_segment(segment: str) -> bool:
    rest = strip_dot_token(segment)
    if rest is None:
        return False
    if rest == "":
        return True
    tail = strip_dot_token(rest)
    return tail == ""


def is_reserved_world_name(value: str) -> bool:
    return value in NAMESPACE_PREFIXES or value in {"proc", "var/log"} or value.startswith("proc/")


def is_canonical_world(value: str) -> bool:
    if value == "" or is_reserved_world_name(value):
        return False
    if disk_world_name_len(value) > MAX_DISK_WORLD_NAME_BYTES:
        return False
    if "\\" in value or any(is_control_char(ch) for ch in value):
        return False
    for segment in value.split("/"):
        if segment == "" or is_dot_segment(segment):
            return False
    namespace = value.split("/", 1)[0]
    return namespace in NAMESPACE_PREFIXES


def is_memory_world(value: str) -> bool:
    return value.startswith(MEMORY_WORLD_PREFIXES)


def require_world_format(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT id, version FROM world_format").fetchall()
    if len(row) != 1:
        raise AuditVerifyError("world_format must contain exactly one row")
    marker_id, version = row[0]
    if marker_id != 1:
        raise AuditVerifyError("world_format.id must be 1")
    if version != CURRENT_WORLD_FORMAT_VERSION:
        raise AuditVerifyError(f"unsupported world format version: {version}")


def load_generation(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT generation FROM stage_meta WHERE id=1").fetchone()
    if row is None:
        raise AuditVerifyError("missing required row: stage_meta id=1")
    return require_generation(row[0])


def meta_sha256_canonical(content_type: str, headers: list[tuple[str, str]]) -> str:
    digest = hashlib.sha256()
    sha256_field(digest, b"content-type", content_type)
    for name, value in headers:
        sha256_field(digest, b"header-name", name)
        sha256_field(digest, b"header-value", value)
    return digest.hexdigest()


def sha256_field(digest: "hashlib._Hash", label: bytes, value: str) -> None:
    encoded = value.encode("utf-8")
    digest.update(label)
    digest.update(b"\0")
    digest.update(str(len(encoded)).encode("ascii"))
    digest.update(b"\0")
    digest.update(encoded)
    digest.update(b"\0")


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
    world: str,
    timestamp: str,
    event_type: str,
    target: str,
    generation: str,
    body_sha256: str,
    size: int,
    content_type: str,
    meta_sha256: str,
) -> str:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    hmac_field(mac, b"prev", prev)
    hmac_field(mac, b"world", world)
    hmac_field(mac, b"timestamp", timestamp)
    hmac_field(mac, b"type", event_type)
    hmac_field(mac, b"target", target)
    hmac_field(mac, b"gen", generation)
    hmac_field(mac, b"body-sha256", body_sha256)
    hmac_field(mac, b"size", str(size))
    hmac_field(mac, b"content-type", content_type)
    hmac_field(mac, b"meta-sha256", meta_sha256)
    return mac.hexdigest()


def verify_event(
    row: EventRow,
    headers: list[tuple[str, str]],
    key: bytes,
    world: str,
    generation: str,
    prev: str,
    idx: int,
) -> tuple[str, VerifyBreak | None]:
    if row.event_type not in {
        "put",
        "append",
        "delete_intent",
        "delete_commit",
        "delete_commit_failed",
        "format",
    }:
        return prev, VerifyBreak(idx, "known-event-type", f"event-type-{row.event_type}")
    if row.event_type in {"put", "append", "format"} and row.target != world:
        return prev, VerifyBreak(idx, f"target-{world}", f"target-{row.target}")
    if row.event_type == "format":
        expected_version = str(CURRENT_WORLD_FORMAT_VERSION)
        if (WORLD_FORMAT_VERSION_HEADER, expected_version) not in headers:
            return prev, VerifyBreak(
                idx,
                f"{WORLD_FORMAT_VERSION_HEADER}-{expected_version}",
                "missing-world-format-version",
            )
    if row.event_type in DELETE_EVENT_TYPES:
        if not is_canonical_world(row.target):
            return prev, VerifyBreak(
                idx,
                "delete-target-canonical-world",
                f"target-{row.target}",
            )
        proof_break = verify_delete_subject_proof(row, headers, idx)
        if proof_break is not None:
            return prev, proof_break
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

    try:
        require_timestamp(row.timestamp)
    except AuditVerifyError as exc:
        return prev, VerifyBreak(idx, "timestamp-sqlite-utc-ms", str(exc))

    expected_hmac = event_hmac(
        key,
        prev=prev,
        world=world,
        timestamp=row.timestamp,
        event_type=row.event_type,
        target=row.target,
        generation=generation,
        body_sha256=row.body_sha256,
        size=row.size,
        content_type=row.content_type,
        meta_sha256=row.meta_sha256,
    )
    if not hmac.compare_digest(expected_hmac.encode("utf-8"), row.hmac.encode("utf-8")):
        return prev, VerifyBreak(idx, hmac_label(expected_hmac), hmac_label(row.hmac))

    return row.hmac, None


def verify_delete_subject_proof(
    row: EventRow,
    headers: list[tuple[str, str]],
    idx: int,
) -> VerifyBreak | None:
    has_any = any(
        name.lower().startswith(DELETE_SUBJECT_PREFIX) for name, _ in headers
    )
    if not has_any and is_memory_world(row.target):
        return None
    if not is_lower_hex(row.body_sha256, 64):
        return VerifyBreak(
            idx,
            "delete-row-body-sha256",
            "invalid-delete-row-body-sha256",
        )

    values: dict[str, str] = {}
    for name in DELETE_SUBJECT_HEADERS:
        matches = [value for header_name, value in headers if header_name == name]
        if not matches:
            return VerifyBreak(
                idx,
                f"delete-subject-{name}",
                f"missing-delete-subject-{name}",
            )
        if len(matches) > 1:
            return VerifyBreak(
                idx,
                f"one-delete-subject-{name}",
                f"duplicated-delete-subject-{name}",
            )
        values[name] = matches[0]

    if not is_canonical_world(values[DELETE_SUBJECT_WORLD]):
        return VerifyBreak(
            idx,
            f"valid-delete-subject-{DELETE_SUBJECT_WORLD}",
            f"invalid-delete-subject-{DELETE_SUBJECT_WORLD}",
        )
    if values[DELETE_SUBJECT_WORLD] != row.target:
        return VerifyBreak(
            idx,
            "delete-subject-world-matches-target",
            "delete-subject-world-mismatch",
        )
    if not is_lower_hex(values[DELETE_SUBJECT_GENERATION], 32):
        return VerifyBreak(
            idx,
            f"valid-delete-subject-{DELETE_SUBJECT_GENERATION}",
            f"invalid-delete-subject-{DELETE_SUBJECT_GENERATION}",
        )
    try:
        seq = int(values[DELETE_SUBJECT_SEQ], 10)
    except ValueError:
        seq = 0
    if str(seq) != values[DELETE_SUBJECT_SEQ] or seq <= 0:
        return VerifyBreak(
            idx,
            f"valid-delete-subject-{DELETE_SUBJECT_SEQ}",
            f"invalid-delete-subject-{DELETE_SUBJECT_SEQ}",
        )
    if not is_lower_hex(values[DELETE_SUBJECT_BODY_SHA256], 64):
        return VerifyBreak(
            idx,
            f"valid-delete-subject-{DELETE_SUBJECT_BODY_SHA256}",
            f"invalid-delete-subject-{DELETE_SUBJECT_BODY_SHA256}",
        )
    if not hmac.compare_digest(
        values[DELETE_SUBJECT_BODY_SHA256].encode("utf-8"),
        row.body_sha256.encode("utf-8"),
    ):
        return VerifyBreak(
            idx,
            "delete-subject-body-sha256-matches-row",
            "delete-subject-body-sha256-mismatch",
        )
    if not is_hmac_label(values[DELETE_SUBJECT_HMAC]):
        return VerifyBreak(
            idx,
            f"valid-delete-subject-{DELETE_SUBJECT_HMAC}",
            f"invalid-delete-subject-{DELETE_SUBJECT_HMAC}",
        )
    return None


def is_hmac_label(value: str) -> bool:
    return value.startswith("hmac-") and is_lower_hex(value.removeprefix("hmac-"), 64)


def row_from_sql(row: sqlite3.Row) -> tuple[EventRow, tuple[str, str] | None]:
    event = EventRow(
        id=int(row[0]),
        timestamp=require_str(row[1], "timestamp"),
        event_type=require_str(row[2], "event_type"),
        target=require_str(row[3], "target"),
        body_sha256=require_str(row[4], "body_sha256"),
        size=require_int(row[5], "size"),
        content_type=require_str(row[6], "content_type"),
        meta_sha256=require_str(row[7], "meta_sha256"),
        hmac=require_str(row[8], "hmac"),
        prev_hmac=require_str(row[9], "prev_hmac"),
    )
    name = row[10]
    value = row[11]
    if name is None or value is None:
        return event, None
    return event, (require_str(name, "event_headers.name"), require_str(value, "event_headers.value"))


def verify_connection(
    conn: sqlite3.Connection, key: bytes, *, world: str, allow_empty: bool = False
) -> VerifyOk | VerifyBreak:
    require_world_format(conn)
    generation = load_generation(conn)
    prev = ""
    genesis = ""
    events = 0
    current: EventRow | None = None
    headers: list[tuple[str, str]] = []

    for sql_row in conn.execute(AUDIT_SELECT):
        row, header = row_from_sql(sql_row)
        if current is not None and current.id != row.id:
            prev, broken = verify_event(current, headers, key, world, generation, prev, events)
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
        prev, broken = verify_event(current, headers, key, world, generation, prev, events)
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
            report = verify_connection(conn, key, world=world, allow_empty=allow_empty)
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
            generation TEXT NOT NULL,
            body BLOB DEFAULT x'',
            content_type TEXT DEFAULT 'application/octet-stream'
        );
        INSERT OR IGNORE INTO stage_meta(id, generation, body)
            VALUES(1, '0123456789abcdef0123456789abcdef', x'');
        CREATE TABLE world_format(
            id INTEGER PRIMARY KEY CHECK(id=1),
            version INTEGER NOT NULL
                CHECK(typeof(version)='integer')
                CHECK(version=2)
        );
        INSERT INTO world_format(id, version) VALUES(1, 2);
        CREATE TABLE cas_bodies(
            body_sha256 TEXT NOT NULL PRIMARY KEY
                CHECK(typeof(body_sha256)='text')
                CHECK(length(body_sha256)=64)
                CHECK(body_sha256 NOT GLOB '*[^0-9a-f]*'),
            body BLOB NOT NULL
                CHECK(typeof(body)='blob')
        ) WITHOUT ROWID;
        CREATE TABLE cas_state(
            id INTEGER PRIMARY KEY CHECK(id=1),
            first_retained_seq INTEGER
                CHECK(
                    first_retained_seq IS NULL OR
                    (typeof(first_retained_seq)='integer' AND first_retained_seq > 0)
                )
        );
        INSERT INTO cas_state(id, first_retained_seq) VALUES(1, NULL);
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
            content_type TEXT DEFAULT '',
            meta_sha256 TEXT DEFAULT '',
            hmac TEXT NOT NULL,
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
    world: str,
    event_type: str,
    target: str,
    body_sha256: str,
    size: int,
    content_type: str,
    headers: list[tuple[str, str]],
    timestamp: str = "2026-01-02T03:04:05.678Z",
) -> str:
    canonical = sorted((name.lower(), value) for name, value in headers)
    meta = meta_sha256_canonical(content_type, canonical)
    generation = load_generation(conn)
    require_timestamp(timestamp)
    digest = event_hmac(
        key,
        prev=prev,
        world=world,
        timestamp=timestamp,
        event_type=event_type,
        target=target,
        generation=generation,
        body_sha256=body_sha256,
        size=size,
        content_type=content_type,
        meta_sha256=meta,
    )
    conn.execute(
        """
        INSERT INTO events(timestamp, event_type, target, body_sha256, size,
                           content_type, meta_sha256, hmac, prev_hmac)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            event_type,
            target,
            body_sha256,
            size,
            content_type,
            meta,
            digest,
            prev,
        ),
    )
    event_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    for name, value in canonical:
        conn.execute(
            "INSERT INTO event_headers(event_id, name, value) VALUES(?, ?, ?)",
            (event_id, name, value),
        )
    return digest


def delete_subject_headers(target: str, body_sha256: str) -> list[tuple[str, str]]:
    return [
        (DELETE_SUBJECT_WORLD, target),
        (DELETE_SUBJECT_GENERATION, "0123456789abcdef0123456789abcdef"),
        (DELETE_SUBJECT_SEQ, "1"),
        (DELETE_SUBJECT_BODY_SHA256, body_sha256),
        (DELETE_SUBJECT_HMAC, f"hmac-{'a' * 64}"),
    ]


def self_test() -> int:
    for world in [
        "home/a",
        "tmp/a",
        "dev/a",
        "sys/a",
        "etc/a",
        "lib/a",
        "boot/a",
        "usr/a",
        "var/a",
    ]:
        assert is_canonical_world(world)
    for world in [
        "",
        "/home/a",
        "home",
        "var/log",
        "proc",
        "proc/version",
        "home//a",
        "home/.",
        "home/..",
        "home/%2e",
        "home/%2E%2E/a",
        "home/a\\b",
        "home/a\0b",
        "foo/a",
        f"home/{'a' * 195}",
        f"home/{'a/' * 70}",
    ]:
        assert not is_canonical_world(world), world

    meta = meta_sha256_canonical("text/plain", [])
    vector_a = event_hmac(
        b"key",
        prev="",
        world="home/a",
        timestamp="2026-01-02T03:04:05.678Z",
        event_type="replace/home/",
        target="x",
        generation="0123456789abcdef0123456789abcdef",
        body_sha256="abc",
        size=3,
        content_type="text/plain",
        meta_sha256=meta,
    )
    vector_b = event_hmac(
        b"key",
        prev="",
        world="home/a",
        timestamp="2026-01-02T03:04:05.678Z",
        event_type="replace",
        target="/home/x",
        generation="0123456789abcdef0123456789abcdef",
        body_sha256="abc",
        size=3,
        content_type="text/plain",
        meta_sha256=meta,
    )
    assert vector_a == DOMAIN_VECTOR_A
    assert vector_b == DOMAIN_VECTOR_B
    assert vector_a != vector_b

    with tempfile.TemporaryDirectory(prefix="auditedb-audit-verify-") as tmp:
        root = Path(tmp)
        db = world_db(root, "home/a")
        db.parent.mkdir(parents=True)
        conn = sqlite3.connect(db)
        try:
            create_schema(conn)
            h0 = insert_event(
                conn,
                b"key",
                prev="",
                world="home/a",
                event_type="format",
                target="home/a",
                body_sha256=hashlib.sha256(b"").hexdigest(),
                size=0,
                content_type="",
                headers=[(WORLD_FORMAT_VERSION_HEADER, str(CURRENT_WORLD_FORMAT_VERSION))],
                timestamp="2026-01-02T03:04:05.000Z",
            )
            h1 = insert_event(
                conn,
                b"key",
                prev=h0,
                world="home/a",
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
                world="home/a",
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
        assert results[0].events == 3

        timestamp_db = world_db(root, "home/timestamp-tamper")
        timestamp_db.parent.mkdir(parents=True)
        conn = sqlite3.connect(timestamp_db)
        try:
            create_schema(conn)
            h0 = insert_event(
                conn,
                b"key",
                prev="",
                world="home/timestamp-tamper",
                event_type="format",
                target="home/timestamp-tamper",
                body_sha256=hashlib.sha256(b"").hexdigest(),
                size=0,
                content_type="",
                headers=[(WORLD_FORMAT_VERSION_HEADER, str(CURRENT_WORLD_FORMAT_VERSION))],
                timestamp="2026-01-02T03:04:05.000Z",
            )
            insert_event(
                conn,
                b"key",
                prev=h0,
                world="home/timestamp-tamper",
                event_type="put",
                target="home/timestamp-tamper",
                body_sha256="abc",
                size=3,
                content_type="text/plain",
                headers=[],
                timestamp="2026-01-02T03:04:05.678Z",
            )
            conn.execute(
                "UPDATE events SET timestamp='2026-01-02T03:04:05.679Z' WHERE id=2"
            )
            conn.commit()
        finally:
            conn.close()
        timestamp_result = verify_data_root(
            root, b"key", worlds=["home/timestamp-tamper"], allow_empty=False
        )
        assert timestamp_result[0].status == "broken"
        assert timestamp_result[0].break_at == 1
        assert (timestamp_result[0].expected or "").startswith("hmac-")

        bad_timestamp_db = world_db(root, "home/bad-timestamp")
        bad_timestamp_db.parent.mkdir(parents=True)
        conn = sqlite3.connect(bad_timestamp_db)
        try:
            create_schema(conn)
            insert_event(
                conn,
                b"key",
                prev="",
                world="home/bad-timestamp",
                event_type="format",
                target="home/bad-timestamp",
                body_sha256=hashlib.sha256(b"").hexdigest(),
                size=0,
                content_type="",
                headers=[(WORLD_FORMAT_VERSION_HEADER, str(CURRENT_WORLD_FORMAT_VERSION))],
                timestamp="2026-01-02T03:04:05.000Z",
            )
            conn.execute("UPDATE events SET timestamp='not-time' WHERE id=1")
            conn.commit()
        finally:
            conn.close()
        bad_timestamp_result = verify_data_root(
            root, b"key", worlds=["home/bad-timestamp"], allow_empty=False
        )
        assert bad_timestamp_result[0].status == "broken"
        assert bad_timestamp_result[0].expected == "timestamp-sqlite-utc-ms"

        ledger_db = world_db(root, "var/log/deletes")
        ledger_db.parent.mkdir(parents=True)
        conn = sqlite3.connect(ledger_db)
        try:
            create_schema(conn)
            deleted_body_sha256 = hashlib.sha256(b"body").hexdigest()
            insert_event(
                conn,
                b"key",
                prev="",
                world="var/log/deletes",
                event_type="delete_intent",
                target="home/a",
                body_sha256=deleted_body_sha256,
                size=0,
                content_type="text/plain",
                headers=delete_subject_headers("home/a", deleted_body_sha256),
            )
            conn.commit()
        finally:
            conn.close()
        moved_ledger = verify_world_db("var/log/other", ledger_db, b"key", allow_empty=False)
        assert moved_ledger.status == "broken"
        assert (moved_ledger.expected or "").startswith("hmac-")

        missing_delete_gen_db = world_db(root, "var/log/missing-delete-gen")
        missing_delete_gen_db.parent.mkdir(parents=True)
        conn = sqlite3.connect(missing_delete_gen_db)
        try:
            create_schema(conn)
            insert_event(
                conn,
                b"key",
                prev="",
                world="var/log/missing-delete-gen",
                event_type="delete_intent",
                target="home/a",
                body_sha256=hashlib.sha256(b"body").hexdigest(),
                size=0,
                content_type="text/plain",
                headers=[],
            )
            conn.commit()
        finally:
            conn.close()
        missing_delete_gen = verify_world_db(
            "var/log/missing-delete-gen",
            missing_delete_gen_db,
            b"key",
            allow_empty=False,
        )
        assert missing_delete_gen.status == "broken"
        assert missing_delete_gen.expected == f"delete-subject-{DELETE_SUBJECT_WORLD}"

        mixed_case_delete_subject_db = world_db(root, "var/log/mixed-case-delete-subject")
        mixed_case_delete_subject_db.parent.mkdir(parents=True)
        conn = sqlite3.connect(mixed_case_delete_subject_db)
        try:
            create_schema(conn)
            insert_event(
                conn,
                b"key",
                prev="",
                world="var/log/mixed-case-delete-subject",
                event_type="delete_intent",
                target="home/a",
                body_sha256=hashlib.sha256(b"body").hexdigest(),
                size=0,
                content_type="text/plain",
                headers=[("AuditeDB-Delete-Subject-Generation", "01")],
            )
            conn.commit()
        finally:
            conn.close()
        mixed_case_delete_subject = verify_world_db(
            "var/log/mixed-case-delete-subject",
            mixed_case_delete_subject_db,
            b"key",
            allow_empty=False,
        )
        assert mixed_case_delete_subject.status == "broken"
        assert mixed_case_delete_subject.expected == f"delete-subject-{DELETE_SUBJECT_WORLD}"

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
            create_schema(conn)
            conn.executescript(
                """
                DROP TABLE events;
                DROP TABLE event_headers;
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
                world="home/text-size",
                timestamp="2026-01-02T03:04:05.678Z",
                event_type="put",
                target="home/text-size",
                generation=load_generation(conn),
                body_sha256="abc",
                size=3,
                content_type="text/plain",
                meta_sha256=meta,
            )
            conn.execute(
                """
                INSERT INTO events(timestamp, event_type, target, body_sha256,
                                   size, content_type, meta_sha256, hmac, prev_hmac)
                VALUES('2026-01-02T03:04:05.678Z', 'put', 'home/text-size', 'abc',
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
            create_schema(conn)
            conn.executescript(
                """
                DROP TABLE event_headers;
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
                world="home/half-null",
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
                world="home/a",
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
        try:
            verify_data_root(root, b"key", worlds=None, allow_empty=False)
            raise AssertionError("non-canonical disk world must fail full scan")
        except AuditVerifyError as exc:
            assert "non-canonical disk name" in str(exc), exc

    print("audit chain verifier self-test ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_root", nargs="?", help="AuditeDB data root to verify")
    parser.add_argument("--world", action="append", help="Canonical world path to verify")
    parser.add_argument("--key", help="Audit HMAC key as UTF-8 text")
    parser.add_argument("--key-file", help="File containing audit HMAC key bytes")
    parser.add_argument("--key-env", default="AUDITEDB_KEY", help="Environment variable for key")
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
    try:
        results = verify_data_root(
            Path(args.data_root),
            key,
            worlds=args.world,
            allow_empty=args.allow_empty,
        )
    except AuditVerifyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
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
