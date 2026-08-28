# AuditeDB

**the db that listens.**

AuditeDB is a flat key-value store that borrows the Unix filesystem
hierarchy as its namespace. `home/` is user data, `etc/` is config,
`tmp/` is scratch. The API is `put` and `get` of bytes at paths;
durable writes are HMAC-audited, durable paths keep verifiable timeline
history, and paths can be subscribed to for live change events.

Each durable path maps to a percent-encoded directory with one SQLite
file inside. No cluster, no migration, `cp -r` is the backup.

## Why

SQLite alone stores current state. AuditeDB adds three things on top of
plain files on disk: an audit chain (who changed what, when), change
subscriptions (no polling), and timeline history (every previous body
is addressable). `cp -r` is still the backup.

## Two ways to use it

**Embed the engine:** add the `l5` crate (Rust) or `l5` package
(Python) and call five verbs directly. No network, no server.

**Run the server:** start the `auditedb` binary and use `curl`.

## Quick start -- Python

```python
import l5, secrets

with l5.open("./data", key=secrets.token_bytes(32)) as db:
    db.put("home/hello", b"world")
    print(db.get_text("home/hello"))   # "world"
    print("home/hello" in db)          # True
    print(db.list_worlds())            # ["home/hello"]
```

```
pip install l5
```

## Quick start -- Rust

```rust
use l5::{AccessTier, AuditHmacKey, Engine, Preconditions, Representation, ValidatedWorldPath};
use bytes::Bytes;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let engine = Engine::builder()
        .data_root("./data")
        .key(AuditHmacKey::new(b"0123456789abcdef0123456789abcdef".to_vec()).unwrap())
        .build()
        .unwrap();

    let world = ValidatedWorldPath::new("home/hello").unwrap();

    engine.replace(
        &world,
        Representation::new(Bytes::from_static(b"world"), "text/plain", Vec::new()),
        Preconditions::none(),
        AccessTier::Write,
    ).await.unwrap();

    let read = engine.read(&world, AccessTier::Read).await.unwrap();
    assert!(read.is_some());
}
```

```toml
[dependencies]
l5 = { version = "=8.3.0", features = ["bundled-sqlite", "unstable-engine"] }
tokio = { version = "1", features = ["macros", "rt"] }
```

## Quick start -- curl

```bash
export AUDITEDB_KEY=$(openssl rand -hex 32)
export AUDITEDB_WRITE_TOKEN=my-write-token
auditedb &

curl -X PUT -H "Authorization: Bearer my-write-token" \
     -d 'world' http://localhost:3105/home/hello

curl http://localhost:3105/home/hello
# world
```

## Five verbs

| Verb          | What it does                            |
| ------------- | --------------------------------------- |
| `read`      | Return the stored bytes, or nothing.    |
| `replace`   | Overwrite the body.                     |
| `append`    | Extend the body.                        |
| `delete`    | Remove the world; durable deletes advance audit. |
| `subscribe` | Stream change events.                   |

In Rust, storage verbs that touch durable state are async: `read`,
`replace`, `append`, `delete`, and `subscribe` must be awaited. A subscription
then yields events asynchronously.

In Python, the SDK surface is synchronous. The FFI boundary owns the Tokio
runtime and blocks on async Engine verbs internally.

## Namespaces

The path prefix determines storage backend and default auth tier.

| Prefix    | Storage | Audited | Default tier |
| --------- | ------- | ------- | -------- |
| `home/` | SQLite  | yes     | Write    |
| `etc/`  | SQLite  | yes     | Approve  |
| `lib/`  | SQLite  | yes     | Approve  |
| `boot/` | SQLite  | yes     | Approve  |
| `usr/`  | SQLite  | yes     | Approve  |
| `var/`  | SQLite  | yes     | Write    |
| `tmp/`  | memory  | no      | Write    |
| `dev/`  | memory  | no      | Write    |
| `sys/`  | memory  | no      | Write    |

Transient namespaces (`tmp/`, `dev/`, `sys/`) are not audited and do not
survive restart.

## Auth tiers

Four tiers, each a superset of the previous:

`Anon` -> `Read` -> `Write` -> `Approve`

Configure tokens via `AUDITEDB_READ_TOKEN`, `AUDITEDB_WRITE_TOKEN`,
`AUDITEDB_APPROVE_TOKEN`. Pass them as `Authorization: Bearer <token>`.

## Audit chain

Every durable write appends to an HMAC chain -- each event signs the
previous HMAC, world path, timestamp, body hash, and metadata hash into
a new HMAC. The chain is append-only and tamper-evident: modifying an
event breaks that event's HMAC and, if later rows exist, the subsequent
HMAC links.

```
event1.hmac = HMAC-SHA256(key, path + timestamp + body_hash + ...)
event2.hmac = HMAC-SHA256(key, event1.hmac + path + timestamp + body_hash + ...)
event3.hmac = HMAC-SHA256(key, event2.hmac + path + timestamp + body_hash + ...)
```

Verify the chain at any time:

```bash
curl http://localhost:3105/proc/audit/home/hello/verify
```

```python
db.verify("home/hello")  # True
```

The HMAC key (`AUDITEDB_KEY`) stays in memory and never touches disk.
When the in-process key object is dropped, its bytes are wiped on a
best-effort basis.

## Timeline coordinates

Every body-bearing durable write produces a timeline address for that
exact historical body:

| Component      | What it is                                      |
| -------------- | ----------------------------------------------- |
| `world`        | Path that owns the timeline row                  |
| `generation`   | Which "life" of the world (hex, changes on delete+recreate) |
| `seq`          | Position in this generation's event array        |
| `body_sha256`  | Content fingerprint of the body at that point    |

The address is absolute and content-bound. Use it to fetch any retained
past body:

```bash
curl "http://localhost:3105/home/hello?timeline=1\
&timeline-generation=a3f7...56\
&timeline-seq=2\
&timeline-body-sha256=ac1b...4b"
```

If any coordinate is wrong, the read returns a typed rejection -- never
wrong data:

| Condition          | Response         |
| ------------------ | ---------------- |
| Wrong generation   | `409 Conflict`   |
| Wrong body_sha256  | `409 Conflict`   |
| seq out of range   | `404 Not Found`  |
| Body pruned        | `410 Gone`       |

## Compare-and-set (ETags)

Reads, replaces, and appends expose an ETag. Pass it back to do
conditional writes:

```bash
# Read current value and its ETag
ETAG=$(curl -s -D- http://localhost:3105/home/hello | grep ETag)

# Conditional write -- succeeds only if no one else wrote since
curl -X PUT -H "Authorization: Bearer $WRITE" \
     -H "If-Match: $ETAG" \
     -d 'updated' http://localhost:3105/home/hello
# 200 if current, 412 Precondition Failed if stale
```

## Delete protocol

Delete is two-phase with a separate audit ledger (`var/log/deletes`):

1. **Intent** -- `delete_intent` appended to ledger
2. **Drain** -- in-flight readers finish, read cache tombstoned
3. **Physical delete** -- world directory removed from disk
4. **Commit** -- `delete_commit` appended to ledger

If commit fails after physical delete, a `delete_commit_failed` event
is recorded. Failure is audited, never silent. Delete requires `Approve`
tier -- `Write` is not enough.

## Subscriptions

```python
with db.subscribe("home/*") as sub:
    for event in sub:
        if event["kind"] == "event" and "timeline_seq" in event:
            body = db.get_at(event)  # body as it was when this event fired
            print(event["verb"], event["path"], body)
```

```bash
curl -N http://localhost:3105/listen/home/*
```

Body-bearing durable events carry timeline coordinates; `get_at(event)`
reads the exact retained body version that triggered the event, even
after later writes. Exact-world subscriptions can replay from a durable
cursor. Wildcard subscriptions stream from the in-memory ring.

## Fail-loud behavior

AuditeDB refuses to run damaged:

- **Corrupt audit chain at startup** -> engine refuses to build
- **HMAC key shorter than 32 bytes** -> engine refuses to build
- **Invalid path or namespace** -> request rejected before touching storage
- **Write-tier attempts delete** -> rejected (requires Approve)
- **Audit append fails during write** -> transaction fails, gap never committed

## Things to know

- **Reads are public by default.** If `AUDITEDB_READ_TOKEN` is not set,
  anyone can read. Set it explicitly for private instances.
- **`tmp/`, `dev/`, `sys/` are memory-only.** Not audited, lost on
  restart. Everything else is durable.
- **Many server limits treat zero as default, not disabled.**
  `AUDITEDB_MAX_LISTEN_CONNECTIONS=0` reverts to the default (1024), not zero.
- **Percent encoding eats path length.** `home/a/b/c` encodes to
  `home%2Fa%2Fb%2Fc` on disk -- each `/` becomes 3 bytes toward the
  200-byte limit.
- **Process-local event IDs reset on restart.** Durable exact-world SSE
  cursors can replay from the audit timeline; wildcard/ring cursors are
  process-local.
- **One writer per data root.** Enforced by a SQLite lock file. Two
  processes cannot open the same data root.

## Project layout

```
core/   l5 engine library (Rust)     -- paths, bytes, ETags, audit, auth
bin/    auditedb server binary       -- HTTP + SSE adapters
ffi/    UniFFI bridge                -- currently packaged for Python
sdk/    l5 Python package            -- in-process Engine handle over FFI
```

## Schema reference

See [docs/schema.html](docs/schema.html) for the storage schema, HMAC
framing, and wire format.

## License

MIT
