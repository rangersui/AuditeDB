# AuditeDB

**the db that listens.**

AuditeDB is a flat key-value store that borrows the Unix filesystem
hierarchy as its namespace. `home/` is user data, `etc/` is config,
`tmp/` is scratch — not by analogy, by design. You `put` and `get`
bytes at paths the same way you'd `fopen` a file, but durable writes
are HMAC-audited, durable paths keep timeline history, and paths can be
subscribed to for live change events.

Each durable path maps to a percent-encoded directory with one SQLite
file inside. No cluster, no migration, `cp -r` is your backup.

## Why

You're already using SQLite to store things. But:

- **Who changed it?** You don't know — there's no audit trail.
- **Did it change?** You have to poll to find out.
- **What was it before?** Gone — you overwrote it.

AuditeDB gives your local storage an audit chain, change subscriptions,
and timeline history. No infrastructure to add — plain files on disk,
`cp -r` is backup. Same operational model, but it remembers.

## Two ways to use it

**Embed the engine:** add the `l5` crate (Rust) or `l5` package
(Python) and call five verbs directly. No network, no server.

**Run the server:** start the `auditedb` binary and use `curl`.
CoAP is included by default; MQTT is available with the `mqtt` feature.

## Quick start — Python

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

## Quick start — Rust

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

## Quick start — curl

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
`replace`, `append`, and `delete` must be awaited. `subscribe` opens a
synchronous handle; receiving from that handle is async.

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

`Anon` → `Read` → `Write` → `Approve`

Configure tokens via `AUDITEDB_READ_TOKEN`, `AUDITEDB_WRITE_TOKEN`,
`AUDITEDB_APPROVE_TOKEN`. Pass them as `Authorization: Bearer <token>`.

## Audit chain

Every durable write signs the previous HMAC, world path, timestamp, body
hash, and metadata hash into a new event. The chain is verifiable:

```bash
curl http://localhost:3105/proc/audit/home/hello/verify
```

```python
db.verify("home/hello")  # True
```

The HMAC key (`AUDITEDB_KEY`) stays in memory and never touches disk.

## Subscriptions

```python
with db.subscribe("home/*") as sub:
    for event in sub:
        if event["kind"] == "event":
            print(event["verb"], event["path"])
```

```bash
curl -N http://localhost:3105/listen/home/*
```

Exact-world subscriptions can replay from a durable cursor. Wildcard
subscriptions stream from the in-memory ring.

## Project layout

```
core/   l5 engine library (Rust)     — paths, bytes, ETags, audit, auth
bin/    auditedb server binary       — HTTP + CoAP adapters (+MQTT opt-in)
ffi/    UniFFI bridge                — currently packaged for Python
sdk/    l5 Python package            — in-process Engine handle over FFI
```

## Schema reference

See [docs/schema.html](docs/schema.html) for the storage schema, HMAC
framing, and wire format.

## License

MIT
