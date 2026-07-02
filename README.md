# AuditeDB

**the db that listens.**

Audit the past. Subscribe to the future.

A filesystem-backed flat key-value store with an audit trail. Embed the `l5` engine as a library, or run the `auditedb` HTTP server as a HTTP disk.

Powered by the L5 Engine.

```text
GET /home/a     read bytes
PUT /home/a     replace bytes
POST /home/a    append bytes
DELETE /home/a  remove bytes
LISTEN /home/*  subscribe to changes
```

5 verbs · HMAC audit chain · SQLite inside.

```
┌─ l5 (L5 Engine, core/) ────────────────────┐
│ paths + bytes + ETags + HMAC chain + auth  │
│ no HTTP, no sockets, no env vars           │
└─────────────────────┬──────────────────────┘
                      │ pub Engine API
┌─ auditedb (AuditeDB server, bin/) ─────────┐
│ HTTP + CoAP + MQTT + SSE adapters          │
│ config, routing, auth parsing, /proc/*     │
└────────────────────────────────────────────┘
```

---

## Documentation map

See the [wiki](https://github.com/rangersui/AuditeDB/wiki) for design documentation: storage model, audit chain, namespace system, auth tiers, and operational guides.

This README is the Engine/library reference: storage model, trust tiers, audit chain, namespaces, and the Rust `Engine` API. Protocol adapters have their own README files so wire-specific behaviour does not get mistaken for Engine physics.

| Surface | README | Scope |
|---------|--------|-------|
| Engine library | this file | Protocol-neutral paths, bytes, ETags, audit, auth, subscriptions. |
| HTTP binary adapter | [`bin/src/server/http/README.md`](bin/src/server/http/README.md) | `auditedb` startup, HTTP worlds, `/proc/*`, `/listen/*`, curl. |
| MQTT binary adapter | [`bin/src/server/mqtt/README.md`](bin/src/server/mqtt/README.md) | MQTT 3.1.1 scope, retain tier mapping, QoS, and limits. |
| CoAP binary adapter | [`bin/src/server/coap/README.md`](bin/src/server/coap/README.md) | CoAP UDP mapping and deployment knobs. |
| FFI adapter | [`ffi/README.md`](ffi/README.md) | UniFFI binding: Python, Kotlin, Swift. Blocking pull, same Engine verbs. |
| Python SDK | [`sdk/src/l5`](sdk/src/l5) | In-process Python handle over the L5 FFI binding. |

Library embedders call typed Engine methods instead of HTTP `/proc/*` paths or
timeline query URLs:

| Engine method | Return shape |
|---------------|--------------|
| `Engine::list_worlds` | `Vec<ValidatedWorldPath>` |
| `Engine::du` | `Vec<WorldUsage>` |
| `Engine::df` | `DfSnapshot` |
| `Engine::pool` | `PoolSnapshot` |
| `Engine::verify_audit` | `AuditVerify` |
| `Engine::chain_head` | `Option<HeadStamp>` |
| `Engine::chain_stamp` | `ChainStampRead` |
| `Engine::dereference_timeline_coordinate` | `TimelineDereference` |

## Quick start — library

```rust
use l5::{
    AccessTier, AuditHmacKey, Engine, Preconditions, Representation, ValidatedWorldPath,
};
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
        Representation::new(Bytes::from_static(b"hi"), "text/plain", Vec::new()),
        Preconditions::none(),
        AccessTier::Write,
    ).await.unwrap();

    let read = engine.read(&world, AccessTier::Read).unwrap();
    assert!(read.is_some());
}
```

```toml
[dependencies]
l5 = { version = "=8.3.0", default-features = false,
       features = ["bundled-sqlite", "unstable-engine"] }
tokio = { version = "1", features = ["macros", "rt"] }
```

The `unstable-engine` gate explicitly marks the public Engine API unstable.
API shapes may change between minor versions until that gate is removed. Pin an
exact `l5` version when embedding the unstable Engine API.

---

## Five engine verbs

| Verb        | Engine method        | What it does                                         |
|-------------|----------------------|------------------------------------------------------|
| `read`      | `Engine::read`       | Full representation; `None` if missing.              |
| `replace`   | `Engine::replace`    | Overwrite body + headers + content type.             |
| `append`    | `Engine::append`     | Extend body; headers untouched.                      |
| `delete`    | `Engine::delete`     | Unlink the world; audit chain advances.              |
| `subscribe` | `Engine::subscribe`  | Replay-then-live `ChangeEvent` stream.               |

In the Rust API, `read` and introspection calls are synchronous. Mutating operations (`replace`, `append`, `delete`) are async; `subscribe` returns a subscription synchronously, and `EngineSubscription::recv().await` waits for events.

Durable audit rows sign `prev`, `world`, `timestamp`, `type`, `target`, `gen`,
`body-sha256`, `size`, `content-type`, and `meta-sha256` in that order. The
metadata hash (`meta_sha256`) is length-framed separately: `content-type`, each
header name, and each header value are hashed as `label\0len\0value\0` fields.
The same frames are used by the Rust Engine and by `tools/audit_chain_verify.py`.

Subscriptions do not carry body bytes. Durable body writes carry a
`TimelineAddress`; callers that need the exact historical body call
`Engine::dereference_timeline_coordinate` with the timeline coordinate instead
of racing a current `read`. `ChangeEvent::id()` is diagnostic only. Durable
reconnect state lives in `ChangeEvent::identity()` as a `SubscriptionEventId`
rendered by adapters as `<world>@<generation>=<timeline-seq>`. That sequence is
the current timeline row coordinate, not a `ChainSeq` audit-stamp ordinal.

HTTP, CoAP, MQTT, and SSE are adapter mappings over these verbs. The library does not know about those protocols; it knows about the five verbs.

## Four trust tiers

`Anon` ⊂ `Read` ⊂ `Write` ⊂ `Approve`. Every operation declares the minimum
tier it requires; the engine refuses with `EngineError::Auth(...)` below it.

| Tier      | Source                  | Allowed                                                     |
|-----------|-------------------------|-------------------------------------------------------------|
| `Anon`    | caller supplies no credential | public reads, when the configured policy allows them |
| `Read`    | caller proves read tier       | read, list, subscribe, audit verify |
| `Write`   | caller proves write tier      | everything `Read` + ordinary replace/append (`home/`, `tmp/`, `dev/`, `sys/`, non-log `var/`) |
| `Approve` | caller proves approve tier    | everything `Write` + delete + writes in protected namespaces (`etc/`, `lib/`, `boot/`, `usr/`, `var/log/`) |

---

## Storage namespaces

Path prefix decides backend. `ValidatedWorldPath::new` validates once;
downstream operations cannot drift.

| Prefix    | Backend  | Durable | Audited | Default | Notes |
|-----------|----------|---------|---------|---------|-------|
| `home/`   | SQLite   | yes     | yes     | `Write` | application data |
| `etc/`    | SQLite   | yes     | yes     | `Approve` | configuration |
| `lib/`    | SQLite   | yes     | yes     | `Approve` | inert blobs |
| `boot/`   | SQLite   | yes     | yes     | `Approve` | bootstrap state |
| `usr/`    | SQLite   | yes     | yes     | `Approve` | user-scoped data |
| `var/`    | SQLite   | yes     | yes     | `Write` | variable durable state; `var/log/` requires `Approve` and `var/log/deletes` is append-only |
| `tmp/`    | memory   | no      | no      | `Write` | scratch |
| `dev/`    | memory   | no      | no      | `Write` | device-like ephemeral |
| `sys/`    | memory   | no      | no      | `Write` | service-info ephemeral |

Bare names (`foo`) and wire paths (`/foo`) are rejected by the library. The
binary adapters may apply wire-specific canonicalisation before constructing a
validated path. Those adapter rules live in the adapter README files linked
above.

---

## Feature flags

`l5` is the library package. Its feature surface is small:

| Feature                | Default | Pulls in                                                       | Purpose                            |
|------------------------|:-------:|---------------------------------------------------------------|------------------------------------|
| `bundled-sqlite`       |    ✓    | `rusqlite/bundled`                                            | static SQLite link                 |
| `unstable-engine`      |    ✓    | `tracing`                                                      | public `Engine` API                |

Library-only build, no HTTP stack:

```bash
cargo build --manifest-path core/Cargo.toml --lib --no-default-features --features bundled-sqlite,unstable-engine
```

The resulting dependency tree has zero `axum`, `hyper`, `tower`,
`tokio-stream`, `futures-util`, `rumqttd`, or `base64`.

The binary package in [`bin/Cargo.toml`](bin/Cargo.toml) owns adapter/runtime
features:

| Feature           | Default | Pulls in                         | Purpose                       |
|-------------------|:-------:|----------------------------------|-------------------------------|
| `bundled-sqlite`  |    ✓    | `l5/bundled-sqlite`              | static SQLite link            |
| `coap`            |    ✓    | —                                | CoAP adapter                  |
| `multi-thread`    |    ✓    | `tokio/rt-multi-thread`          | multi-thread runtime          |
| `mqtt`            |         | `rumqttd`, Tokio I/O utilities   | MQTT 3.1.1 adapter            |
| `unstable-engine` |    ✓    | —                                | local `cfg` gate for tracing / error arms in binary code |

---

## Architecture — library + binary split

The codebase is two Rust packages:

| Package | Path | Cargo name | Produces |
|---------|------|------------|----------|
| Library | `core/` | `l5` | `libl5.rlib` |
| Binary  | `bin/`  | `auditedb` | `auditedb` executable |

The library is the embedded L5 Engine. The binary package is the AuditeDB
distribution and produces the `auditedb` executable.

- **Library** (`core/src/lib.rs` + `engine*.rs` + storage primitives):
  the protocol-neutral Engine. No HTTP, no CoAP, no MQTT, no SSE, no env vars,
  no sockets. Safe to embed in any Rust context.
- **Binary** (`bin/src/main.rs` + `bin/src/server/...` + adapter-side config,
  routing, response rendering, path canonicalisation): the HTTP + CoAP + MQTT
  server. Owns Authorization parsing, request lifecycle, graceful shutdown.
  Consumes the library through the public `Engine` facade only.

The split is real, not cosmetic:

- `cargo build --manifest-path core/Cargo.toml --lib --no-default-features --features bundled-sqlite,unstable-engine`
  produces an embeddable Engine library whose dep tree contains **zero**
  HTTP-shaped crates (`axum`, `hyper`, `tower`, `rumqttd`, `base64` are all absent).
- `cargo build --manifest-path bin/Cargo.toml` builds the `auditedb`
  binary and all server adapters from the binary package.

---

## The name

AuditeDB comes from `audire`: to listen.

The tagline is literal. AuditeDB listens forward through `subscribe`, so
clients can react to changes instead of polling. It also listens backward
through the HMAC audit chain, so durable writes leave a verifiable history.

AuditeDB is the product. L5 is the engine.

### Why "L5"

CRUD has four operations. AuditeDB has five:

```text
read · replace · append · delete · subscribe
```

The fifth verb is the point. Storage can be observed, not just polled.

The engine stays small: validate the path, prove authority, mutate bytes,
advance the audit chain, notify listeners. Anything that needs to interpret
stored content belongs in a client, worker, or adapter.

---

## License

MIT. See `LICENSE`.
