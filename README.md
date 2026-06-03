# Elastik

**Audi-ted L5 storage engine.**

**SQLite for files.** Store bytes at paths. Version everything. Audit
everything. Authenticate everything. Subscribe to changes.

*SQLite für Dateien. Bytes an Pfaden. Alles auditiert. Änderungen abonniert.*

```
┌─ engine (library) ─────────────────────────┐
│ paths + bytes + ETags + HMAC chain + auth  │
│ no HTTP, no sockets, no env vars           │
└────────────────────────────────────────────┘
```

---

## Documentation map

This README is the Engine/library reference: storage model, trust tiers, audit
chain, namespaces, and the Rust `Engine` API. Protocol adapters have their own
README files so wire-specific behaviour does not get mistaken for Engine
physics.

| Surface | README | Scope |
|---------|--------|-------|
| Engine library | this file | Protocol-neutral paths, bytes, ETags, audit, auth, subscriptions. |
| HTTP binary adapter | [`bin/src/server/http/README.md`](bin/src/server/http/README.md) | `elastik-core` startup, HTTP worlds, `/proc/*`, `/listen/*`, curl. |
| MQTT binary adapter | [`bin/src/server/mqtt/README.md`](bin/src/server/mqtt/README.md) | MQTT 3.1.1 scope, retain tier mapping, QoS, and limits. |
| CoAP binary adapter | [`bin/src/server/coap/README.md`](bin/src/server/coap/README.md) | CoAP UDP mapping and deployment knobs. |
| FFI adapter | [`ffi/README.md`](ffi/README.md) | UniFFI binding: Python, Kotlin, Swift. Blocking pull, same Engine verbs. |
| Python SDK | [`sdk/README.md`](sdk/README.md) | Python client surface. |
| JavaScript SDK | [`sdk-js/README.md`](sdk-js/README.md) | JS client surface. |

Library embedders call typed Engine methods instead of HTTP `/proc/*` paths:

| Engine method | Return shape |
|---------------|--------------|
| `Engine::list_worlds` | `Vec<ValidatedWorldPath>` |
| `Engine::du` | `Vec<WorldUsage>` |
| `Engine::df` | `DfSnapshot` |
| `Engine::pool` | `PoolSnapshot` |
| `Engine::verify_audit` | `AuditVerify` |

There is no Engine `/proc/version` method; version banners are binary-adapter
surface, while the library version comes from the Rust crate metadata.

## Quick start — library

```rust
use elastik_core::{
    AccessTier, Engine, Preconditions, Representation, SecretBytes, ValidatedWorldPath,
};
use bytes::Bytes;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let engine = Engine::builder()
        .data_root("./data")
        .key(SecretBytes::new(b"shared-secret".to_vec()).unwrap())
        .build()
        .unwrap();

    let world = ValidatedWorldPath::new("home/hello").unwrap();

    engine.replace(
        &world,
        Representation {
            body: Bytes::from_static(b"hi"),
            content_type: "text/plain".into(),
            headers: Vec::new(),
        },
        Preconditions::none(),
        AccessTier::Write,
    ).await.unwrap();

    let read = engine.read(&world, AccessTier::Read).unwrap();
    assert!(read.is_some());
}
```

```toml
[dependencies]
elastik-core = { version = "8", default-features = false,
                 features = ["bundled-sqlite", "unstable-engine"] }
tokio = { version = "1", features = ["macros", "rt"] }
```

The `unstable-engine` gate explicitly marks the public Engine API unstable.
API shapes may change between minor versions until that gate is removed.

---

## Five engine verbs

| Verb        | Engine method        | What it does                                         |
|-------------|----------------------|------------------------------------------------------|
| `read`      | `Engine::read`       | Full representation; `None` if missing.              |
| `replace`   | `Engine::replace`    | Overwrite body + headers + content type.             |
| `append`    | `Engine::append`     | Extend body; headers untouched.                      |
| `delete`    | `Engine::delete`     | Unlink the world; audit chain advances.              |
| `subscribe` | `Engine::subscribe`  | Replay-then-live `ChangeEvent` stream.               |

In the Rust API, `read` and introspection calls are synchronous. Mutating
operations (`replace`, `append`, `delete`) are async; `subscribe` returns a
subscription synchronously, and `EngineSubscription::recv().await` waits for
events.

HTTP, CoAP, MQTT, and SSE are adapter mappings over these verbs. The library
does not know about those protocols; it knows about the five verbs.

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

`elastik-core` is now the library package only. Its feature surface is small:

| Feature                | Default | Pulls in                                                       | Purpose                            |
|------------------------|:-------:|---------------------------------------------------------------|------------------------------------|
| `bundled-sqlite`       |    ✓    | `rusqlite/bundled`                                            | static SQLite link                 |
| `unstable-engine`      |    ✓    | `tracing`                                                      | public `Engine` API                |

Library-only build, no HTTP stack:

```bash
cargo build --lib --no-default-features --features bundled-sqlite,unstable-engine
```

The resulting dependency tree has zero `axum`, `hyper`, `tower`,
`tokio-stream`, `futures-util`, `rumqttd`, or `base64`.

The binary package in [`bin/Cargo.toml`](bin/Cargo.toml) owns adapter/runtime
features:

| Feature           | Default | Pulls in                         | Purpose                       |
|-------------------|:-------:|----------------------------------|-------------------------------|
| `bundled-sqlite`  |    ✓    | `elastik-core/bundled-sqlite`    | static SQLite link            |
| `coap`            |    ✓    | —                                | CoAP adapter                  |
| `multi-thread`    |    ✓    | `tokio/rt-multi-thread`          | multi-thread runtime          |
| `mqtt`            |         | `rumqttd`, Tokio I/O utilities   | MQTT 3.1.1 adapter            |
| `unstable-engine` |    ✓    | `elastik-core/unstable-engine`   | Engine facade used by adapters |

---

## Architecture — library + binary split

The codebase is split into two Rust packages:

- **Library package** (`core/src/lib.rs` + `engine*.rs` + storage primitives):
  the
  protocol-neutral Engine. No HTTP, no CoAP, no MQTT, no SSE, no env vars, no sockets.
  Safe to embed in any Rust context.
- **Binary package** (`bin/src/main.rs` + `bin/src/server/...` + adapter-side `config`,
  `http_range`, `http_semantics`, `path`): the HTTP + CoAP + MQTT server. Owns
  Authorization parsing, request lifecycle, response rendering, graceful
  shutdown. Consumes the library through the public `Engine` facade only.

The split is real, not cosmetic:

- `cargo build --lib --no-default-features --features bundled-sqlite,unstable-engine`
  produces an embeddable Engine library whose dep tree contains **zero**
  HTTP-shaped crates.
- `cargo build --manifest-path bin/Cargo.toml` builds the `elastik-core`
  binary and all server adapters from the binary package.

---

## Why "L5"

Five overloaded reasons. All true.

1. **Audi inline-5 heritage.** Asymmetric, distinctive, lean. One cylinder
   head instead of two. V6 → L5 means: no more HTTP-coupled head on the
   library side.
2. **Level 5 autonomous.** Codebase is AI-co-authored end to end; every PR
   is adversarially reviewed before it lands.
3. **Five engine verbs.** read · replace · append · delete · **subscribe**.
4. **Linear architecture.** Straight pipe: validate → permit → transition →
   audit → notify. Durable writes append the HMAC audit record in the write
   transaction before subscribers hear about the change.
5. **Five layers of trust.** Anon → Read → Write → Approve → Engine itself.

### The fifth cylinder is the brand

CRUD has four operations. Elastik has **five**. The cylinder that turns an
inline-4 into an inline-5 is `subscribe`.

```
audire   (Latin: "to listen")
  ├─ Audi          (German car brand — Latin translation of founder Horch's
  │                 surname, which means "listen!" in German)
  ├─ audit         (English: formal review — originally "to listen to
  │                 accounts being read aloud")
  └─ subscribe     (Elastik L5's fifth verb — the listening verb)

           audire
             │
   ┌─────────┼──────────┐
   │         │          │
 Audi      audit    subscribe
   │         │          │
  L5    audited       fifth cylinder
   │   (= the         (= the listening
   │     feature)      verb)
   └─────────┼──────────┘
             ▼
       Elastik L5
```

The audit chain — the HMAC ledger that records every write — is the engine
*listening to* every change. The fifth cylinder *is* the listening verb. The
tagline *is* the listening etymology. **Vorsprung durch Technik** — technical
edge through listening. Three independent puns, one root word.

> **The tagline is literal.** *Audi-ted* is `audit` written so the
> Latin-via-German brand stays visible. **Audi**-ted L5: the storage engine
> whose fifth cylinder listens.

---

## License

MIT. See `LICENSE`.
