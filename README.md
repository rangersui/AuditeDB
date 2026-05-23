# Elastik

**Audi-ted L5 storage engine.**

**SQLite for files.** Store bytes at paths. Version everything. Audit
everything. Authenticate everything. Subscribe to changes.

```
┌─ engine (library) ─────────────────────────┐    ┌─ adapter (binary) ──────┐
│ paths + bytes + ETags + HMAC chain + auth  │ ←─ │ HTTP / CoAP / SSE /     │
│ no HTTP, no sockets, no env vars           │    │ env vars / signal pipe  │
└────────────────────────────────────────────┘    └─────────────────────────┘
```

---

## Quick start — binary

```bash
ELASTIK_KEY=secret cargo run --bin elastik-core
# elastik-core v8.0.0 on http://127.0.0.1:3105/

curl -X PUT  -d 'hi' http://127.0.0.1:3105/home/hello
curl                  http://127.0.0.1:3105/home/hello       # -> hi
curl                  http://127.0.0.1:3105/proc/worlds      # -> home/hello
curl -N               http://127.0.0.1:3105/listen/home/*    # SSE stream
```

The binary refuses to build without `unstable-engine-bin` (cargo will say so).
The library does not need that feature.

## Quick start — library

```rust
use elastik_core::{
    AccessTier, Engine, Preconditions, Representation, SecretBytes, ValidatedWorldPath,
};
use bytes::Bytes;

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
```

```toml
[dependencies]
elastik-core = { version = "8", default-features = false,
                 features = ["bundled-sqlite", "unstable-engine"] }
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

The binary's HTTP surface (`GET / HEAD / PUT / POST / DELETE / GET /listen/*`)
and the CoAP surface are two possible mappings. The library does not know
about either; it knows about the five verbs.

## Four trust tiers

`Anon` ⊂ `Read` ⊂ `Write` ⊂ `Approve`. Every operation declares the minimum
tier it requires; the engine refuses with `EngineError::Auth(...)` below it.

| Tier      | Source                  | Allowed                                                     |
|-----------|-------------------------|-------------------------------------------------------------|
| `Anon`    | no token                | public reads, when no read token is configured              |
| `Read`    | `ELASTIK_READ_TOKEN`    | read, list, subscribe, audit verify                         |
| `Write`   | `ELASTIK_WRITE_TOKEN`   | everything `Read` + replace/append in `home/`               |
| `Approve` | `ELASTIK_APPROVE_TOKEN` | everything `Write` + delete + writes in system namespaces   |

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
| `var/`    | SQLite   | yes     | yes     | `Approve` | system logs (`var/log/deletes` is append-only) |
| `tmp/`    | memory   | no      | no      | `Write` | scratch |
| `dev/`    | memory   | no      | no      | `Write` | device-like ephemeral |
| `sys/`    | memory   | no      | no      | `Write` | service-info ephemeral |

Bare names (`foo`) and wire paths (`/foo`) are rejected by the library. The
binary's adapter-side canonicalisation maps HTTP `/foo` to `home/foo` before
constructing the validated path.

---

## Feature flags

| Feature                | Default | Pulls in                                                       | Purpose                            |
|------------------------|:-------:|---------------------------------------------------------------|------------------------------------|
| `bundled-sqlite`       |    ✓    | `rusqlite/bundled`                                            | static SQLite link                 |
| `coap`                 |    ✓    | —                                                              | binary's CoAP adapter              |
| `multi-thread`         |    ✓    | `tokio/rt-multi-thread`                                       | binary's multi-thread runtime      |
| `unstable-engine`      |         | `tracing`                                                      | public `Engine` API                |
| `unstable-engine-bin`  |    ✓    | `axum`, `base64`, `futures-util`, `tokio/net`, `tokio/signal`, `tracing-subscriber` | required by the `elastik-core` bin |

Library-only build, no HTTP stack:

```bash
cargo build --lib --no-default-features --features bundled-sqlite,unstable-engine
```

The resulting dependency tree has zero `axum`, `hyper`, `tower`,
`tokio-stream`, `futures-util`, or `base64`.

---

## Architecture — library + binary split

PR 5 + PR 6 split the codebase into two crate targets sharing one Cargo
package:

- **Library** (`src/lib.rs` + `engine*.rs` + storage primitives): the
  protocol-neutral Engine. No HTTP, no CoAP, no SSE, no env vars, no sockets.
  Safe to embed in any Rust context.
- **Binary** (`src/main.rs` + `src/server/...` + adapter-side `config`,
  `http_range`, `http_semantics`, `path`): the HTTP + CoAP server. Owns
  Authorization parsing, request lifecycle, response rendering, graceful
  shutdown. Consumes the library through the public `Engine` facade only.

The split is real, not cosmetic:

- `cargo build --lib --no-default-features --features bundled-sqlite` produces
  a library whose dep tree contains **zero** HTTP-shaped crates.
- `[[bin]] required-features = ["unstable-engine-bin"]` makes `cargo` refuse
  to produce a binary without the HTTP stack — the requirement is explicit.

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
   notify. No branching complexity in the call graph.
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
