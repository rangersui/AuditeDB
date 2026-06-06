---
name: elastik-architecture
description: >
  Use this skill when making architectural decisions about AuditeDB: whether a
  capability belongs in the Elastik engine library, in the HTTP/CoAP/MQTT
  adapter binary, in a worker, in a client, or in an HTTP world. Trigger when the user
  asks whether AuditeDB should execute code, validate formats, proxy or rewrite
  content, add RPC, become synchronous, add a control-plane endpoint, absorb a
  subsystem that could instead reuse AuditeDB's HTTP key-value/proc/auth/audit/
  listen surfaces, expose new public Engine API on the library side, add HTTP
  semantics to the library, or push storage primitives into the adapter. This
  is the mental-model skill, not the operational cookbook; for commands,
  deployment, curl examples, tokens, paths, and headers, use the elastik skill.
---

# AuditeDB Architecture: Design Principles for the Elastik L5 Engine

## Why This Skill Exists

AuditeDB ships as two Cargo packages:

```text
core/                       bin/
elastik_core (library)      elastik-core (binary)
─────────────────────       ─────────────────────
Engine + storage + audit    HTTP + CoAP + MQTT + SSE + env
+ subscription stream       + tokio runtime + signals
                                     │
                                     ▼
                            consumes the library
                            through the public Engine
                            facade only
```

The library is a protocol-neutral storage engine: paths, bytes, ETags, HMAC
chain, four-tier auth, five verbs. The binary is one specific projection of
that engine onto HTTP, CoAP, MQTT, and SSE wires. Every architecture question about
AuditeDB reduces to one test:

The canonical path shape is intentionally MQTT-like: no leading slash,
slash-separated hierarchy, no query string. HTTP `/home/a`, CoAP `home/a`, and a
MQTT topic such as `sensor/temp` all project onto validated Engine worlds.

```text
Does this keep the engine a storage engine, or does it turn the engine into
something else?
And does this keep the adapter a wire renderer, or does it turn the adapter
into a second engine?
```

When the answer is "something else," the capability belongs in a separate
process, client, browser, worker, adapter, or — if the question is about the
binary — *outside the engine library*.

Use this skill to prevent architectural drift. Use the regular `elastik` skill
for hands-on operation: deployment, curl, /proc, /listen, auth tokens, headers,
world navigation, and Rust library embedding.

## The Library / Binary Boundary

The boundary is structural, not stylistic:

- **Library knows about**: paths (`ValidatedWorldPath`), bytes (`Bytes`),
  ETags, HMAC chain, four-tier auth (`AccessTier`), five verbs (read, replace,
  append, delete, subscribe), and the typed snapshots behind `/proc/*`.
- **Library does not know about**: HTTP, CoAP, SSE, axum, hyper, tower,
  sockets, env vars, the binary's startup banner, or `curl`. A library-only
  build with `--no-default-features --features bundled-sqlite,unstable-engine`
  has zero HTTP-shaped crates in its dependency tree.
- **Binary owns**: HTTP routing, CoAP datagram parsing, MQTT session handling,
  response rendering, Authorization header parsing, env config, graceful shutdown, the
  `ServerState` adapter handle. The binary consumes the library through the
  public `Engine` API only.

When a new capability is proposed, locate it on this boundary first. The
default is **outside the library**. Promoting something to the library
requires that it be true regardless of which adapter is on top.

## Principle 1: Storage, Not App Server

The engine stores bytes and returns bytes. The adapter parses wires and
renders wires. Neither layer interprets, transforms, executes, validates,
renders, or rewrites stored *content*.

Consequences:

- `PUT /home/job/script.py` stores text bytes. It does not run Python.
- `PUT /home/page.html` stores HTML. The browser renders it; AuditeDB does not.
- `PUT /home/data.csv` stores bytes. AuditeDB does not parse CSV or run queries.
- `PUT /home/blob.json` stores bytes with a content type. Validation belongs in
  the client or worker that understands that schema.
- A dangerous executable stored in AuditeDB is stored data. The danger begins
  when some client downloads and executes it.

Decision test:

```text
After this feature is added, does AuditeDB still only store, version,
authorize, audit, notify, and return bytes?
```

If not, push the feature out of core.

## Principle 2: Physics, Not Policy

Security and correctness should come from what the system cannot do, not from
what the README says people should avoid.

Bad shape:

```text
Policy: AuditeDB will not execute uploaded code.
```

Better shape:

```text
Physics: AuditeDB has no execution engine.
```

Bad shape:

```text
Policy: Workers should not bypass the storage/audit path.
```

Better shape:

```text
Physics: Workers interact through HTTP worlds, so writes go through the same
auth, quota, ETag, and audit machinery as every other client.
```

For concurrent writes, AuditeDB supports HTTP conditional requests. `If-Match`
is not required for every write, but when a workflow needs compare-and-swap
semantics, the correct shape is: read ETag, write with `If-Match`, and treat
412 as "lost the race; re-read and retry if appropriate."

## Principle 3: Async Is Nature, Not Compromise

A disk is asynchronous by nature. You write now; another actor may read later.
The delay may be milliseconds, days, or never.

Synchronous computation is different: receive input, execute logic, and return
computed output in the same interaction. AuditeDB does not do that.

Clarifications:

- GET returning stored bytes is not synchronous computation. The bytes already
  exist.
- HEAD returning metadata is not synchronous computation. It reports stored
  representation state.
- PUT storing bytes is not computation. It records the supplied representation.
- PUT data and get a computed result back is computation. Put that in a worker.

The standard pattern is:

```text
client writes request world
worker listens or polls
worker computes
worker writes result world
client reads result world
```

AuditeDB is the mailbox and audit surface, not the worker.

## Principle 4: Compute Lives in a Separate Process

When computation is needed, run it in a separate process with its own PID,
permissions, lifecycle, and failure domain.

```text
AuditeDB: stores bytes, serves bytes, verifies/audits durable writes,
         exposes /proc, emits /listen events.

Worker:  reads bytes from AuditeDB, computes, writes bytes back.
```

Why this matters:

- Kill the worker: AuditeDB still serves existing data.
- Worker crashes: storage remains up.
- Worker is compromised: limit the worker's token, filesystem access, and
  network access.
- AuditeDB has no code execution engine to hijack.

The worker can be Python, Node, Rust, shell, PLC bridge code, browser-side JS,
or a cron job. That variety is a feature. AuditeDB should not absorb it.

## Principle 5: Format Is the Consumer's Problem

AuditeDB stores bytes with HTTP metadata. The consumer decides what the bytes
mean.

- Browser receives `text/html`: browser renders it.
- Browser receives `application/pdf`: browser or plugin handles it.
- `curl` receives `application/json`: curl prints bytes.
- A worker receives `text/csv`: worker parses it if the workflow requires CSV.

This is why AuditeDB does not need a PDF renderer, HTML engine, JSON validator,
templating engine, image pipeline, or URL rewriter. Correct `Content-Type` and
ordinary HTTP delivery let existing clients do their jobs.

No-JS browsers are useful design probes: if navigation, forms, links, and
metadata are enough, the page is aligned with AuditeDB's low-hop model. Use JS
when it helps, but do not make JS the only way to understand stored state.

## Principle 6: HTTP Usually Already Has the Mechanism (Adapter), Engine
Usually Already Has the Type (Library)

Before inventing structure, check the existing shape.

### On the binary (HTTP/CoAP adapter)

| Need | HTTP shape |
|---|---|
| Read bytes | GET |
| Read metadata | HEAD |
| Replace bytes | PUT |
| Append where supported | POST |
| Remove bytes | DELETE |
| Version identity | ETag |
| Compare-and-swap | If-Match |
| Create-if-absent | If-None-Match: * |
| Cache policy | Cache-Control / Expires |
| Body format | Content-Type |
| Human language | Content-Language |
| Navigation | Link headers and /proc/worlds |
| Change stream | SSE at /listen/<pattern> |
| Introspection | /proc/* |

Do not add a custom JSON-RPC layer merely to rename HTTP concepts that already
exist.

### On the library (Engine API)

| Need | Engine API |
|---|---|
| Read bytes | `Engine::read` |
| Replace bytes | `Engine::replace` |
| Append bytes | `Engine::append` |
| Remove bytes | `Engine::delete` |
| Validated path | `ValidatedWorldPath::new` |
| Version identity | `WriteResult.etag` / `ReadResult.etag` |
| Compare-and-swap | `Preconditions::if_match` / `if_none_match` |
| Tier authorization | `AccessTier` + `Engine::verify_token` |
| Change stream | `Engine::subscribe` returning `EngineSubscription` |
| Introspection | `Engine::list_worlds` / `du` / `df` / `pool` / `verify_audit` |
| Audit verification | `Engine::verify_audit` returning typed `AuditVerify` |
| Trace observation | `Engine::replace_traced` / `append_traced` / `delete_traced` with `EngineWriteTraceHooks` / `EngineDeleteTraceHooks` |

Do not add new public Engine surface to rename a concept that already has a
type. Adding a method costs SemVer headroom — it stays forever inside the
`unstable-engine` gate's intent to stabilize.

## Principle 7: Attack Surface Belongs at the Edge

The engine core should not parse or execute stored content. That removes entire
classes of core compromise: no template injection in core, no SQL exposed to
clients, no plugin loader, no content transformer, no code runner.

This does not mean every system built on AuditeDB is safe by default. Risk moves
to the consumer:

- A browser can execute HTML/JS it reads.
- A worker can execute or parse unsafe bytes.
- A stolen token can read or write whatever that token tier permits.
- A leaked HMAC key breaks audit-chain trust.
- A damaged data root can break durable state.

Core mitigations are tiered tokens, path-prefix policy, quota, ETag/CAS,
startup audit verification, and HMAC-chained durable mutation history.

Important distinction:

```text
Auth: Bearer/Basic tokens select a read/write/approve tier.
Audit: HMAC chains verify durable mutation history.
```

Do not call audit HMAC "authentication." Do not claim `/proc/audit` records all
access. It verifies the durable write chain for a world; it does not log every
GET/HEAD and it does not expose historical bodies.

## Principle 8: The Center Must Be the Simplest Component

The component everything depends on should be the hardest component to break.
Traditional systems often put the most complex part at the center: app server,
broker, query engine, scheduler, plugin runtime, or orchestration API.

AuditeDB has two centers stacked: the engine library is the deeper center, the
adapter binary is the wider but shallower center. Both must stay simple.

**Engine library center:**

- `ValidatedWorldPath` proof type.
- Five verbs (read, replace, append, delete, subscribe).
- `AccessTier` + `Engine::verify_token`.
- SQLite-backed durable worlds + memory-backed transient worlds.
- ETag version identity.
- HMAC-chained durable mutation audit.
- Typed `/proc/*` snapshots (`DfSnapshot`, `PoolSnapshot`, `WorldUsage`,
  `AuditVerify`).
- Subscription stream (`EngineSubscription`).

**Adapter binary center:**

- HTTP method + status code rendering.
- CoAP datagram parsing.
- `Authorization` header parsing.
- SSE rendering for `/listen/*`.
- Env config + startup banner + graceful shutdown.
- `ServerState` adapter handle.

If the engine library starts parsing wire shapes, reading env, opening
sockets, or rendering HTTP responses, it has stopped being a storage engine.
If the adapter binary starts owning storage state, audit chain bytes, or
re-implementing permits that the library provides, it has stopped being an
adapter.

## Applying the Principles

When someone asks "can AuditeDB do X?", run this decision chain:

```text
1. Does X require interpreting stored content?
   Yes -> worker/client, not the engine or adapter.

2. Does X require executing code?
   Yes -> worker/client, not the engine or adapter.

3. Does X require making outbound requests?
   Yes -> worker/client, not the engine or adapter.

4. Does X require synchronous computed output?
   Yes -> worker/client, not the engine or adapter.

5. Does X require storing, replacing, appending, deleting, reading,
   or subscribing to bytes?
   Yes -> Engine library (the five verbs).

6. Does X require metadata about stored bytes?
   Yes -> ReadResult.etag, ReadResult.representation,
          Engine::du / df / pool / list_worlds / verify_audit.

7. Does X require notifying observers that bytes changed?
   Yes -> Engine::subscribe -> EngineSubscription.

8. Does X look like /health, /version, /metrics, /audit, auth, or static
   serving for another HTTP subsystem?
   First ask whether it is just AuditeDB's existing proc/auth/audit/static
   surface projected into a domain adapter.

9. Does X require a wire shape the selected AuditeDB binary does not speak
   today (e.g. gRPC or another raw TCP protocol)?
   New adapter binary or external bridge process. Do NOT extend the engine
   library with the new wire's vocabulary.
```

If the answer is "worker," the shape is stable:

```text
client -> PUT request world
worker -> GET/LISTEN request world
worker -> compute outside AuditeDB
worker -> PUT result world
client -> GET/HEAD result world
```

## Common Proposals and Correct Responses

**"Add a /run endpoint that executes Python."**

No. Store the code or task description as bytes. A worker with an explicit
sandbox may read it, execute it, and write a result world.

**"Add URL rewriting for proxied HTML."**

No. Rewriting is content transformation. A worker or build step can fetch,
rewrite, and PUT final bytes. AuditeDB serves the final representation.

**"Add JSON validation on PUT."**

No. Validation is content interpretation. Put schema validation in the client,
worker, CI pipeline, or domain adapter.

**"Make AuditeDB synchronous for simple requests."**

GET is already immediate because it reads existing bytes. If "synchronous"
means "compute a new answer before the response returns," use a worker.

**"Add rate limiting."**

Maybe. Rate limiting is request metadata, not content interpretation. It can be
core-adjacent if it protects the shared control plane and stays domain-neutral.

**"Add authentication."**

Already exists as token tiers. Keep it generic: read, write, approve. Do not
turn core auth into domain-specific identity logic.

**"Add a new /health, /version, /metrics, or /audit route for my adapter."**

Usually no. Reuse `/proc/version`, `/proc/df`, `/proc/pool`,
`/proc/audit/<world>/verify`, ordinary status codes, and domain worlds. The
adapter should supply domain meaning, not rebuild the shared control plane.

## The Projection Theorem

Given enough time, any HTTP-facing subsystem will reinvent a subset of AuditeDB:
routing, versioning, health, metrics, auth, audit, static serving, and event
notification.

It will usually do so with extra machinery because it does not recognize that
HTTP itself is already the filesystem-shaped interface it needs.

The architectural move is to project domain state onto AuditeDB worlds instead
of rebuilding the same control plane inside every adapter.

## The Test That Ends Arguments

Two tests, one per layer.

### Test 1 — Adapter integrity

Remove the worker. Remove all clients. Leave only the `elastik-core` binary
running.

```text
Is the data still intact?
Can an authorized client still read stored bytes?
Can the engine still verify durable audit chains?
Can the adapter still report its own /proc state?
```

If yes, the adapter is still a storage server.

If removing the worker breaks the adapter, something entered the adapter
that belongs in the worker.

### Test 2 — Engine integrity

Strip the binary entirely. Build only the library:

```bash
cargo build --manifest-path core/Cargo.toml --lib --no-default-features --features bundled-sqlite,unstable-engine
```

```text
Does the library build with zero HTTP-shaped deps?
Can a non-HTTP embedder construct Engine via the builder?
Can it still call read, replace, append, delete, subscribe?
Can it still verify audit chains?
```

If yes, the engine is still protocol-neutral.

If a `cargo tree` on the library shows `axum`, `hyper`, `tower`,
`tokio-stream`, `futures-util`, or `base64`, something entered the engine
that belongs in the binary.
