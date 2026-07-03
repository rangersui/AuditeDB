# AuditeDB HTTP Adapter

The HTTP adapter is the default `auditedb` binary surface. It maps HTTP
methods, headers, and status codes onto the protocol-neutral Engine.

Engine rules live in the top-level [`README.md`](../../../../README.md). This
file documents the binary wire surface: startup, HTTP worlds, `/proc/*`,
`/listen/*`, curl usage, and adapter environment variables.

## Quick Start

```bash
export AUDITEDB_KEY=0123456789abcdef0123456789abcdef
export AUDITEDB_WRITE_TOKEN=secret
cargo run --manifest-path bin/Cargo.toml --bin auditedb
# auditedb v8.3.0 on http://127.0.0.1:3105/

curl                  http://127.0.0.1:3105/proc/version
curl -X PUT -H "Authorization: Bearer $AUDITEDB_WRITE_TOKEN" \
  -d 'hi'          http://127.0.0.1:3105/home/hello
curl              http://127.0.0.1:3105/home/hello
curl              http://127.0.0.1:3105/proc/worlds
curl -N           http://127.0.0.1:3105/listen/home/*
```

The binary package depends on the Engine library with `unstable-engine`
enabled. The Engine library itself still builds without the HTTP adapter stack.

## Environment

Common binary environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `AUDITEDB_KEY` | required | HMAC audit-chain key; startup refuses missing, empty, all-whitespace, or shorter-than-32-byte keys. |
| `AUDITEDB_READ_TOKEN` | unset | Gates reads, `/proc/*`, and `/listen/*`; unset means public reads. |
| `AUDITEDB_WRITE_TOKEN` | unset | Enables ordinary PUT/POST writes in user namespaces such as `home/`. |
| `AUDITEDB_APPROVE_TOKEN` | unset | Enables DELETE and writes in protected namespaces such as `etc/` and `var/log/`. |
| `AUDITEDB_DATA` | `./data` | SQLite data root. |
| `AUDITEDB_HOST` | `127.0.0.1` | HTTP bind host. |
| `AUDITEDB_PORT` | `3105` | HTTP bind port. |
| `AUDITEDB_PERSIST_HEADERS` | unset | Comma-separated custom response headers to preserve, e.g. `x-author,x-meta-*`. |
| `AUDITEDB_DENY_HEADERS` | unset | Subtracts headers from the persist allowlist. |
| `AUDITEDB_MAX_WORLD_BYTES` | `67108864` | Maximum body size for one world. |
| `AUDITEDB_MAX_MEMORY_BYTES` | `268435456` | Accounted in-memory quota for `tmp/`, `dev/`, and `sys/` worlds: body plus key, metadata, hash, and fixed entry overhead. |
| `AUDITEDB_MAX_STORAGE_BYTES` | unset | Optional durable SQLite-backed storage quota. |
| `AUDITEDB_MAX_LISTEN_CONNECTIONS` | `1024` | Maximum concurrent `/listen/*` SSE subscriptions. |
| `AUDITEDB_LISTEN_REPLAY_MAX` | `1024` | Replay ring size for reconnecting SSE clients. |
| `AUDITEDB_READ_CACHE_MAX_ENTRIES` | `5000` | Read-cache entry cap. |
| `AUDITEDB_TRACE_PIPELINE` | unset | Emit request pipeline trace lines when set to `1`, `true`, `yes`, or `on`. |

MQTT and CoAP options live in their adapter READMEs:
[`mqtt/README.md`](../mqtt/README.md) and [`coap/README.md`](../coap/README.md).

## World Methods

HTTP world paths use a leading slash on the wire. The adapter canonicalises
them before calling Engine methods.

| HTTP | Engine verb | Notes |
|------|-------------|-------|
| `GET /<world>` | `read` | Reads the body. Supports range reads where implemented. |
| `HEAD /<world>` | `read` | Reads metadata without the body. |
| `PUT /<world>` | `replace` | Overwrites body, selected headers, and content type. |
| `POST /<world>` | `append` | Appends body where supported. |
| `DELETE /<world>` | `delete` | Requires approve tier. |
| `GET /listen/<pattern>` | `subscribe` | SSE stream over Engine change events. |

Bare HTTP paths such as `/foo` are adapter-side conveniences and map to
`home/foo` before validation. The Engine library itself rejects bare names.

## `/listen/*`

`GET /listen/<pattern>` opens a Server-Sent Events stream. Each event is a
control-plane notification: it says which world changed, but it never embeds
the world's body.

```text
event: format
id: home/task/a@0123456789abcdef0123456789abcdef=1
data: path: /home/task/a
data: method: FORMAT
data: event-type: format
data: body-sha256: e3b0...
data: size: 0
data: content-type:

event: put
id: home/task/a@0123456789abcdef0123456789abcdef=2
data: path: /home/task/a
data: method: PUT
data: etag: hmac-...
data: timeline-world: home/task/a
data: timeline-generation: ...
data: timeline-seq: 2
data: timeline-body-sha256: ...
data: event-type: put
data: body-sha256: ...
data: size: 123
data: content-type: text/plain
```

`timeline-*` fields appear for durable body writes when the Engine has a
timeline address for that exact world. They identify the historical write; they
are not a body payload. A later `GET /home/task/a` reads the current value and
may observe a newer write than the event that woke the client.

The SSE `id` field is a durable subscription replay coordinate
`<world>@<generation>=<seq>`. Its `seq` is the current `TimelineSeq` / SQLite
`events.id` row coordinate, not a verified chain ordinal and not a
`/proc/audit/<world>/stamp/<seq>` input. Durable body writes use the subject
world as the id world and include `timeline-*` fields. The subject-world delete
signal is still live-only, omits `id`, and includes `ledger-cursor` naming the
delete intent row plus derived `ledger-seq`. Durable subject deletes also
include `target-generation`, the deleted incarnation recorded in the signed
delete-subject proof. That proof is signed metadata with five fields:
subject world, generation, seq, body-sha256, and row HMAC. The wire exposes
the generation directly; `ledger-cursor` points at the replayable delete-ledger
row that carries the full proof. `event-type`, `body-sha256`, `size`, and
`content-type` describe the durable audit row; they are metadata, not embedded
body bytes.
Subscribe to `var/log/deletes` for the replayable delete wake stream; the SSE
event names the ledger world, and carries `event-type` (`delete_intent`,
`delete_commit`, or `delete_commit_failed`) plus `target` for the deleted
subject. Memory events also omit `id`. `Last-Event-ID` can resume an
exact-world subscription from that world's durable replay coordinate. Wildcard
subscriptions can replay only from this process's live ring; a missed ring
marker reports `event: reset` with `reason: ring-miss`. Runtime broadcast
overflow reports `event: lag`.

Use the timeline coordinate to read that exact historical body:

```text
GET  /home/task/a?timeline=1&timeline-generation=<gen>&timeline-seq=<seq>&timeline-body-sha256=<sha256>
HEAD /home/task/a?timeline=1&timeline-generation=<gen>&timeline-seq=<seq>&timeline-body-sha256=<sha256>
```

The path supplies the world. `timeline-world` is never accepted in the query.
Historical `GET` responses return the full body. Historical `GET` and `HEAD`
responses include `X-Timeline-*` proof headers. `HEAD` returns headers only.
They do not emit current-world `ETag`, range, or monitor-link headers.

Timeline-looking requests have a closed status vocabulary:

| Case | Status | Output shape |
|------|--------|--------------|
| `OPTIONS`, even with timeline-looking or malformed timeline query strings | `204` | Ordinary world-route `Allow`, no timeline dereference. |
| Historical `GET` | `200` | Historical body bytes plus `X-Timeline-*` proof headers. |
| Historical `HEAD` | `200` | Same proof headers, no body. |
| Invalid timeline query, duplicate fields, unknown timeline fields, extra query fields, malformed coordinates, or memory-world coordinates | `400` | Text error. |
| Missing or invalid read token when a read token is configured | `401` | Existing read-token challenge. |
| Timeline mode with any method other than `GET`, `HEAD`, or `OPTIONS` | `405` | `Allow: GET, HEAD, OPTIONS`. |
| Raw query over the adapter cap | `414` | Text error. |
| Generation or body-SHA-256 mismatch | `409` | Text reason. |
| Expired historical body | `410` | Text reason plus `X-Timeline-*` proof headers for the expired row. |
| Non-body event, missing row, or unproven coordinate | `404` | Text reason. |
| Corrupt verified row, worker failure, or other storage/internal failure | `500` | Text error. |
| Transient storage failure or shutdown | `503` | Retryable storage response. |
| Insufficient storage | `507` | Insufficient-storage response. |

`HEAD` timeline failures preserve the same status and headers as `GET` but
return no response body. Timeline mode never falls back to the current world
body when the historical coordinate cannot be proven.

Persisted metadata is filtered before historical response headers are emitted.
Invalid or denied stored metadata does not become a timeline parse failure.

Timeline mode adds no environment variables. It uses the existing read-token,
header persistence, read-cache, and storage settings listed above.

## `/proc/*`

The binary exposes text-shaped `/proc/*` endpoints over HTTP. These are adapter
renderings of Engine snapshots, not storage worlds. `/proc/version` is public
and is the quickest liveness probe. The other read-only `/proc/*` endpoints
require `AUDITEDB_READ_TOKEN` for `GET` and `HEAD` when a read token is
configured. `OPTIONS` is always policy-free capability discovery: it returns
`Allow` without validating the resource-specific `<world>` or proving that the
resource exists.

| Endpoint | Methods | Auth | Purpose |
|----------|---------|------|---------|
| `/proc/version` | `GET`, `HEAD`, `OPTIONS` | public | Binary version string, e.g. `auditedb 8.3.0 (rust)`. |
| `/proc/worlds` | `GET`, `HEAD`, `OPTIONS` | `GET`/`HEAD` read-gated; `OPTIONS` public | Canonical world list, one `home/foo`-style key per line. |
| `/proc/du` | `GET`, `HEAD`, `OPTIONS` | `GET`/`HEAD` read-gated; `OPTIONS` public | Per-world byte usage. This is an unpaginated management view. |
| `/proc/df` | `GET`, `HEAD`, `OPTIONS` | `GET`/`HEAD` read-gated; `OPTIONS` public | Storage and memory quota snapshot plus world count. |
| `/proc/pool` | `GET`, `HEAD`, `OPTIONS` | `GET`/`HEAD` read-gated; `OPTIONS` public | Read-cache, tombstone, and ledger-writer counters/gauges. |
| `/proc/mqtt/metrics` | `GET`, `HEAD`, `OPTIONS` | `GET`/`HEAD` read-gated; `OPTIONS` public | MQTT adapter counters and gauges when MQTT is enabled. |
| `/proc/audit/<world>/verify` | `GET`, `HEAD`, `OPTIONS` | `GET`/`HEAD` read-gated; `OPTIONS` public | Verify the durable world's HMAC audit chain. Memory worlds return not-applicable. |
| `/proc/audit/<world>/head` | `GET`, `HEAD`, `OPTIONS` | `GET`/`HEAD` read-gated; `OPTIONS` public | Return `200` with `x-audit-head: true`, `x-audit-generation: <32hex>`, `x-audit-seq`, `x-audit-hmac: hmac-<64hex>`, and no body. Worlds with no audit head return `204` with `x-audit-head: n/a` and no proof headers. |
| `/proc/audit/<world>/stamp/<seq>` | `GET`, `HEAD`, `OPTIONS` | `GET`/`HEAD` read-gated; `OPTIONS` public | Return the verified HMAC at a positive audit-chain ordinal. Existing durable chains without that ordinal return `204` with `x-audit-stamp: n/a`, `x-audit-generation`, and `x-audit-events`; memory worlds return `204` with only `x-audit-stamp: n/a`. |

`/proc/du` is tab-separated:

```text
world    total_body_bytes    current_body_bytes    retained_cas_body_bytes    audit_chain_events
```

`/proc/df` keeps the legacy `storage`, `memory`, and `worlds` rows, and also
emits `storage_current_body_bytes`, `storage_retained_cas_body_bytes`, and
`storage_audit_chain_events`. Durable storage byte gauges are Engine-accounted
body bytes, not SQLite file size, WAL size, or index overhead. The `memory`
row charges body bytes plus key, metadata, hash, and fixed entry overhead.

For audit verification, `<world>` is still a normal canonical world key:
`/proc/audit/home/note/verify` verifies `home/note`. It does not create or read
a `proc/audit/...` storage world. The HTTP adapter parses that path, validates
`home/note`, calls `Engine::verify_audit`, then renders the typed result back
as HTTP status and audit headers.

## Browser Reality

HTTP responses are real web responses. `X-Content-Type-Options: nosniff` means
browsers will not guess a friendlier type for `application/octet-stream`.
If a world should render in a browser, write it with an accurate `Content-Type`.

Use curl for bare-metal HTTP checks. Browsers are policy stacks.
