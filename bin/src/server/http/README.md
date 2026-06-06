# AuditeDB HTTP Adapter

The HTTP adapter is the default `elastik-core` binary surface. It maps HTTP
methods, headers, and status codes onto the protocol-neutral Engine.

Engine rules live in the top-level [`README.md`](../../../../README.md). This
file documents the binary wire surface: startup, HTTP worlds, `/proc/*`,
`/listen/*`, curl usage, and adapter environment variables.

## Quick Start

```bash
export ELASTIK_KEY=secret
export ELASTIK_WRITE_TOKEN=secret
cargo run --manifest-path bin/Cargo.toml --bin elastik-core
# elastik-core v8.2.0 on http://127.0.0.1:3105/

curl                  http://127.0.0.1:3105/proc/version
curl -X PUT -H "Authorization: Bearer $ELASTIK_WRITE_TOKEN" \
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
| `ELASTIK_KEY` | required | HMAC audit-chain key; startup refuses empty or missing keys. |
| `ELASTIK_READ_TOKEN` | unset | Gates reads, `/proc/*`, and `/listen/*`; unset means public reads. |
| `ELASTIK_WRITE_TOKEN` | unset | Enables ordinary PUT/POST writes in user namespaces such as `home/`. |
| `ELASTIK_APPROVE_TOKEN` | unset | Enables DELETE and writes in protected namespaces such as `etc/` and `var/log/`. |
| `ELASTIK_TOKEN` | unset | Deprecated alias for `ELASTIK_WRITE_TOKEN`. |
| `ELASTIK_DATA` | `./data` | SQLite data root. |
| `ELASTIK_HOST` | `127.0.0.1` | HTTP bind host. |
| `ELASTIK_PORT` | `3105` | HTTP bind port. |
| `ELASTIK_PERSIST_HEADERS` | unset | Comma-separated custom response headers to preserve, e.g. `x-author,x-meta-*`. |
| `ELASTIK_DENY_HEADERS` | unset | Subtracts headers from the persist allowlist. |
| `ELASTIK_MAX_WORLD_BYTES` | `67108864` | Maximum body size for one world. |
| `ELASTIK_MAX_MEMORY_BYTES` | `268435456` | Total in-memory quota for `tmp/`, `dev/`, and `sys/` worlds. |
| `ELASTIK_MAX_STORAGE_BYTES` | unset | Optional durable SQLite-backed storage quota. |
| `ELASTIK_MAX_LISTEN_CONNECTIONS` | `1024` | Maximum concurrent `/listen/*` SSE subscriptions. |
| `ELASTIK_LISTEN_REPLAY_MAX` | `1024` | Replay ring size for reconnecting SSE clients. |
| `ELASTIK_READ_CACHE_MAX_ENTRIES` | `5000` | Read-cache entry cap. |
| `ELASTIK_TRACE_PIPELINE` | unset | Emit request pipeline trace lines when set. |

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

## `/proc/*`

The binary exposes text-shaped `/proc/*` endpoints over HTTP. These are adapter
renderings of Engine snapshots, not storage worlds. `/proc/version` is public
and is the quickest liveness probe. The other read-only `/proc/*` endpoints
require `ELASTIK_READ_TOKEN` when a read token is configured. `OPTIONS` is
always policy-free capability discovery.

| Endpoint | Methods | Auth | Purpose |
|----------|---------|------|---------|
| `/proc/version` | `GET`, `HEAD`, `OPTIONS` | public | Binary version string, e.g. `elastik-core 8.2.0 (rust)`. |
| `/proc/worlds` | `GET`, `HEAD`, `OPTIONS` | read-gated | Canonical world list, one `home/foo`-style key per line. |
| `/proc/du` | `GET`, `HEAD`, `OPTIONS` | read-gated | Per-world byte usage. This is an unpaginated management view. |
| `/proc/df` | `GET`, `HEAD`, `OPTIONS` | read-gated | Storage and memory quota snapshot plus world count. |
| `/proc/pool` | `GET`, `HEAD`, `OPTIONS` | read-gated | Read-cache, tombstone, and ledger-writer counters/gauges. |
| `/proc/mqtt/metrics` | `GET`, `HEAD`, `OPTIONS` | read-gated | MQTT adapter counters and gauges when MQTT is enabled. |
| `/proc/audit/<world>/verify` | `GET`, `HEAD`, `OPTIONS` | read-gated | Verify the durable world's HMAC audit chain. Memory worlds return not-applicable. |

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
