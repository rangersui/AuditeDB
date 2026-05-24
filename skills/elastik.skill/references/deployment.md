# Deployment

Use this reference when starting Elastik, configuring a target instance, or
explaining the minimum environment a user needs.

## Minimum local run

Elastik needs one HMAC key. Tokens are optional gates.

```bash
export ELASTIK_HOST=127.0.0.1
export ELASTIK_PORT=3105
export ELASTIK_BASE="http://${ELASTIK_HOST}:${ELASTIK_PORT}"
export ELASTIK_DATA=./data
export ELASTIK_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export ELASTIK_WRITE_TOKEN="write-token"
export ELASTIK_APPROVE_TOKEN="approve-token"
```

Then run one of the available entrypoints:

```bash
# From a source checkout
cargo run --manifest-path core/Cargo.toml

# If the Rust binary is installed or built
elastik-core

# If the Python package is installed
python -m elastik run \
  --key "$ELASTIK_KEY" \
  --write-token "$ELASTIK_WRITE_TOKEN" \
  --approve-token "$ELASTIK_APPROVE_TOKEN"
```

Use whichever entrypoint exists on the user's machine. The HTTP contract is the
same after the instance is running.

## Verify the instance

```bash
curl -i "$ELASTIK_BASE/proc/version"
curl -i "$ELASTIK_BASE/proc/worlds"
curl -i "$ELASTIK_BASE/proc/df"
```

`/proc/version` is public and works without any token. `/proc/worlds` and
`/proc/df` are read-gated when `ELASTIK_READ_TOKEN` is set; otherwise they are
public too.

`/proc/worlds` is plain text, one world per line. It is not JSON.

On startup, Elastik verifies every durable world's HMAC audit chain before it
listens for requests. If a chain is broken, startup fails loudly and names the
affected world instead of serving corrupt state. Resolve that world or data root
before retrying the boot.

The bare root `GET /` returns a short hint:

```text
elastik-core <version> (rust)
try: curl /proc/worlds
```

## Environment variables

Core address and data:

```text
ELASTIK_HOST=127.0.0.1
ELASTIK_PORT=3105
ELASTIK_BASE=http://127.0.0.1:3105
ELASTIK_DATA=./data
ELASTIK_KEY=<secret hmac key>
```

Auth gates:

```text
ELASTIK_READ_TOKEN=<optional read token>
ELASTIK_WRITE_TOKEN=<write token for PUT/POST on ordinary namespaces>
ELASTIK_APPROVE_TOKEN=<approve token for protected writes and all DELETEs>
```

Header policy:

```text
ELASTIK_PERSIST_HEADERS=x-meta-*
ELASTIK_DENY_HEADERS=cache-control
```

Resource caps:

```text
ELASTIK_MAX_WORLD_BYTES=67108864
ELASTIK_MAX_STORAGE_BYTES=
ELASTIK_MAX_MEMORY_BYTES=268435456
ELASTIK_MAX_LISTEN_CONNECTIONS=1024
```

Trace:

```text
ELASTIK_TRACE_PIPELINE=1
```

## Token gates by namespace

The write/approve split is not free-form policy; it is fixed by the core
according to the key prefix.

```text
prefix       write gate         notes
-----------------------------------------------------------------
home/*       write token        ordinary user K-V
tmp/*        write token        scratch (memory)
dev/*        write token        live values (memory, convention)
sys/*        write token        live values (memory, convention)
var/*        write token        variable durable state
etc/*        approve token      config-like, durable
lib/*        approve token      inert assets/blobs
boot/*       approve token      system/boot
usr/*        approve token      system/userland
var/log/*    approve token      log/audit-like, durable
proc/*       not user-writable  generated introspection
```

DELETE always requires the approve token, regardless of namespace.

If only the write token is needed, the approve token can be omitted in
development. For any deployment that allows deletes or touches system
namespaces, both should be set.

## Binding rule

Loopback is local. Binding to `127.0.0.1` exposes Elastik only on the local
machine.

Non-loopback is a deliberate network service. If binding to `0.0.0.0`, a LAN
address, or an overlay address, set at least a read token unless public reads
are intentional.

## One writer per data directory

Elastik holds a SQLite-backed writer lock on
`ELASTIK_DATA/.elastik-writer-lock.sqlite3` for the lifetime of the process. A
second Elastik process pointed at the same data directory fails to start with a
lock error instead of silently corrupting state.

To serve a different universe, change `ELASTIK_DATA`.

## Storage layout

The core lays out one SQLite file per durable world under `ELASTIK_DATA`:

```text
ELASTIK_DATA/
  <disk_name(world)>/
    universe.db
```

Each `universe.db` contains the world's representation: `stage_meta`,
`meta_headers`, `events`, `event_headers`. This is implementation detail; the
HTTP surface treats a world as a single key with a body and metadata.

## Deployment checklist

1. Pick `ELASTIK_DATA`.
2. Generate `ELASTIK_KEY`.
3. Decide read/write/approve tokens.
4. Start the instance.
5. Verify `/proc/version`.
6. PUT one test world.
7. HEAD the test world and confirm `ETag`.
