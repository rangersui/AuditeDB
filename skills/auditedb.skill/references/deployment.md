# Deployment

Use this reference when starting AuditeDB, configuring a target instance, or
explaining the minimum environment a user needs.

## Minimum local run

AuditeDB needs one HMAC key. Tokens are optional gates.

```bash
export AUDITEDB_HOST=127.0.0.1
export AUDITEDB_PORT=3105
export AUDITEDB_BASE="http://${AUDITEDB_HOST}:${AUDITEDB_PORT}"
export AUDITEDB_DATA=./data
export AUDITEDB_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export AUDITEDB_WRITE_TOKEN="write-token"
export AUDITEDB_APPROVE_TOKEN="approve-token"
```

Then run one of the available server entrypoints:

```bash
# From a source checkout
cargo run --manifest-path bin/Cargo.toml --bin auditedb

# If the Rust binary is installed or built
auditedb
```

Use whichever entrypoint exists on the user's machine. The HTTP contract is the
same after the instance is running.

## Verify the instance

```bash
curl -i "$AUDITEDB_BASE/proc/version"
curl -i "$AUDITEDB_BASE/proc/worlds"
curl -i "$AUDITEDB_BASE/proc/df"
```

`/proc/version` is public and works without any token. `/proc/worlds` and
`/proc/df` are read-gated when `AUDITEDB_READ_TOKEN` is set; otherwise they are
public too.

`/proc/worlds` is plain text, one world per line. It is not JSON.

On startup, AuditeDB verifies every durable world's HMAC audit chain before it
listens for requests. If a chain is broken, startup fails loudly and names the
affected world instead of serving corrupt state. Resolve that world or data root
before retrying the boot.

The bare root `GET /` returns a short hint:

```text
auditedb <version> (rust)
try: curl /proc/worlds
```

## Environment variables

Core address and data:

```text
AUDITEDB_HOST=127.0.0.1
AUDITEDB_PORT=3105
AUDITEDB_BASE=http://127.0.0.1:3105
AUDITEDB_DATA=./data
AUDITEDB_KEY=<secret hmac key>
```

Auth gates:

```text
AUDITEDB_READ_TOKEN=<optional read token>
AUDITEDB_WRITE_TOKEN=<write token for PUT/POST on ordinary namespaces>
AUDITEDB_APPROVE_TOKEN=<approve token for protected writes and all DELETEs>
```

Header policy:

```text
AUDITEDB_PERSIST_HEADERS=x-meta-*
AUDITEDB_DENY_HEADERS=cache-control
```

Resource caps:

```text
AUDITEDB_MAX_WORLD_BYTES=67108864
AUDITEDB_MAX_STORAGE_BYTES=
AUDITEDB_MAX_MEMORY_BYTES=268435456
AUDITEDB_MAX_LISTEN_CONNECTIONS=1024
```

Trace:

```text
AUDITEDB_TRACE_PIPELINE=1
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

Loopback is local. Binding to `127.0.0.1` exposes AuditeDB only on the local
machine.

Non-loopback is a deliberate network service. If binding to `0.0.0.0`, a LAN
address, or an overlay address, set at least a read token unless public reads
are intentional.

## One writer per data directory

AuditeDB holds a SQLite-backed writer lock on
`AUDITEDB_DATA/.AuditeDB-writer-lock.sqlite3` for the lifetime of the process. A
second AuditeDB process pointed at the same data directory fails to start with a
lock error instead of silently corrupting state. The error includes a
best-effort holder PID when the previous owner committed one before taking the
lock.

This assumes a local filesystem. SQLite file locks are not a distributed
coordination protocol, and NFS or other network filesystems with weak locking
or caching semantics can break that assumption. Put `AUDITEDB_DATA` on local
storage, or use an external coordinator that is designed for distributed
ownership.

To serve a different universe, change `AUDITEDB_DATA`.

## Storage layout

The core lays out one SQLite file per durable world under `AUDITEDB_DATA`:

```text
AUDITEDB_DATA/
  <disk_name(world)>/
    universe.db
```

Each `universe.db` contains the world's representation: `stage_meta`,
`meta_headers`, `events`, `event_headers`. This is implementation detail; the
HTTP surface treats a world as a single key with a body and metadata.

## Deployment checklist

1. Pick `AUDITEDB_DATA`.
2. Generate `AUDITEDB_KEY`.
3. Decide read/write/approve tokens.
4. Start the instance.
5. Verify `/proc/version`.
6. PUT one test world.
7. HEAD the test world and confirm `ETag`.
