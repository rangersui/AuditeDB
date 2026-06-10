# HTTP worlds

Use this reference when working with AuditeDB wire behaviour: methods, paths,
headers, namespace policy, status codes, caching, ETag/CAS, `/proc/*`, and
`/listen/*`.

## Data model

AuditeDB is a flat HTTP key-value store. A world is one entry:

```text
world  =  canonical key  ->  representation
representation  =  body bytes + content-type + persisted headers
                 + version/audit metadata (ETag)
```

There are no directories. The slashes in a key are part of the string, not a
tree. `home/a/b` is not a child of `home/a`; it is a different key.

## Canonical key

The HTTP wire path always starts with a slash. The HTTP adapter canonicalises
it into an Engine world path before lookup:

```text
HTTP wire:        /home/a    /tmp/x
Engine canonical: home/a     tmp/x
```

### MQTT-shaped canonical keys

Core canonical keys are MQTT-topic-shaped: `home/sensor/temp`, not
`/home/sensor/temp` and not `home/sensor/temp?x=y`. This is why HTTP, CoAP,
SSE, and MQTT can all project onto the same validated Engine world grammar:
the adapter owns wire syntax, the engine owns the topic-like key.

### Bare-path rule

Paths that do not start with a reserved root get `home/` prepended:

```text
/jobs/x      ->  home/jobs/x
/log/foo     ->  home/log/foo
/channel/me  ->  home/channel/me
```

Prefer explicit `home/...` in code and documentation so the destination key is
obvious without knowing this rule.

### Reserved roots

```text
home  tmp  dev  sys  proc  etc  lib  boot  usr  var  var/log
```

A reserved root cannot be written as a world by itself, only used as a prefix.
The entire `proc/*` subtree is reserved for generated introspection and is not
user-writable at all.

### Path validation

```text
reject  empty key
reject  a reserved root by itself (home, tmp, proc, var, var/log, ...)
reject  /proc/* writes
reject  backslash
reject  control bytes (tab, newline, CR, anything matching char::is_control)
reject  empty segment, e.g. home//x
reject  dot or encoded-dot segment, e.g. . .. %2e %2e%2e
allow   ordinary Unicode
allow   slash, but only as a key character and namespace prefix convention,
        not as a directory operator
```

Because control bytes are rejected at write time, `/proc/du`'s
`world<TAB>bytes<LF>` format is unambiguous: a legitimate world name cannot
contain a tab or newline.

## Namespace policy

Each reserved prefix selects backend, durability, audit, and write gate.

```text
prefix       backend   persistence  audit  write gate   convention
-------------------------------------------------------------------------------
home/*       SQLite    durable      yes    write        ordinary user K-V
etc/*        SQLite    durable      yes    approve      config
lib/*        SQLite    durable      yes    approve      inert assets/blobs
boot/*       SQLite    durable      yes    approve      system/boot
usr/*        SQLite    durable      yes    approve      system/userland
var/*        SQLite    durable      yes    write        variable durable state
var/log/*    SQLite    durable      yes    approve      log/audit-like
tmp/*        memory    transient    no     write        scratch
dev/*        memory    transient    no     write        live values (PLC/sensor)
sys/*        memory    transient    no     write        health/status live
proc/*       virtual   generated    no     read-mostly  introspection (no write)
```

Namespaces are prefix-level storage policy plus human convention. The core
enforces backend, durability, audit, auth gate, and the reserved-root list. It
does not enforce directory semantics or rich OS behaviour. Names like `/dev`,
`/sys`, `/etc`, `/lib`, and `/var/log` are coordination conventions for humans
and agents, not runtime hooks into a kernel.

DELETE always requires the approve token, in every namespace.

### Special worlds

- `var/log/deletes` is the global delete ledger. It is append-only in the sense
  that DELETE refuses to remove it.

## Verbs

```text
GET     read body
HEAD    read metadata, no body
PUT     replace world
POST    append, where the endpoint supports it
DELETE  remove world (approve token)
LISTEN  subscribe to change events; wire is GET /listen/<pattern>, SSE
```

LISTEN is a semantic verb. On the wire it is an ordinary `GET` against
`/listen/<pattern>`, but the response is a long-lived `text/event-stream` rather
than a single body. See the `/listen/*` section below.

`OPTIONS` is supported on guarded paths for capability discovery but is not a
core data verb.

Status codes are part of the API contract. Do not wrap them in JSON.

Common status-code triage:

```text
200/201/204  success, depending on method
206          Range success
304          If-None-Match matched; body omitted
401          missing or wrong Authorization Bearer token
403          token tier too low for the namespace
404          world not found
412          If-Match failed; re-read ETag and retry if appropriate
413          request body exceeded ELASTIK_MAX_WORLD_BYTES
416          Range starts past EOF
503          transient busy/locked/listen-cap condition; retry when safe
507          durable quota, memory quota, or filesystem full
```

## Introspection: /proc/*

```text
path                            auth          body
-------------------------------------------------------------------------------
/proc/version                   public        plain text: core version
/proc/worlds                    read          plain text, one world per line
/proc/du                        read          plain text, world<TAB>bytes<LF>
/proc/df                        read          plain text metrics: storage,
                                              memory, quota, world count
/proc/pool                      read          plain text metrics: read cache,
                                              connection pool, ledger writer
/proc/audit/<world>/verify      read          status/headers; GET or HEAD
/proc, /proc/<unknown>          method-vary   reserved namespace guard
```

`/proc/version` is intentionally unauthenticated so that probes can confirm a
server is alive without credentials.

`/proc/audit/<world>/verify` walks the HMAC-chained audit log for a durable
world. `GET` and `HEAD` both work; the result is in the response status and
headers, not a useful body. For memory-backed worlds (`tmp/*`, `dev/*`,
`sys/*`) it returns `not applicable`.

`/proc/pool` output looks like this (counter or snapshot suffix on each line):

```text
read_cache_entries N snapshot
read_cache_tombstones N snapshot
read_cache_hits N counter
read_cache_misses N counter
read_cache_capped N counter
read_cache_open_fails N counter
read_cache_max_entries N snapshot
ledger_writer_inits N counter
```

`/proc` and any unknown `/proc/<name>` act as namespace guards. Behaviour:

```text
GET     /proc          -> 404
HEAD    /proc          -> 404
OPTIONS /proc          -> 204, Allow: GET, HEAD, OPTIONS
<other> /proc          -> 405
```

The guard exists to keep the `proc/*` subtree closed against accidental writes.

## ETag and CAS

- Durable worlds use HMAC-chained strong ETags. The ETag is the version
  identity, not a hint.
- Use `If-Match` for compare-and-swap writes.
- Use `If-None-Match` for cache revalidation.
- `304 Not Modified` means the current representation matches the supplied
  validator.
- Do not invent version fields when ETag already carries the version identity.

## Header persistence policy

AuditeDB uses a layered header policy:

1. **Hard deny.** Hop-by-hop, request-control, probe, proxy, and core-owned
   headers never persist.
2. **User deny.** `ELASTIK_DENY_HEADERS` subtracts from allow layers for future
   writes only.
3. **Default allow.** Standard representation, browser-policy, and
   body-identity headers persist.
4. **User allow.** `ELASTIK_PERSIST_HEADERS` opts in custom headers such as
   `x-meta-*`.

`X-Meta-*` is a user metadata convention. It is not persisted by default. To
round-trip custom metadata, set:

```text
ELASTIK_PERSIST_HEADERS=x-meta-*
```

`Content-Type` has a dedicated media-type slot; it is not ordinary persisted
metadata. `ETag`, `Link`, `Content-Length`, and range headers are core-owned.

## Listen: /listen/*

`/listen/<pattern>` returns a long-lived `text/event-stream`. There is no
content negotiation: curl and browsers see the same SSE frames. The wire is
not "one path per line"; it is SSE.

### Frame shape

```text
event: put
id: 42
data: path: /home/task/a
data: method: PUT
data: etag: hmac-...

event: delete
id: 43
data: path: /home/task/a
data: method: DELETE

event: lag
data: missed: 12

event: reset
id: 7
data: since: 500
data: newest: 7

: keepalive
```

The server (`axum::Sse` with a 15-second `KeepAlive`) emits a `: keepalive`
SSE comment on idle, a `lag` event when the listener falls behind or
resumes from an id older than the replay ring retains, a `reset` event when
the client's `Last-Event-ID` predates an engine restart (ids are
process-local; the `id:` field rebases the client's cursor and the stream
continues live), and a `put` / `delete` / similar event on each change.

### Client compatibility

```text
client                                      works   notes
---------------------------------------------------------------------------
curl -N /listen/<pattern>                   yes     sees SSE frames, not paths
browser EventSource, no read token          yes     standard SSE
browser EventSource + Bearer token          no      native EventSource cannot
                                                    set Authorization
browser fetch + ReadableStream              yes     parse SSE manually
Python requests(..., stream=True)           yes     parse SSE lines manually
JS SDK listen()                              yes     wraps fetch + parser
```

The summary for client code: `/listen/*` is Server-Sent Events. Use
`EventSource` only when no `Authorization` header is required. Use
`fetch` + `ReadableStream` or the SDK's `listen()` when read tokens are
enabled.

## Curl patterns

Bare PUT:

```bash
printf 'hello\n' |
  curl -i -X PUT "$ELASTIK_BASE/home/note" \
    -H "Authorization: Bearer $ELASTIK_WRITE_TOKEN" \
    -H "Content-Type: text/plain; charset=utf-8" \
    --data-binary @-
```

CAS update:

```bash
etag="$(
  curl -fsSI "$ELASTIK_BASE/home/note" |
    awk 'BEGIN{IGNORECASE=1} /^etag:/ { sub(/\r$/, ""); print substr($0, index($0, ":") + 2); exit }'
)"

printf 'new\n' |
  curl -i -X PUT "$ELASTIK_BASE/home/note" \
    -H "Authorization: Bearer $ELASTIK_WRITE_TOKEN" \
    -H "If-Match: $etag" \
    --data-binary @-
```

## Browser caching note

Use curl or Firefox when testing `If-None-Match` and `304`. Brave may strip
`If-None-Match` as an ETag fingerprinting defence, so it can return 200 even
when Elastik would correctly return 304 to a bare HTTP client.
