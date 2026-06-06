# AuditeDB MQTT Adapter

The MQTT adapter is a binary surface over the Engine. It speaks MQTT 3.1.1 to
clients and translates accepted operations into Engine reads, writes, and
subscriptions.

Engine rules live in the top-level [`README.md`](../../../../README.md). HTTP
startup and `/proc/*` live in [`../http/README.md`](../http/README.md).

## Scope

This is an MQTT-shaped storage adapter, not a full broker replacement.

Supported:

- MQTT 3.1.1
- inbound QoS 0, QoS 1, and QoS 2 publishes
- clean sessions
- unique non-empty client IDs
- namespace-relative client topics
- durable retained replay via Engine worlds

Rejected or intentionally absent:

- MQTT v5 properties
- persistent sessions
- Last Will
- global `#`
- `+` single-level wildcards
- client topics that explicitly include AuditeDB namespaces such as `home/` or `tmp/`

The built-in listener is plaintext MQTT. Terminate TLS externally before
exposing it outside a trusted network.

## Topic Mapping

Clients publish and subscribe to namespace-relative topics:

```text
sensor/temp
factory/line-1/status
```

The adapter chooses the Engine namespace:

| MQTT publish | Engine world | Storage |
|--------------|--------------|---------|
| `retain=false`, `sensor/temp` | `tmp/sensor/temp` | transient memory, not audited |
| `retain=true`, `sensor/temp` | `home/sensor/temp` | durable SQLite, HMAC audited |

Outbound MQTT topics strip the internal namespace back to the client-visible
topic. A client sees `sensor/temp`, not `tmp/sensor/temp` or `home/sensor/temp`.

Avoid mixing retained and non-retained publishes for the same MQTT topic unless
the application intentionally wants two storage tiers behind one
client-visible name.

System namespaces such as `var/`, `etc/`, `sys/`, and `dev/` remain HTTP/CoAP
surfaces. MQTT exposes only the namespace-relative application view.

## Retained Replay

On `SUBSCRIBE sensor/#`, the adapter:

1. reads retained durable values from `home/sensor` and `home/sensor/*`,
2. sends matching non-empty retained values once with the MQTT retain flag set,
3. starts live fanout from both `tmp/` and `home/`,
4. strips the internal namespace on outbound topics.

Empty retained publishes clear replay by storing an empty `home/` value, which
is not replayed.

Retained replay preparation is fail-loud. A retained list/read failure or limit
breach rejects that MQTT filter with SUBACK failure instead of silently
pretending no retained state exists.

Retained replay is bounded per MQTT filter:

| Limit | Value |
|-------|-------|
| scanned retained worlds | `16384` |
| replayed retained messages | `4096` |
| replayed payload bytes | `16777216` |

## Live Fanout

Outbound subscription fanout is always granted as QoS 0. It sends the latest
readable world body after a change notification, not a durable per-message
queue. DELETE events do not produce MQTT publishes, and slow clients may miss
QoS 0 fanout notifications without a client-visible resync signal.

An exact MQTT filter opens two Engine listen slots: one for `tmp/` live fanout
and one for `home/` live fanout. A wildcard `topic/#` filter opens four slots:
`tmp/topic`, `tmp/topic/*`, `home/topic`, and `home/topic/*`. Real capacity is
also bounded by the Engine subscription pool.

## QoS

Inbound QoS 0, 1, and 2 publish flows are supported for live clean sessions.
QoS 2 state is connection-local and is not a persistent-session replay store
across reconnects.

| Limit | Value |
|-------|-------|
| pending QoS 2 publishes per session | `64` |
| pending QoS 2 payload bytes per session | `ELASTIK_MQTT_MAX_PENDING_QOS2_BYTES`, default `1048576` |
| outbound queue | `128` packets |
| MQTT filters per session | `64` |

## Authentication

MQTT `CONNECT` uses the password bytes as the AuditeDB token. Username-only
token auth is kept only as a legacy fallback.

| Token | Tier |
|-------|------|
| none | `Anon` |
| `ELASTIK_READ_TOKEN` | `Read` |
| `ELASTIK_WRITE_TOKEN` | `Write` |
| `ELASTIK_APPROVE_TOKEN` | `Approve` |

Bad credentials fail at CONNECT with a CONNACK failure code.

Empty client IDs are rejected; clients must supply a stable identifier. If a
new connection uses a client ID that is already connected, the older session is
closed. In-flight QoS 2 publishes in the older clean session are not persisted
until their PUBREL commit has completed.

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `ELASTIK_MQTT_HOST` | `ELASTIK_HOST` | MQTT bind host when the `mqtt` feature is enabled. |
| `ELASTIK_MQTT_PORT` | `1883` | MQTT bind port when the `mqtt` feature is enabled; set `0` to disable. |
| `ELASTIK_MQTT_MAX_PACKET_BYTES` | parsed `ELASTIK_MAX_WORLD_BYTES + 1024` | Maximum MQTT packet size accepted by the adapter. |
| `ELASTIK_MQTT_MAX_CONNECTIONS` | `1024` | Maximum concurrent MQTT TCP sessions. |
| `ELASTIK_MQTT_MAX_PENDING_QOS2_BYTES` | `1048576` | Maximum buffered, uncommitted QoS 2 payload bytes per MQTT session. |
| `ELASTIK_MQTT_CONNECT_TIMEOUT_MS` | `3000` | Maximum time an accepted TCP socket may spend waiting to send its first CONNECT packet. Increase for high-latency cellular or satellite links. |
| `ELASTIK_MQTT_MAX_PREAUTH_PER_IP` | `32` | Maximum concurrent pre-auth MQTT sockets from one source IP. Tune for NAT-heavy factory networks. |

## Metrics

When MQTT is enabled, the HTTP adapter exposes read-gated MQTT counters at
`/proc/mqtt/metrics`:

```text
mqtt_active_connections <n> snapshot
mqtt_total_connections <n> counter
mqtt_auth_failures <n> counter
mqtt_publish_failures <n> counter
mqtt_retained_publishes <n> counter
mqtt_keep_alive_timeouts <n> counter
mqtt_retained_replay_failures <n> counter
mqtt_retained_replay_messages <n> counter
mqtt_retained_replay_worlds_scanned <n> counter
mqtt_preauth_rejections <n> counter
mqtt_client_id_replacements <n> counter
mqtt_fanout_drops <n> counter
mqtt_fanout_read_failures <n> counter
mqtt_qos2_pending_messages <n> snapshot
mqtt_qos2_pending_bytes <n> snapshot
mqtt_qos2_pending_bytes_peak <n> snapshot
```
