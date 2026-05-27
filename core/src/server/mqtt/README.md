# Elastik MQTT Adapter

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
- namespace-relative client topics
- durable retained replay via Engine worlds

Rejected or intentionally absent:

- MQTT v5 properties
- persistent sessions
- Last Will
- global `#`
- `+` single-level wildcards
- client topics that explicitly include Elastik namespaces such as `home/` or `tmp/`

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

1. reads retained durable values from `home/sensor/*`,
2. sends matching non-empty retained values once with the MQTT retain flag set,
3. starts live fanout from both `tmp/` and `home/`,
4. strips the internal namespace on outbound topics.

Empty retained publishes clear replay by storing an empty `home/` value, which
is not replayed.

Retained replay is best-effort in this adapter layer. A retained list or read
failure is logged and the live subscription still proceeds; the Engine remains
the source of truth, and clients that require a strict snapshot should read the
world directly over HTTP before or after subscribing.

## Live Fanout

Outbound subscription fanout is always granted as QoS 0. It sends the latest
readable world body after a change notification, not a durable per-message
queue. DELETE events do not produce MQTT publishes, and slow clients may miss
QoS 0 fanout notifications without a client-visible resync signal.

Each accepted MQTT filter opens two Engine listen slots: one for `tmp/` live
fanout and one for `home/` live fanout. Real capacity is also bounded by the
Engine subscription pool.

## QoS

Inbound QoS 0, 1, and 2 publish flows are supported for live clean sessions.
QoS 2 state is connection-local and is not a persistent-session replay store
across reconnects.

| Limit | Value |
|-------|-------|
| pending QoS 2 publishes per session | `64` |
| pending QoS 2 payload bytes per session | `ELASTIK_MQTT_MAX_PENDING_QOS2_BYTES`, default `1048576` |
| outbound queue | `128` packets |
| MQTT filters per session | `128` |

## Authentication

MQTT `CONNECT` uses the password bytes as the Elastik token. Username-only
token auth is kept only as a legacy fallback.

| Token | Tier |
|-------|------|
| none | `Anon` |
| `ELASTIK_READ_TOKEN` | `Read` |
| `ELASTIK_WRITE_TOKEN` | `Write` |
| `ELASTIK_APPROVE_TOKEN` | `Approve` |

Bad credentials fail at CONNECT with a CONNACK failure code.

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `ELASTIK_MQTT_HOST` | `ELASTIK_HOST` | MQTT bind host when the `mqtt` feature is enabled. |
| `ELASTIK_MQTT_PORT` | `1883` | MQTT bind port when the `mqtt` feature is enabled; set `0` to disable. |
| `ELASTIK_MQTT_MAX_PACKET_BYTES` | parsed `ELASTIK_MAX_WORLD_BYTES + 1024` | Maximum MQTT packet size accepted by the adapter. |
| `ELASTIK_MQTT_MAX_CONNECTIONS` | `1024` | Maximum concurrent MQTT TCP sessions. |
| `ELASTIK_MQTT_MAX_PENDING_QOS2_BYTES` | `1048576` | Maximum buffered, uncommitted QoS 2 payload bytes per MQTT session. |
