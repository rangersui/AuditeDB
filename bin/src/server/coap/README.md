# AuditeDB CoAP Adapter

The CoAP adapter is a UDP binary surface over the Engine. It exists for
constrained clients that want the same world model without speaking HTTP.

Engine rules live in the top-level [`README.md`](../../../../README.md). HTTP
startup and `/proc/*` live in [`../http/README.md`](../http/README.md).

## Scope

CoAP maps a small subset of protocol requests onto the Engine. It is an
adapter skin, not a separate store or policy layer.

Implemented:

- `GET` -> Engine `read`
- `PUT` -> Engine `replace`

Not implemented yet:

- `POST` -> returns Method Not Allowed
- `DELETE` -> returns Method Not Allowed

Use HTTP when you need browser rendering, `/proc/*` management views, or
straight curl debugging. Use CoAP when UDP and small client stacks matter.

## Auth

CoAP authentication is experimental. Critical option `65001` carries the raw
AuditeDB token bytes, equivalent to the HTTP bearer token value without the
`Bearer ` prefix. Absence of option `65001` means `Anon`; a matching configured
token yields `Read`, `Write`, or `Approve`.

This option is not encryption and is not a CoAPS replacement. Use CoAPS,
DTLS-PSK, or another trusted edge if the token must not be visible on the wire.

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `ELASTIK_COAP_HOST` | `127.0.0.1` | CoAP bind host when CoAP is enabled. |
| `ELASTIK_COAP_PORT` | unset | Enables the CoAP UDP surface on this port. |
| `ELASTIK_COAP_MAX_IN_FLIGHT` | `1024` | Maximum concurrent CoAP requests. |

Shared Engine and auth environment variables are documented in
[`../http/README.md`](../http/README.md), because the HTTP adapter is also the
default binary startup surface.
