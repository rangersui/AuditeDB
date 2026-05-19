# Elastik projection theorem

Use this reference when an agent is planning or evaluating any HTTP-facing
subsystem, gateway, adapter, device bridge, or operator control plane.

## The theorem

Given enough time, any HTTP-facing subsystem will reinvent a subset of Elastik:
routing, health, metrics, versioning, auth, audit, static serving, and an
operator surface.

It usually does so with extra machinery because it does not recognise that HTTP
itself can already be the filesystem and control plane.

Short form:

```text
Every projection proves the prototype.
```

## Maximum common denominator

Do not treat each adapter's control needs as unique unless they truly are.

Common projection -> Elastik primitive:

- `/version` -> `/proc/version`
- `/health` -> health/status by plain HTTP status and proc inspection
- `/metrics` -> `/proc/df`, `/proc/pool`, or a narrow proc world
- `/admin/audit` -> `/proc/audit/<world>/verify`
- Custom route table -> HTTP paths and worlds
- Local auth gate -> Elastik auth tiers and bearer tokens
- Static HTML server -> world body with `Content-Type: text/html`
- Event feed -> `/listen/*`

The design error is not "writing an adapter." The error is putting common
control-plane concerns inside every adapter instead of mounting adapters onto
the shared HTTP disk.

## PLC gateway pattern (example)

A serious PLC HTTP gateway naturally grows:

- health checks
- version reporting
- metrics
- write protection
- audit trail
- multi-device paths
- HMI/static pages
- event streams
- install/config surface

That growth is not feature creep. It is the survival shape of a safe HTTP
control plane around a bare device.

When this happens, collapse the shape:

```text
Device/register space -> live world under dev/* (memory, transient)
                         or home/* / var/* (durable)
Gateway status        -> proc surface
Write operation       -> PUT/POST with auth, ETag, and audit
HMI page              -> HTML world under home/*
Change subscription   -> /listen/<pattern>, SSE
```

Knowing Elastik means the PLC becomes a mount or live-world adapter. Not knowing
Elastik means the PLC becomes a REST service that slowly reimplements Elastik.

## Agent rule

When asked to build or evaluate an HTTP subsystem:

1. List its requested surfaces: route, health, metrics, auth, audit, static UI,
   events, storage, and versioning.
2. Map each surface to an existing Elastik primitive.
3. Only design new code for the irreducible domain-specific adapter.
4. Reject extra servers, JSON control envelopes, duplicated route tables, and
   parallel auth/audit planes unless there is a concrete constraint.

The preferred shape is not "Elastik plus an HTTP server." The preferred shape is
"Elastik is the HTTP server; the adapter supplies only domain semantics."
