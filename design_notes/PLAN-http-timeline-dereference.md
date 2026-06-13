# PLAN: HTTP Timeline Dereference

> Addendum to `path3-precondition-challenge.md`.
> Scope: the HTTP adapter contract for reading a body by the timeline
> coordinate emitted by `/listen/*`.

## 1. Frame Being Tested

Path 3 made subscribe useful by giving change notifications a durable
coordinate:

```text
TimelineCoordinate = { world, gen, seq, body_sha256 }
```

The HTTP adapter needs a wire shape for clients that have those fields but do
not have Rust's proof-bearing `TimelineAddress` type. The adapter must classify
timeline intent before dispatch, validate wire fields at the boundary, ask core
to prove the coordinate against the audit row, and then return that historical
body. It must never silently fall back to `GET current`.

The v1 request target is an explicit timeline mode on the world URL:

```http
GET /home/task/a?timeline=1&timeline-generation=<32hex>&timeline-seq=<positive-i64>&timeline-body-sha256=<64hex>
HEAD /home/task/a?timeline=1&timeline-generation=<32hex>&timeline-seq=<positive-i64>&timeline-body-sha256=<64hex>
```

No new top-level route is reserved. A world that used shorthand
`/timeline/foo` continues to mean the ordinary world `home/timeline/foo`.
The requested world remains the path. The query supplies only the remaining
coordinate fields.

## 2. Precondition Challenge

| Assumption | Physics or policy | Decision |
|---|---|---|
| Historical reads need a new top-level route. | Policy. | Rejected for v1. A query mode on the existing world URL avoids stealing `home/timeline/*` shorthand. |
| `timeline=1` can be the only signal of timeline intent. | Policy and unsafe. | Rejected. Any `timeline-*` coordinate field is also timeline-looking. Timeline-looking requests must never fall through to current reads or writes. |
| Timeline query keys can be classified as raw bytes. | Policy and unsafe. | Rejected. The adapter must decode into ordered query pairs once, then classify duplicate and unknown keys after decoding. |
| Query parsing can live only in GET/HEAD handlers. | Policy and unsafe. | Rejected. Method gating must happen before write dispatch so `PUT /home/a?timeline=1...` cannot mutate the current world. |
| `TimelineCoordinate` can be passed directly to `read_timeline_body`. | Policy and violates the seal. | Rejected. `TimelineCoordinate` proves wire syntax only. Core needs a resolver gate that verifies the event row and mints a proof-bearing `TimelineAddress` only on the verified branch. |
| Coordinate failure states can reuse `TimelineRead`. | Policy and violates the seal. | Rejected. Current `TimelineRead` variants carry `TimelineAddress`. Pre-proof failures must use a separate coordinate-result shape. |
| Missing retained bytes always mean the value expired. | Policy and unsafe. | Rejected. V1 treats missing promised bytes without pruning proof as corruption; future retention states need the proofs required by `PLAN-cas-body-schema.md`. |
| Missing subject files prove timeline `Gone`. | Policy and unsafe. | Rejected. Physical absence is only absence. `Gone` needs delete-ledger or derived-index proof bound to the requested coordinate. |
| The current delete ledger proves every historical sequence in a deleted world. | Policy and false. | Rejected. It currently proves the final subject coordinate only. Earlier coordinates need a future derived index or remain unproven. |
| V1 should scan `var/log/deletes` on every HTTP dereference. | Policy and unsafe. | Rejected. Delete proof is out of v1 until there is a bounded / indexed lookup path. |
| `Expired` / `NeverRetained` are v1 HTTP outcomes. | Policy and not yet falsifiable. | Rejected for v1. They become HTTP outcomes only after a retention/pruning proof layer exists. |
| Historical responses should reuse current-world `ETag`. | Policy and unsafe before an ETag split. | Rejected. `body_sha256` is content identity, not write-position identity. v1 historical reads do not emit `ETag`. |
| Range and conditional GET must work immediately. | Policy. | Rejected for v1. The first route returns the addressed full body or a typed absence/error. Range and cache validators can be a later layer after historical ETag semantics are designed. |

### Residual Physics

- The HTTP request target is split across path and query. If the pipeline drops
  the query, the adapter cannot distinguish timeline intent from current reads.
- The Rust type seal is real: an untrusted coordinate cannot become a
  `TimelineAddress` unless core verifies the matching event row.
- The subject world can be physically gone. That fact alone proves nothing about
  a requested coordinate; deletion facts must come from `var/log/deletes` or a
  derived index that binds the requested world, generation, sequence, and body
  hash. V1 does not scan that ledger from HTTP; `Gone` waits for a bounded /
  indexed delete-proof layer.
- Storage is finite, so retained CAS bytes can be unavailable for different
  reasons that must not collapse into one false `Expired` state. In v1, without
  pruning proof, a missing promised CAS body is corruption rather than expiry.
- HTTP `OPTIONS` is answered without executing a read or write. It can describe
  the world resource without dereferencing a timeline coordinate.

The remaining hard problem is therefore not "how do we parse a query string".
It is "how do we classify timeline-looking request targets before dispatch and
preserve the proof boundary after classification".

## 3. HTTP Wall

The route still matches `/{*world}`, but the request target must enter the FSM
with its query string intact. The minimal shape is:

```text
world_handler(method, path, raw_query, headers, body)
  -> if method == OPTIONS: return existing route-level OPTIONS response
  -> pipeline::run(method, path, raw_query, headers, body, state, req_id)

pipeline:
  raw path -> ValidatedWorldPath
  raw query + ValidatedWorldPath -> TimelineRequestMode
  TimelineRequestMode + method -> dispatch or typed error
```

The classifier operates on percent-decoded ordered query pairs, not on raw query
text and not on a lossy map. Duplicate detection happens after decoding, so
`timeline%2dgeneration` and `timeline-generation` are the same key for
classification. Malformed percent encoding is a `400 Bad Request`.

The parser must be bounded without making timeline parsing an untracked route
side channel. V1 sets an explicit adapter contract: non-`OPTIONS` world
requests accept at most 8192 raw query bytes. Over-cap raw queries return `414
URI Too Long` through the pipeline's closed error vocabulary. Within that cap,
ordinary current reads that carry unrelated query strings keep today's behavior:
the query is ignored unless a decoded control key is `timeline` or starts with
`timeline-`. Queries under the cap are decoded as a bounded stream:

- if no decoded key is `timeline` or starts with `timeline-`, classification is
  `Current` and unrelated query pairs are ignored as they are today;
- once any decoded `timeline` / `timeline-*` key appears, the query is in the
  timeline-control namespace. Only `timeline` plus exactly three coordinate
  fields are accepted. In that namespace, the fifth decoded pair of any key is
  a `400 Bad Request` before unbounded allocation can grow.

`OPTIONS` is the exception to query parsing. It stays at the existing route
boundary, before query decoding and before timeline-mode classification.
`OPTIONS /home/a?timeline=1`, incomplete timeline queries, and even malformed
percent escapes all receive the ordinary world-route `OPTIONS` response and
execute no dereference. Timeline-mode query validation applies to non-OPTIONS
methods only.

After path validation and before verb dispatch, the pipeline classifies read
mode:

```text
enum TimelineRequestMode {
    Current,
    Timeline(TimelineCoordinate),
}
```

Classification rules:

```text
no timeline key and no timeline-* keys
  -> Current

timeline=1 and exactly timeline-generation, timeline-seq, timeline-body-sha256
  -> Timeline(TimelineCoordinate)

any timeline-* key without timeline=1
  -> 400 timeline coordinate requires timeline=1

timeline present but not exactly timeline=1
  -> 400 invalid timeline mode

duplicate timeline key
  -> 400 duplicate timeline mode

timeline=1 with any missing coordinate field
  -> 400 missing timeline coordinate field

timeline=1 with duplicate coordinate fields
  -> 400 duplicate timeline coordinate field

timeline=1 with any unknown timeline-* field
  -> 400 unknown timeline coordinate field

timeline=1 with any extra non-timeline query field
  -> 400 unsupported timeline query field

timeline=1 with timeline-world
  -> 400 timeline world comes from the path

timeline=1 on a non-durable world such as tmp/*, dev/*, or sys/*
  -> 400 timeline coordinates require durable worlds

timeline=1 with malformed generation / seq / body sha256
  -> 400
```

Malformed generation and body hash values can use the reason from
`InvalidTimelineCoordinate`. `timeline-seq` has two layers: non-integer or
overflowing decoded values fail in the HTTP query parser; parsed non-positive
integers fail through `InvalidTimelineCoordinate::SeqNonPositive`.

The world comes from the path. `timeline-world` is never accepted as query
state, because accepting it would allow one request to name two worlds.

Dispatch rules:

```text
Current + GET/HEAD/PUT/POST/DELETE -> existing world verbs
Timeline + GET                     -> timeline dereference GET
Timeline + HEAD                    -> timeline dereference HEAD
Timeline + any non-GET/HEAD/OPTIONS method
                                    -> 405 Allow: GET, HEAD, OPTIONS
```

`OPTIONS` remains the existing policy-free world-route response. The query is
not dereferenced for `OPTIONS`; it advertises the world resource's ordinary
method affordance and executes no timeline operation. This is deliberately
different from the `405` emitted after timeline-mode classification: `OPTIONS`
describes the world route, while a rejected timeline-mode verb advertises the
timeline dereference submode.

`Range`, `If-None-Match`, and `If-Range` do not apply in v1 timeline mode. They
must not change the result into a current read, and successful historical
responses must not advertise `Accept-Ranges` or `ETag`.

## 4. Type Seal

The adapter boundary parses:

```text
path world + query fields -> TimelineCoordinate
```

`TimelineCoordinate` is not a read permit. The resolver entrypoint must preserve
the existing read permit seal, for example through `world_read_ops` with
`&ReadPermit` plus `&TimelineCoordinate`, or through an `Engine` method that
authorizes read access before calling the resolver. A convenient internal helper
that accepts only `TimelineCoordinate` would bypass the read proof even if it
later verifies the event row.

A core resolver must then perform the timeline proof transition:

```text
TimelineCoordinate
  -> subject DB exists, its audit chain verifies intact, and actual generation
     differs from requested generation
     -> mint VerifiedGenerationMismatch and return GenMismatch before row lookup
  -> live body-bearing event row proves world + generation + sequence + body hash
     -> mint TimelineAddress
     -> read retained body through a resolver-specific path that cannot map
        physical absence to address-bearing Gone
  -> live event row exists but is not body-bearing
     -> mint VerifiedNonBodyEvent and return NonBodyEvent
  -> event row exists but body hash differs from the requested coordinate
     -> mint VerifiedAddressMismatch and return AddressMismatch
  -> verified subject DB and generation exist, but the requested seq is absent
     -> mint VerifiedMissingRow and return MissingRow
  -> event row shape is impossible or malformed after chain verification
     (wrong target, invalid stored body hash, unknown event type, etc.)
     -> return Corrupt
  -> no subject DB, or no available bounded/indexed proof can bind the
     requested coordinate
     -> return UnprovenCoordinate
```

If the subject file is physically absent and no exact delete proof exists, the
resolver has not proved `Gone`. It has only failed to prove the coordinate from
the available indexes, so the result must stay `UnprovenCoordinate`.

The proof transition must be snapshot-bound. Generation verification, audit-chain
verification, row classification, body-hash comparison, and retained-CAS lookup
must run in one `TrackedReadConnection` read transaction, or an equivalent
transaction-scoped proof object must be carried into the retained-body read.
Splitting these steps across independent SQLite snapshots reopens a race where
the resolver proves one row and reads bytes from another state.

Because several failures can occur before an address or delete fact is proven,
the resolver must not return `TimelineRead` directly. It needs a separate shape
such as:

```text
TimelineDereferenceV1 =
    Body(TimelineBody)                  // contains verified TimelineAddress
  | GenMismatch(VerifiedGenerationMismatch)
  | AddressMismatch(VerifiedAddressMismatch)
  | NonBodyEvent(VerifiedNonBodyEvent)
  | MissingRow(VerifiedMissingRow)
  | UnprovenCoordinate(TimelineCoordinate)
  | Corrupt { coordinate: TimelineCoordinate, reason: TimelineCorruption }
```

The exact Rust names can change, but the proof rule cannot:

- only variants whose event row has been verified may carry `TimelineAddress`;
- verified negative historical facts are proof values too. `GenMismatch`,
  `AddressMismatch`, `NonBodyEvent`, and `MissingRow` must use opaque
  private-field proof structs or private resolver-only constructors. A raw
  `TimelineCoordinate` is syntax, not proof;
- `GenMismatch` requires an intact subject audit-chain verification before the
  resolver returns `409`; tampered worlds fail loud as corruption / storage, not
  as harmless generation mismatch;
- `NonBodyEvent` is distinct from `MissingRow` and `Corrupt`: the row exists and
  the chain is intact, but the event class does not carry a body;
- `AddressMismatch` is distinct from `MissingRow` and `Corrupt`: the row exists,
  but its body hash disagrees with the requested coordinate, so the resolver
  must stop before any CAS lookup;
- retention states (`NeverRetained`, `Expired`) are not v1 HTTP outcomes. They
  require a verified address plus the retention / pruning proof described in
  `PLAN-cas-body-schema.md`;
- deletion states are not v1 HTTP outcomes. They require a bounded delete-ledger
  or derived-index proof that binds the exact requested coordinate, not just the
  path;
- pre-proof variants carry `TimelineCoordinate` or another non-proof request
  type and must not map to a historical fact they cannot prove.

`DeletedTimelineProof` must follow the same seal pattern as `TimelineAddress`:
opaque fields, no public raw constructor, and a single checked construction
path. That proof type is out of v1. A future layer may add it only with a
bounded / indexed lookup path. When added for the current delete ledger, its
constructor may only accept an HMAC-verified `var/log/deletes` `delete_commit`
row with `event_type == delete_commit`, row `target == coordinate.world`, row
`body_sha256 == coordinate.body_sha256`, and reserved subject world,
generation, sequence, and body hash matching the same coordinate. The reserved
subject HMAC is not part of `TimelineCoordinate`; the constructor must instead
verify exactly one `auditedb-delete-subject-hmac` header with value `hmac-` plus
64 lowercase hex characters, covered by the verified delete-commit row. It must
reject `delete_intent`, `delete_commit_failed`, missing subject headers,
duplicate subject headers, malformed / uppercase / raw subject HMAC forms,
tampered event headers, row/header disagreement, and non-final-coordinate
matches. The current delete ledger can only prove `Gone` for the deleted
incarnation's final coordinate; an earlier sequence in the same deleted world
remains `UnprovenCoordinate` until a derived index exists.

If any handler can call a body read with `TimelineCoordinate` directly, or can
reuse the existing absence-based `TimelineRead::Gone` as delete proof, the seal
failed.

## 5. Result Mapping

The HTTP route maps the resolver outcome without substituting current state.

| Resolver result | HTTP status | Body |
|---|---:|---|
| `Body` | 200 | historical body bytes |
| `Body` via `HEAD` | 200 | empty |
| `GenMismatch` | 409 | text reason |
| `AddressMismatch` | 409 | text reason |
| `NonBodyEvent` | 404 | text reason |
| `MissingRow` | 404 | text reason |
| `UnprovenCoordinate` | 404 | text reason |
| `Corrupt` | 500 | text reason |
| missing / invalid auth | 401 | existing read-token response |
| authenticated but insufficient tier | 403 | new typed forbidden response, if this layer splits auth causes |
| raw query over chosen cap | 414 | typed URI-too-long / request-target-too-large response |
| transient storage | 503 | existing retryable storage response |
| insufficient storage | 507 | existing insufficient-storage response |
| other storage/internal failure | 500 | existing storage failure response |

`HEAD` preserves the same status and headers but never returns a response body,
including absence and error responses.

The live adapter currently collapses auth failures to `401`. If timeline
dereference splits missing / invalid credentials from authenticated-but-too-low
tier, the same implementation layer must add the concrete `403 Forbidden`
response helper and closed reason variant. If that split is not implemented in
the layer, timeline auth must stay aligned with the existing `401` AuthGate
handling rather than documenting a status the adapter cannot emit.

Every non-200 timeline failure must map to a closed `pipeline::ErrorReason`
variant or a new typed variant added in the same implementation layer. Do not
emit ad hoc strings that bypass the existing trace / metrics vocabulary.

Successful historical responses include:

```text
Content-Type
Content-Length
X-Timeline-World
X-Timeline-Generation
X-Timeline-Seq
X-Timeline-Body-Sha256
persisted metadata headers, after the normal output denylist
```

`X-Timeline-*` response headers are core-owned proof headers. Persisted metadata
must not be able to spoof or duplicate them. The implementation must add the
timeline proof-header names to the hard output denylist, or otherwise filter
persisted metadata before appending trusted timeline headers so the final
response contains exactly one value for each `X-Timeline-*` proof header.

They do not include:

```text
ETag
Accept-Ranges
Link: rel="monitor"
```

The monitor link belongs to current-world reads. Historical dereference is a
point lookup for one coordinate, not a live subscription target.

## 6. Falsifying Counterexamples

### Counterexample A: Stray Coordinate Falls Through

```http
GET /home/config?timeline-generation=G&timeline-seq=42&timeline-body-sha256=H
```

If this returns the current body, the route failed. The request is
timeline-looking and malformed. Correct result: `400 Bad Request`.

### Counterexample B: Timeline Mutation

```http
PUT /home/config?timeline=1&timeline-generation=G&timeline-seq=42&timeline-body-sha256=H
```

If this mutates `home/config`, the route failed. The timeline mode was explicit
before dispatch. Correct result: `405 Method Not Allowed`.

### Counterexample C: World Mismatch Smuggling

```http
GET /home/a?timeline=1&timeline-world=home/b&timeline-generation=G&timeline-seq=1&timeline-body-sha256=H
```

If the route accepts `timeline-world`, the route failed. The path is the world.
No second world identity is allowed in query state.

### Counterexample D: Coordinate Used As Proof

If code can express:

```rust
engine.read_timeline_body(&coordinate, tier)
```

or any equivalent raw-coordinate body read, the route failed. The coordinate
must go through a resolver that verifies the event row and mints
`TimelineAddress` only on the verified branch.

### Counterexample E: Historical Read Emits Current ETag

If a historical read of seq 1 after seq 2 returns seq 2's ETag, the route
failed. If it emits `sha256-...` as an ETag without a separate position
validator design, the route also failed.

### Counterexample F: Missing File Pretends To Prove Gone

```http
GET /home/config?timeline=1&timeline-generation=G&timeline-seq=42&timeline-body-sha256=H
```

If `home/config` is physically absent but no delete-ledger row or derived index
proves that exact coordinate, the route must not return `410 Gone`. It can
return an unproven / missing-coordinate result, but the absence of
`universe.db` is not a timeline fact.

### Counterexample G: MissingRow vs UnprovenCoordinate

```text
case 1: subject DB exists, generation matches, seq 42 is absent
case 2: subject DB is gone and no bounded/indexed proof binds seq 42
```

If both cases collapse to the same internal resolver variant, the resolver
failed. Case 1 is `MissingRow`; case 2 is `UnprovenCoordinate`. Both may map to
HTTP `404`, but tests must assert the internal distinction before wire mapping.

### Counterexample H: Wrong Body Hash For Existing Row

```text
events.seq=42 has body_sha256=A
client asks for body_sha256=B
```

If the resolver returns `MissingRow`, `Corrupt`, or performs a CAS lookup for
`B`, the resolver failed. Correct result: typed `AddressMismatch` before CAS
lookup, mapped to `409 Conflict`.

### Counterexample I: Generation Mismatch Precedes Row Lookup

```text
subject DB exists with actual generation A
client asks for generation B
```

If the resolver checks event rows before returning `GenMismatch`, the resolver
failed only after the subject audit chain has verified intact. V1 has no
delete-proof lookup, so live generation mismatch is decided before requested-seq
lookup. A future bounded/indexed delete-proof layer may place exact delete proof
ahead of this branch.

### Counterexample J: Non-Body Event Does Not Mint Body Address

```text
events.seq=42 is delete_commit
client asks for seq 42 with the row body_sha256
```

If the resolver mints `TimelineAddress` or reports corruption only because the
row is non-body-bearing, the resolver failed. Correct result: typed
`NonBodyEvent`.

### Counterexample K: Delete Ledger Overclaims History

```text
seq 1 = B
seq 2 = C
delete records final coordinate seq 2 / C
client asks for seq 1 / B
```

If v1 returns `410 Gone` for seq 1 from the final-coordinate delete proof, the
resolver failed. The current delete ledger proves the final coordinate only.
Earlier coordinates require a future derived index or remain
`UnprovenCoordinate`.

### Counterexample L: V1 Does Not Scan The Delete Ledger

```text
var/log/deletes contains delete_commit for subject seq 2 / C
client asks for seq 2 / C
```

If v1 performs an unbounded scan of `var/log/deletes` on the GET path or returns
`410 Gone`, the resolver failed. Delete proof is a later layer that needs a
bounded / indexed lookup path first.

### Counterexample M: OPTIONS Does Not Decode Timeline Query

```http
OPTIONS /home/config?timeline%ZZ=1
```

If this enters timeline query classification or returns malformed-query `400`,
the route failed. `OPTIONS` stays policy-free at the world route and does not
decode query state.

### Counterexample N: Duplicate Mode Collapse

```http
GET /home/config?timeline=1&timeline=0&timeline-generation=G&timeline-seq=42&timeline-body-sha256=H
```

If a map-style parser collapses this to either `timeline=1` or `timeline=0`,
the route failed. Correct result: `400 Bad Request`.

### Counterexample O: Query Cap Is Enforced

```http
GET /home/config?timeline=1&timeline-generation=G&timeline-seq=42&timeline-body-sha256=H&x=1
```

If a fifth decoded pair is stored in an unbounded map or ignored, the route
failed. Correct result: `400 Bad Request`. If the raw query exceeds the chosen
request-target / local cap, the route must return `414 URI Too Long`.

```http
GET /home/config?a=1&b=2&c=3&d=4&e=5
```

If unrelated non-timeline query parameters trigger the fifth-pair timeline
error, the route broke current-read compatibility. Correct result: classify as
`Current` after bounded inspection, because no decoded key is `timeline` or
starts with `timeline-`.

### Counterexample P: Encoded Key Bypasses Timeline Wall

```http
GET /home/config?timeline=1&timeline%2dgeneration=G&timeline-seq=42&timeline-body-sha256=H
```

If raw-key classification misses `timeline%2dgeneration` and returns a current
body or a missing-field error inconsistent with the decoded duplicate/known-key
rules, the route failed. The query classifier operates on decoded ordered pairs.

### Counterexample Q: Persisted Metadata Spoofs Timeline Proof Headers

```http
PUT /home/config
X-Timeline-Seq: 999

body
```

If a later historical response contains both the trusted `X-Timeline-Seq` and
the persisted fake value, whether because an operator allowlisted `x-timeline-*`
or because a poisoned stored header row already exists, the proof headers are
ambiguous. Correct result: persisted metadata is filtered so the final response
contains exactly one core-owned `X-Timeline-*` value, minted by the dereference
path.

### Counterexample R: Corrupt Row Shape Is Not A 404

```text
verified chain reaches seq 42, but the stored row has target != requested world
or an invalid body_sha256 shape
```

If this maps to `MissingRow` or `UnprovenCoordinate`, the resolver hid corruption
as absence. Correct result: `Corrupt` -> `500`.

### Counterexample S: HEAD Error Bodies Leak

```http
HEAD /home/config?timeline=1&timeline-generation=bad&timeline-seq=42&timeline-body-sha256=bad
```

If the response status is `400`, `404`, `409`, or `500` but the HTTP body is the
same text emitted for `GET`, the route violated HEAD parity. Correct result:
same status and headers as GET, no response body.

### Counterexample T: Malformed Sequence Value

```http
GET /home/config?timeline=1&timeline-generation=G&timeline-seq=not-an-int&timeline-body-sha256=H
```

If this reaches `TimelineCoordinate::from_wire_parts`, the parser boundary
failed. Non-integer and overflowing sequence values fail in HTTP query parsing;
only parsed non-positive integers reach `InvalidTimelineCoordinate`.

### Counterexample U: Memory World Timeline Request

```http
GET /tmp/config?timeline=1&timeline-generation=G&timeline-seq=42&timeline-body-sha256=H
```

If this falls through to current `tmp/config` semantics, the route failed.
Timeline coordinates are durable-world coordinates. Correct result:
`400 Bad Request`.

## 7. Implementation Order

1. Add a core resolver result type that separates pre-proof coordinate failures
   from verified-address outcomes. `Gone`, `Expired`, and `NeverRetained` stay
   out of v1 until bounded delete / retention proof layers exist. Verified
   negative outcomes must be sealed proof values or private resolver-only
   constructors, not freely constructible enum variants carrying raw
   coordinates.
2. Add a core resolver that accepts `TimelineCoordinate`, verifies the event
   row, and only then mints `TimelineAddress`. Preserve the existing
   `ReadPermit` seal at this entrypoint, and do not reuse the existing
   absence-based `TimelineRead::Gone` path as delete proof. Keep chain
   verification, row classification, hash comparison, and retained-CAS lookup
   in one SQLite read transaction / transaction-scoped proof.
3. Thread the HTTP query string through the route into the FSM as raw
   request-target data. Preserve the existing route-level `OPTIONS` short-circuit
   before query decoding.
4. Add a small HTTP timeline-mode classifier inside the pipeline after
   `ValidatedWorldPath` construction and before verb dispatch. It applies the
   8192-byte raw-query cap, decodes into ordered pairs, detects duplicates after
   decoding, and produces `Current`, `Timeline(TimelineCoordinate)`, typed `400`
   / `414` reasons, or the timeline-mode `405` for every non-GET/HEAD/OPTIONS
   method. New reasons must be closed `pipeline::ErrorReason` variants, not ad
   hoc strings.
5. Wire GET / HEAD timeline mode through a dedicated read branch, running
   SQLite / filesystem work through `spawn_blocking` at the binary adapter
   boundary, and map resolver outcomes to the statuses above.
6. Add SDK helpers only after the raw HTTP route is proven.

Each item should be its own stacked PR unless the diff is tiny enough that the
review surface stays plainly one concern.

## 8. Endpoint Checklist Gates

Each implementation PR that changes the HTTP adapter for this feature must
record the AGENTS endpoint checklist result:

- happy-path GET and HEAD dereference tests;
- malformed query tests for missing, duplicate, unknown, malformed-percent,
  duplicate-after-decoding, encoded `timeline` and each encoded `timeline-*`
  coordinate key, non-integer/overflowing sequence, non-positive sequence (`0`
  and `-1`), non-durable-world coordinate fields, unrelated non-timeline query
  compatibility, and raw-query cap saturation returning `414`;
- route-topology tests proving no `/timeline/*` route is introduced,
  `/timeline/foo` remains the ordinary `home/timeline/foo` world path, and `/`,
  `/listen/*`, `/proc/*`, `/proc/audit/*`, and `/proc/{*reserved}` keep their
  existing ownership ahead of `/{*world}`;
- `OPTIONS` tests proving timeline-looking and malformed-percent queries still
  receive the ordinary world-route `OPTIONS` response without query decoding;
- method-wall tests for timeline-mode `PUT`, `POST`, `DELETE`, and at least one
  unsupported method such as `PATCH`;
- conditional / range request-header tests proving timeline mode ignores
  `Range`, `If-None-Match`, and `If-Range` for v1: no `304`, `206`, `416`,
  current-world ETag, or partial historical body;
- proof-state tests for `GenMismatch` after intact audit-chain verification,
  `AddressMismatch`, `NonBodyEvent`, `MissingRow`, `UnprovenCoordinate`,
  malformed/corrupt event-row shape, internal distinction before HTTP mapping
  when two states share status, and explicit proof that v1 does not scan the
  delete ledger or emit `Gone`;
- denied/error coverage for missing / invalid auth (`401`), and either
  insufficient-tier `403` with a newly added forbidden response helper or
  explicit alignment with the current `401` AuthGate behaviour;
- HEAD absence/error parity tests for `400`, `404`, `409`, and `500`: same
  status and headers as GET, no response body;
- resource-bound evidence that filesystem / SQLite work runs through
  `spawn_blocking`;
- header tests proving persisted metadata headers pass through the normal output
  denylist and historical success responses suppress `ETag`, `Accept-Ranges`,
  and `Link: rel="monitor"`; these tests must also prove persisted metadata
  cannot spoof or duplicate any `X-Timeline-*` proof header;
- resource-cap evidence or explicit rationale for route-local query decoding,
  delete-ledger / derived-index scans, queues, buffers, and response bodies,
  including the 8192-byte raw-query cap, decoded-pair cap, saturated-path status, and
  test evidence where applicable;
- closed-error-vocabulary evidence for any new timeline parse / dereference
  failure reason added to `pipeline::ErrorReason`;
- README / API docs parity for the new query mode, statuses, response headers,
  and output shape;
- `.env.example` parity for any new environment variable, or an explicit
  no-new-env rationale.

## 9. Review Ledger Requirements

The implementation PR body for each layer must record:

- base branch / prior layer;
- exact section of this plan implemented;
- production-line diff size;
- commands run;
- scientist reviewers and QA/enforcement reviewer;
- confirmed P0-P2 findings, fixes, and the fresh clearing round;
- verifier evidence for any confirmed P0-P2 finding;
- P3 disposition: fixed immediately or explicitly ledgered as accepted debt.

The design PR body must also record the design-review ledger. This document is
the contract being reviewed; the PR body is the durable review artifact so that
fresh reviewers do not have to read prior reviewer judgments while reviewing
the plan itself.
