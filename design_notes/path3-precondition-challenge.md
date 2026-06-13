# Path 3 Precondition Challenge

> Design note for the Subscribe/Timeline CAS work.
> Scope: mandatory AGENTS.md Precondition Challenge for Path 3.

## 1. Frame Being Tested

Path 3 says:

```text
notification carries an address
chain rows are the timeline
CAS dereferences body hashes
read(TimelineAddress) is the race-killer
```

The old half-state was worse than either clean alternative:

```text
notification has id + ring + Last-Event-ID
notification does not carry body
storage has no durable timeline read
```

That tells a client "B happened", then forces it to `GET current`, where
it may read C. B is gone. The notification looked like an event stream
but behaved like a hint.

## 2. Hidden Assumptions

| Assumption | Physics or policy | Decision |
|---|---|---|
| Subscribers need every changed body pushed to them. | Policy. | Dissolved. AuditeDB is a storage engine; push is a signal. Bodies are fetched by address. Small body inlining is an optimisation, not the contract. |
| A notification without body is useless. | Policy, unless there is no historical read. | Dissolved by a full timeline-address read: `(world, gen, seq, body_sha256)`. The address makes the signal meaningful without making subscribe a delivery broker. |
| Durable history requires storing every body forever. | Policy over finite-storage physics. | Dissolved. Chain rows are permanent; CAS bodies are retained by policy. Expiry must be provable by a durable expiry marker, GC watermark, or equivalent retention proof. Without that proof, a missing CAS body is corruption/missing-body, not Expired. |
| SSE ids must be small or integer-like. | Policy. | Dissolved. The parent plan's stale `12-hex` wording is superseded before any Path 3 cursor implementation. `gen` must be a minted incarnation id with at least 128 bits of entropy, rendered as 32 hex chars. It is not a deterministic first-event HMAC. SSE `id` is an opaque string; cursor readability is secondary. |
| `body_sha256` should become the HTTP ETag because CAS exists. | Policy and unsafe by default unless a separate position validator lands. | Rejected for initial Path 3. ETag remains chain-position identity (`hmac-{event_hmac}`) until an ETag-split stack lands with an explicit position validator. `body_sha256` is the CAS/content address exposed separately. |
| The engine should track per-subscriber delivery state. | Policy. | Rejected. The engine stores timeline facts and emits best-effort signals. Clients keep notebooks/cursors. Pattern catch-up is a client-side vector over matched worlds, not a scalar SSE id. |
| Delete replay requires the deleted world's file to survive. | Policy. | Dissolved through `var/log/deletes`. Path 3 must make ledger rows ordinary ledger-sequenced/notifying chain rows that carry the deleted subject's `gen` and final coordinate. Until that lands, current code only writes ledger rows and live-notifies the subject world. Exact-world and pattern catch-up must consult the ledger, or use an SDK catch-up helper that does. |

## 3. Residual Physics

After dissolving the policy assumptions, the remaining hard constraints are:

- storage is finite, so CAS bodies need retention and may expire;
- network delivery is lossy, so subscribe remains best-effort notification;
- SQLite files can be physically deleted, so delete facts live in the ledger
  world, not in the removed world; Path 3 must make that ledger world the
  replayable delete stream and include the deleted subject's incarnation
  identity;
- world timelines are independent, so there is no global total order and no
  scalar cursor can prove pattern catch-up across worlds;
- migration changes on-disk meaning, so format markers must fail loudly;
- historical reads can prove chain-row presence, but cannot resurrect pruned
  bodies;
- historical reads cannot classify missing CAS bodies as expired unless GC left
  durable expiry proof or a retention watermark covering that body address;
- addressable timeline catch-up and historical value recovery are different:
  Path 3 guarantees "do not silently read current C for signalled B"; it does
  not guarantee B's body remains recoverable after retention expiry.

These are the constraints worth optimising. The plan should not optimise
inside "subscribers cannot fetch the value that was signalled"; that is a
policy failure, not physics.

## 4. Falsifying Counterexamples

### Counterexample A: B Signal, C Read

```text
t1: write config = B, notify id=42
t2: write config = C, notify id=43
t3: client receives id=42 and GETs /config
```

Old design: client reads C and cannot recover B.

Path 3 must make this exact case boring:

```text
id=42 carries TimelineAddress { world=config, gen, seq=42, body_sha256 }
client calls read(TimelineAddress)
```

Expected outcomes:

- body present -> returns B;
- body expired with durable retention proof -> returns Expired/410-class with
  the same chain coordinate;
- body missing without expiry proof -> Corrupt/MissingBody, not Expired;
- gen mismatch -> reset/incarnation mismatch, not a read from the new world;
- subject deleted -> Gone/ledger-backed tombstone for that subject gen;
- chain row missing without a matching tombstone -> corruption/truncation
  signal, not current C.

If any implementation path returns C for the id=42 fetch, Path 3 failed.
If documentation calls the expired case "value catch-up", the documentation
failed: it is audit/timeline catch-up plus honest body expiry.

### Counterexample B: ABA Body

```text
body X -> body Y -> body X
old If-Match from first X is replayed
```

If ETag becomes `sha256(body)`, the stale condition passes after ABA.
Therefore v1 keeps:

```text
ETag = hmac-{event_hmac}
body_sha256 = content address, not the write precondition identity
```

This is the initial Path 3 contract. A later ETag-split stack may change
`ETag` to content identity only if it adds a separate position validator
for compare-and-swap. If a PR changes this without that validator, it
reintroduces ABA.

### Counterexample C: Cursor Collision

If `gen` stays at the parent plan's stale `12-hex` width because someone
treats SSE id as an integer budget, delete/recreate cycles can alias notebook
state across incarnations.

The cursor is an opaque string. The implementation should choose collision
budget first and readability second.

Required v1 decision:

```text
gen = 128-bit minted incarnation id, rendered as 32 hex chars
```

If `gen` is represented through a genesis HMAC, that HMAC must include the
minted incarnation entropy. Any implementation using 12 hex chars, or deriving
`gen` solely from deterministic first-event content, has not dissolved the
false identity premise.

### Counterexample D: Pattern Catch-Up With No Global Order

```text
t1: client subscribes to home/*
t2: home/a changes, client records that stamp
t3: client goes offline
t4: home/b changes
t5: client reconnects with only the last scalar SSE id from home/a
```

There is no global timeline that lets the server infer `home/b` from the
scalar id, and the engine does not track each subscriber's progress. Pattern
catch-up must be client-side notebook diff plus delete-ledger scan:

```text
list_worlds(home/*)
for each world: compare chain_head(world) with notebook[world]
read(TimelineAddress) for missing per-world ranges
scan var/log/deletes after notebook.delete_ledger_head
filter delete rows whose subject matches home/*
```

The scalar SSE id is a live-splice convenience, not durable pattern replay.
If a PR claims wildcard catch-up from one scalar cursor, it has invented a
global log or hidden server state. If it omits the delete-ledger scan, it
uses current namespace membership as history and misses offline deletes.

### Counterexample E: Exact-World Delete Discovery

```text
t1: client tracks home/config
t2: client goes offline
t3: home/config is physically deleted
t4: client resumes home/config
```

The subject world's file is gone. Its timeline cannot answer the delete
after physical removal. The durable fact lives under `var/log/deletes`, and
the delete row must carry enough subject identity to disambiguate
delete/recreate cycles:

```text
subject_final_address = { world, gen, seq, body_sha256 }
subject_final_hmac    = additional position validator, not a substitute
```

Therefore exact-world catch-up has two valid shapes:

- client notebooks always include the delete ledger in their catch-up scan; or
- SDK catch-up helpers hide that scan and report the delete against the
  subject world.

If a PR makes subject-world resume alone prove deletion without consulting the
ledger or a derived index built from it, it has reintroduced file-survival as
a hidden premise. If delete rows identify only the subject path, it has
reintroduced "world path equals world identity" across ABA recreate cycles.

## 5. Clean Alternatives Rejected

### Pure Notification

Could work:

```text
subscribe -> "world changed"
client -> read current
```

Rejected because AuditeDB already carries audit chain coordinates and wants
catch-up semantics. Pure notification is honest but too weak for notebooks,
SDK catch-up, and deletion accounting.

### Push Body As Delivery

Could work:

```text
subscribe -> { world, body }
```

Rejected as the primary contract because it makes subscribe act like a
broker. AuditeDB stores first and notifies second. Inline body is allowed
only as an optional convenience with a cap; the durable contract remains the
timeline address.

### Store Every Body Forever

Could work until the disk fills.

Rejected because finite storage is physics. The permanent object is the chain
row. The body is retained according to policy and may expire loudly.

Consequence: retention can degrade historical *value* recovery to
Expired/410-class while preserving historical *fact* recovery. That is a
deliberate storage-policy tradeoff, not a replay bug.

But expiry is a claim, not absence. CAS GC must leave a durable expiry proof,
or maintain a retention watermark sufficient to prove the address is older than
the retained window. The proof must cover the specific timeline coordinate and
body relation, not only a vague wall-clock cutoff. Otherwise a chain row whose
`body_sha256` no longer resolves is `Corrupt`/`MissingBody`, because the engine
cannot distinguish legitimate pruning from storage loss.

## 6. Implementation Gate

L0 is the already-open chain-head plumbing layer. Long `gen` plumbing is still
planned and must land before Path 3 cursor implementation. After L0, the
first Path-3 CAS semantic layer should not touch HTTP, FFI, SDKs, or
migration.

No user-visible persisted CAS/timeline writes may land before the format marker
and expiry-proof story are explicit. New readers can fail loudly on unknown
layout; they cannot silently reinterpret an unmarked world as timeline-capable.

The first safe CAS semantic layer starts with the core timeline-address
contract and the normative event classifier together:

```text
TimelineAddress = { world, gen, seq, body_sha256 }
read(TimelineAddress) -> Body | Expired | Gone | GenMismatch | MissingRow | MissingBody | Corrupt
```

`gen` is not only an SSE cursor decoration. It is part of the storage-engine
proof that a historical read is resolving the same world incarnation that
emitted the notification.

```text
event_type -> body-bearing? retention-slot? notifies? payload-home?
```

The address contract is the authority; the classifier explains how each chain
row resolves through that address. If either is wrong or ambiguous, CAS,
timeline, retention, subscribe, and migration will all inherit the ambiguity.
