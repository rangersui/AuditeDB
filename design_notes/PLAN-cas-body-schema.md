# PLAN: CAS Body Schema Foothold

> Addendum to `path3-precondition-challenge.md`.
> Scope: the durable SQLite table shape that will hold retained body bytes for
> later `read(TimelineAddress)` work.

## 1. Frame Being Tested

Path 3 needs this eventual lookup:

```text
TimelineAddress = { world, gen, seq, body_sha256 }
read(TimelineAddress) ->
    Body
  | NeverRetained
  | Expired
  | Gone
  | GenMismatch
  | AddressMismatch
  | MissingRow
  | Corrupt
```

This addendum refines the earlier Path 3 result shape by adding
`NeverRetained` as its own absence state. In a world that already has the CAS
schema, history outside the promised retained range must not collapse into
`Expired` or `MissingRow`.

Those result names are not prose-only states. Before any
`read(TimelineAddress)` implementation ships, the Rust contract must be able
to express them exhaustively: either `TimelineRead` grows typed
`NeverRetained` and `AddressMismatch` variants, or the read path returns a
sealed intermediate outcome that forces those distinctions before adapters see
the result. A stringly "reason" field is not enough.

The next storage-format layer should add only the place where retained body
bytes can live:

```sql
CREATE TABLE cas_bodies(
    body_sha256 TEXT NOT NULL PRIMARY KEY
        CHECK(typeof(body_sha256)='text')
        CHECK(length(body_sha256)=64)
        CHECK(body_sha256 NOT GLOB '*[^0-9a-f]*'),
    body BLOB NOT NULL
        CHECK(typeof(body)='blob')
) WITHOUT ROWID;

CREATE TABLE cas_state(
    id INTEGER PRIMARY KEY CHECK(id=1),
    first_retained_seq INTEGER
        CHECK(
            first_retained_seq IS NULL OR
            (typeof(first_retained_seq)='integer' AND first_retained_seq > 0)
        )
);
INSERT INTO cas_state(id, first_retained_seq) VALUES(1, NULL);
```

This is a schema foothold, not CAS semantics. `cas_state.first_retained_seq`
is a format/eligibility marker, not a pruning policy. `NULL` means this world
has no promised CAS-retained event range yet. It must not wire writes, reads,
HTTP, FFI, SDKs, subscribe, retention pruning, delete-ledger catch-up, or ETag
changes.

## 2. Ownership Split

`cas_bodies` owns only bytes:

```text
body_sha256 -> body bytes
```

`cas_state` owns only the local retention eligibility floor:

```text
first_retained_seq = first event seq for which write-side CAS retention is promised
NULL               = CAS retention has not started for this world
```

`events`, `event_headers`, and the persisted world generation remain the
timeline and representation authority:

```text
world generation   -> gen / incarnation identity
events.id          -> seq
events.event_type  -> body-bearing / retention class
events.content_type
events.meta_sha256
event_headers
events.hmac        -> position identity / ETag source
```

Same bytes may be written with different content type or metadata. Therefore
the CAS table must not store representation metadata. A body hash is content
identity, not representation identity and not compare-and-swap identity.

## 3. Hidden Assumptions

| Assumption | Physics or policy | Decision |
|---|---|---|
| The CAS table can store the full representation. | Policy. | Rejected. Metadata is per event; bytes are per body hash. No extra CAS columns. |
| A body hash alone is enough to resolve a timeline read. | Policy and unsafe. | Rejected. Reads must first prove `{world, gen, seq}` through the event row, then dereference `body_sha256`. |
| `events.body_sha256` should have a hard foreign key to `cas_bodies`. | Policy and wrong for expiry. | Rejected. Chain rows are permanent; retained bodies may expire. |
| CAS schema should include retention policy columns now. | Policy. | Rejected for this layer. `first_retained_seq` is an eligibility floor, not expiry policy. |
| A read-only verifier can prove constraints by inserting bad rows. | Physics false. | Rejected. Read-only opens cannot probe by mutation; shape checks must inspect schema metadata/DDL and tests must pin created-table constraints. |
| Missing CAS table on an existing world can be repaired automatically. | Policy. | Rejected. Storage format changes fail loud; no migration/backfill in this stack layer. |
| Missing CAS bytes always mean expiry. | Policy and unsafe. | Rejected. Missing bytes are `Expired` only when a retention/pruning proof says so. Before CAS retention starts they are `NeverRetained`/unavailable-before-CAS; inside a promised retained range without pruning proof they are corruption. |

`NeverRetained` is not a migration escape hatch. A pre-CAS-schema v5.1 world
that lacks `cas_bodies` / `cas_state` fails storage-format verification. The
`NeverRetained` state applies only after the CAS schema exists and
`cas_state.first_retained_seq` proves either `NULL` or a floor above the
requested `seq`.

## 4. Residual Physics

- SQLite schema verification on read-only connections cannot mutate the DB.
- Content hashes can only be proven by hashing bytes; SQL type checks do not
  prove `body_sha256 == sha256(body)`.
- Storage is finite; future body retention can expire while event rows remain.
- Events are ordered per world, not globally.

The future read path therefore needs both:

```text
event row proves timeline coordinate
CAS row supplies retained bytes
Rust recomputes sha256(body) before returning Body
first_retained_seq proves only the local eligibility floor
future pruning proof proves Expired
absence without the right proof becomes NeverRetained or Corrupt
```

## 5. Required Invariants

The schema layer must make these invalid states fail loudly:

- no `cas_bodies` table on a durable world;
- no `cas_state` row on a durable world;
- `body_sha256` column missing from `cas_bodies`;
- `body_sha256` present but not TEXT;
- `body` missing from `cas_bodies`;
- `body` present but not BLOB;
- extra columns in `cas_bodies`;
- extra columns in `cas_state`;
- invalid hash length;
- uppercase or non-hex hash;
- duplicate body-hash rows;
- invalid `first_retained_seq`;
- `first_retained_seq` present but not INTEGER.

Because read-only verification cannot mutate the DB, the implementation must
use non-mutating shape checks for table definitions. `PRAGMA table_info` is not
enough for CHECK constraints. String-fragment checks are also not enough:
`CHECK(typeof(body_sha256)='text' OR 1)` contains the desired fragment while
removing the invariant. The schema PR must compare against canonical generated
DDL or parse/normalize enough to prove each critical CHECK is a standalone
conjunctive constraint. Created-table tests must still attempt invalid inserts
to prove the generated schema actually rejects them.

The schema layer does not need to prove body/hash equality yet. That belongs to
future write/read CAS logic, which has the body bytes in hand and can recompute
or compare before accepting a write or returning `TimelineRead::Body`.

The schema layer also does not prove write-side atomicity. Before write-side
CAS retention is wired, the append path needs a proof-bearing transaction shape
such as a sealed `RetainedCasBody` / `VerifiedCasBody` / `CasRetainTx` value
that binds the transaction, event kind, body bytes, and `body_sha256`. Passing
a raw hash string across the audit boundary would leave "event row, CAS body,
and retention floor commit together" as policy rather than physics.

## 6. Falsifying Counterexamples

### Counterexample A: Same Body, Different Metadata

```text
seq=1: body=X, content-type=text/plain
seq=2: body=X, content-type=application/octet-stream
```

If `cas_bodies` stores content type, one hash would point to two incompatible
representations. Correct shape: CAS stores `X`; each event row stores its own
metadata.

### Counterexample B: Hash-Only Historical Read

```text
seq=1: body=X
seq=2: body=Y
seq=3: body=X
```

If the read path accepts only `body_sha256(X)`, it cannot tell whether the
client asked for seq 1 or seq 3. Correct shape: resolve `events.id = seq` in
the requested generation first, then use that row's body hash.

The resolved row must also agree with the address. Either `TimelineAddress` is
a sealed proof minted only by event-row extraction, or the read path must check
`address.body_sha256 == events.body_sha256` and return a typed mismatch before
any CAS lookup. This keeps a caller from smuggling a valid hash into the wrong
timeline coordinate.

### Counterexample C: Expired Body With Permanent Event

```text
events.id=42 has body_sha256=H
cas_bodies no longer has H
```

This is not automatically retained-body expiry. Correct result later depends on
the retention proof:

- first prove the `{world, gen, seq}` row and check `address.body_sha256`
  against that row, returning `AddressMismatch` before any CAS lookup if it
  differs;
- `seq < first_retained_seq` or `first_retained_seq IS NULL` ->
  never retained / unavailable before CAS retention;
- `seq >= first_retained_seq` and an explicit future pruning record covers the
  requested retained range / epoch / timeline address, not just hash `H`
  -> `TimelineRead::Expired { address }`;
- `seq >= first_retained_seq` with no pruning proof -> `Corrupt` with a missing
  body reason.

Only after those address-level checks may the read path dereference
`cas_bodies[H]`. CAS dedupe must not resurrect a never-retained or expired
timeline address just because another live address later stored the same bytes.
It must never fall back to the current body.

### Counterexample D: Legacy World Missing CAS Table

An existing v5.1 DB has valid generation and audit tables but no `cas_bodies`.
After the schema layer, opening that world must fail loud as a storage-format
mismatch. No migration or silent table creation on read-only paths.

### Counterexample E: Deleted Subject World

```text
t1: subject world home/config has seq=42
t2: home/config is deleted and its universe.db is physically removed
t3: client asks for the address it missed
```

`Gone` cannot be proven by the subject file after physical delete. It must be
proven through `var/log/deletes` or a future derived index built from that
ledger, and that proof must bind to the requested `world` and `gen`. It must
also prove the requested `seq` is within the deleted incarnation's final
coordinate; a path-only delete fact would confuse delete/recreate ABA with the
old world still being gone. The subject-world read flow must not pretend a
missing file alone is a timeline fact.

Likewise, `Expired` must only be constructible from a pruning proof bound to
the requested timeline address or retained range/epoch, and `Gone` must only be
constructible from a delete proof bound to the requested `{world, gen, seq}`.
Until those proof types or verifier functions exist, those states should remain
unreachable from production code.

## 7. Implementation Boundary For The Next PR

The CAS schema PR may:

- update source comments to name the new storage shape;
- create `cas_bodies` in `world_schema::create`;
- create `cas_state` in `world_schema::create`;
- require `cas_bodies` in `world_schema::verify`;
- require `cas_state` and its singleton row in `world_schema::verify`;
- verify the critical table shape without writing to the DB;
- add focused tests for created-table constraints and legacy failure.

The CAS schema PR must not:

- insert bodies on put/append;
- implement `read(TimelineAddress)`;
- change `ChangeEvent`, SSE ids, `/listen/*`, HTTP, CoAP, MQTT, FFI, SDK, or
  public Engine APIs;
- change ETags or precondition semantics;
- add retention/pruning policy;
- add a foreign key from `events.body_sha256` to `cas_bodies`;
- backfill or migrate existing worlds.

The persisted format marker for this layer is the table shape itself:
`cas_bodies`, `cas_state`, and the singleton `cas_state(id=1)` row. Do not add
or rely on a separate durable version field such as `PRAGMA user_version`
unless a later plan explicitly introduces it.

## 8. Follow-Up Order

1. Add inert `cas_bodies` / `cas_state` schema and verification.
2. Sync the typed timeline read contract before dereference plumbing:
   `TimelineRead` must grow explicit `NeverRetained` and `AddressMismatch`
   states, or a sealed intermediate result must force those distinctions before
   adapters can classify the outcome.
3. Add write-side CAS insertion for body-bearing audit events and set
   `first_retained_seq` when the first retained event is committed. Same hash
   plus same bytes is idempotent. Same hash plus different bytes is corruption
   and must fail loud before the event or floor update commits. Do not use
   destructive upsert shapes such as `INSERT OR REPLACE` or
   `ON CONFLICT DO UPDATE`. Use `INSERT ... ON CONFLICT(body_sha256) DO NOTHING`
   or `SELECT` then plain `INSERT`, followed by same-transaction byte/hash
   verification. Once `first_retained_seq` is non-NULL, every
   later body-bearing event must commit the event row and CAS body atomically or
   the scalar floor is not strong enough and must become explicit retained
   ranges/epochs instead.
4. Add event-row address extraction: `{world, gen, seq, body_sha256}`.
5. Add internal `read(TimelineAddress)` that resolves event row first, CAS body
   second, and returns typed absence/corruption, including the distinction
   between never-retained, expired-with-proof, and unexpected missing body.
6. Only after the internal contract is proven, expose adapter/SDK surfaces.
