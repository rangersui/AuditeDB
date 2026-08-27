---
name: rust-type-seal-enforcement
description: "Rust safety-invariant design pattern for turning protocol rules into compile-time structure. Use this skill when designing or reviewing Rust APIs where skipping auth, audit verification, slot tracking, resource draining, transaction ordering, protocol-neutral world_ops, or another safety gate should be impossible to call by accident. Trigger on physics not policy, type seal, proof token, capability token, typestate, private constructor, RAII guard, make invalid states unrepresentable, or when a runtime check should become a required type."
---

# Rust Type-Seal Enforcement

## One-Sentence Doctrine

If an invariant is important enough to deserve an `if` check, it is important
enough to make violating it fail to compile.

That is the whole skill.

`WritePermit` is the digital padlock: without the lock, the high-voltage switch
physically cannot move. `TrackedReadConnection` is the maintenance worker's
lock: while the worker's lock is still on the line, DELETE cannot energize the
line by unlinking the database. `OpeningTransition::Drop` is the rule that even
if the worker never returns cleanly, the intermediate state does not silently
stay armed.

This pattern usually does not die because an attacker bypasses it. It dies
because a well-meaning future developer does not understand it and "simplifies"
the shape away. The skill is the document for that future developer. In an
AI-heavy codebase, the next developer is often an AI agent.

Use this skill when the question is not "what check should we do?" but "how do
we make it hard or impossible for future Rust code to skip the check?"

In this repo the model example is `core/src/read_cache.rs`:

- A raw `rusqlite::Connection` is not enough to read a world.
- Read helpers require `&mut TrackedReadConnection`.
- The only production path to `TrackedReadConnection` is the slot-before-open
  state machine.
- DELETE drains the slot before removing it.
- Test bypasses exist only as explicitly named `#[cfg(test)]` helpers.

That is the standard: a safety rule becomes the shape of the API.

The newer `core/src/world_ops.rs` is the same idea at the protocol boundary
(built when the binary still shipped both HTTP and CoAP adapters; CoAP is
retired, the seal remains):

- No adapter owns a separate write implementation.
- Every adapter calls `authorize_read` / `authorize_write`.
- Disk transitions require `ReadPermit` or `WritePermit`.
- The permit is bound to one canonical world.
- A mismatched request returns `PermitWorldMismatch` instead of writing the
  wrong world.
- Adapters map typed outcomes and typed errors onto wire status codes; they do
  not reimplement auth, locks, preconditions, quota, audit, notify, or
  storage-error classification.

## Core Principle

Policy is a rule someone can forget:

```rust
check_auth();
write_world();
```

Physics is an API that cannot be called without the proof:

```rust
let permit = world_ops::authorize_write(&world, tier)?;
world_ops::replace_write(core, &permit, request, hooks).await?;
```

The second form is not magic. It works only when the proof type is opaque,
resource-scoped, and required by every protected operation.

## What Counts As A Real Seal

A real type seal has four parts.

1. Opaque proof type

The proof type may be visible to callers, but its fields and raw constructors
are not.

```rust
pub(crate) struct TrackedReadConnection {
    conn: rusqlite::Connection,
}
```

Callers can name the type, pass it around, and borrow it, but cannot mint one
with a struct literal.

2. Controlled gate

The checked gate performs the required protocol and returns the proof.

```rust
impl ReadCache {
    pub(crate) fn with_tracked_conn<F, R>(
        &self,
        data: &Path,
        world: &str,
        f: F,
    ) -> rusqlite::Result<Option<R>>
    where
        F: FnOnce(&mut TrackedReadConnection) -> rusqlite::Result<R>,
    {
        // slot-before-open, tombstone checks, transient-slot handling
        // ...
    }
}
```

The gate may be `pub(crate)` when callers in other modules need it. The raw
constructor must stay private.

3. Protected operation requires the proof

```rust
pub(crate) fn read_with_hmac_via_conn(
    conn: &mut TrackedReadConnection,
) -> rusqlite::Result<(Stage, Option<String>)> {
    // caller cannot pass a bare rusqlite::Connection
}
```

If a sibling helper still accepts the raw resource, the seal is incomplete.

4. No fallback around the seal

If the guarded path is unavailable, use a reduced-retention guarded path or
return an error. Do not fall back to the old unguarded implementation.

The read-cache precedent is transient slots: at cache cap, it still installs a
tracked slot for the one read, then drains and removes it. It does not fall
back to "open a connection directly just this once."

## Rust Visibility Rules That Matter

Be precise. Rust privacy is module privacy, not file privacy.

- A private `fn` is visible inside its module and child modules.
- A private field prevents construction from outside that module.
- `pub(crate)` exposes the item to the whole crate.
- `pub(super)` exposes the item to the parent module.
- A type with `pub(crate)` visibility and private fields is nameable but not
  constructible outside its defining module.

Design implication:

- Put the raw constructor in the smallest practical leaf module.
- Avoid child modules under the seal module unless they are part of the trusted
  implementation.
- Do not claim "nobody outside this file" unless the module structure actually
  makes that true.
- Prefer "callers outside this module cannot construct it" over vague wording
  like "private enough."

Bad:

```rust
pub(crate) fn from_raw(conn: Connection) -> TrackedReadConnection {
    TrackedReadConnection(conn)
}
```

That is a crate-wide minting API.

Better:

```rust
impl TrackedReadConnection {
    fn from_raw(conn: Connection) -> Self {
        Self(conn)
    }
}
```

Best when the module is large: keep `from_raw` adjacent to the one state
transition that calls it, and verify call sites with `rg "from_raw"`.

## Resource Binding Is Mandatory

A permit that proves "some check passed" is not enough. The proof must bind to
the exact action/resource it authorizes, or the caller can authorize one thing
and use the permit for another.

Bad:

```rust
pub(crate) struct WritePermit {
    needs_approve: bool,
}

let permit = world_ops::authorize_write("home/a", tier)?;
replace_world(permit, "etc/shadow", body)?; // scope confusion
```

Better:

```rust
pub(crate) struct WritePermit {
    world: String,
    gate: AuthGate,
}

pub(crate) fn authorize_write(world: &str, tier: auth::Tier) -> Result<WritePermit, WriteError> {
    let gate = if needs_write_approve(world) {
        AuthGate::WriteApprove
    } else {
        AuthGate::Write
    };
    if can_write(world, tier) {
        Ok(WritePermit {
            world: world.to_owned(),
            gate,
        })
    } else {
        Err(WriteError::Auth(gate))
    }
}

pub(crate) async fn replace_write<H: WriteTraceHooks + ?Sized>(
    core: &Core,
    permit: &WritePermit,
    req: ReplaceRequest,
    hooks: &H,
) -> Result<WriteOutcome, WriteError> {
    ensure_write_permit(permit, &req.world)?;
    // write is now tied to the authorized world and gate
}
```

Best: construct the operation request inside the gate or make the protected
function take only data that cannot disagree with the permit.

For path-like resources, carry the canonicalized path in the proof token, not
the raw request path.

When the request has to carry its own world string, add a second seal:

```rust
fn ensure_write_permit(permit: &WritePermit, world: &str) -> Result<(), WriteError> {
    if permit.world != world {
        return Err(WriteError::PermitWorldMismatch);
    }
    let expected_gate = if needs_write_approve(world) {
        AuthGate::WriteApprove
    } else {
        AuthGate::Write
    };
    if permit.gate != expected_gate {
        return Err(WriteError::Internal("write permit gate mismatch"));
    }
    Ok(())
}
```

This is still runtime validation, but it is the runtime validation at the only
shared transition boundary. An adapter cannot forget it because no adapter
writes bytes directly anymore.

## Protocol-Neutral World Operations

When more than one adapter can mutate the same storage, the safety boundary
must move below the adapters. (This shape was forced while the binary shipped
HTTP and CoAP side by side; CoAP is retired, but the boundary is what lets any
future adapter — or an embedder calling `Engine` directly — stay safe.)

Current shape:

```text
HTTP handler -> world_ops::authorize_write -> world_ops::replace_write
any adapter  -> world_ops::authorize_write -> world_ops::replace_write
```

`world_ops` owns:

- auth permit creation
- per-world locks
- tombstone clearing
- If-Match / If-None-Match preconditions
- body limits
- durable and memory quota reservation
- audit append
- storage-error classification
- notify

Adapters own only:

- parsing their wire format
- constructing `ReplaceRequest` / `AppendRequest`
- rendering typed outcomes into their protocol
- mapping `ReadError` / `WriteError` to their wire response shape

Do not let a protocol adapter grow a "temporary" direct path to `Core`,
`world`, `store`, or `audit` when a `world_ops` path exists. That recreates the
old split-brain bug from the retired CoAP-adapter era: HTTP and CoAP looked
similar in tests until one of them forgot auth, quota, audit, notify, or a
status-code distinction.

Trace hooks are observers, not owners:

```rust
pub(crate) trait WriteTraceHooks {
    fn lock_acquired(&self) {}
    fn quota_check(&self, _used: usize, _quota: usize) {}
    fn sqlite_committed(&self, _etag: &str) {}
    fn notify_sent(&self) {}
}
```

HTTP can emit pipeline trace lines. Another adapter can pass a no-op hook.
Neither gets a different storage transition.

## Genesis vs Existing Is A Type Decision

Avoid boolean flags such as `allow_empty_chain: bool` at safety boundaries.
They are in-band policy and are easy to flip at a call site.

Prefer named entrypoints or small private enums.

```rust
pub fn verify_appendable_tx_existing<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    key: &[u8],
) -> rusqlite::Result<VerifiedAuditTx<'tx, 'conn>> {
    verify_appendable_tx(tx, key, EmptyChain::Reject)
}

pub fn verify_appendable_tx_genesis<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    key: &[u8],
) -> rusqlite::Result<VerifiedAuditTx<'tx, 'conn>> {
    verify_appendable_tx(tx, key, EmptyChain::Allow)
}

fn verify_appendable_tx<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    key: &[u8],
    empty_chain: EmptyChain,
) -> rusqlite::Result<VerifiedAuditTx<'tx, 'conn>> {
    // verify first, then return proof token
}
```

The public call site now has to say `existing` or `genesis`. That is still a
choice, but it is visible and reviewable.

## RAII State Transition Guard

Use RAII when entering an intermediate state must always end in a valid state,
including during panic unwinding.

```rust
struct OpeningTransition<'a> {
    state: &'a mut SlotState,
    finalized: bool,
}

impl<'a> OpeningTransition<'a> {
    fn promote(mut self, conn: Connection) {
        let tracked = TrackedReadConnection::from_raw(conn);
        *self.state = SlotState::Ready(StdMutex::new(tracked));
        self.finalized = true;
    }

    fn fail(mut self) {
        *self.state = SlotState::Tombstone;
        self.finalized = true;
    }
}

impl Drop for OpeningTransition<'_> {
    fn drop(&mut self) {
        if !self.finalized {
            *self.state = SlotState::Tombstone;
        }
    }
}
```

Keep the transition type itself private unless callers outside the module are
intended to drive the state machine. In `read_cache.rs`, sibling modules should
not be able to create `OpeningTransition` and call `promote` manually.

## Test Bypasses

Production code should have zero bypasses. Tests may get a named, cfg-gated
escape hatch.

```rust
#[cfg(test)]
pub(crate) fn test_only_wrap_raw_connection(conn: Connection) -> TrackedReadConnection {
    TrackedReadConnection::from_raw(conn)
}
```

Rules:

- The name starts with `test_only_`.
- It is behind plain `#[cfg(test)]`.
- It is not behind a feature flag that could be enabled in production.
- It is documented as a bypass.
- Production code never calls it.

Do not rely on `nm` or `objdump` as the primary proof that a test bypass is
absent. Rust may inline, strip, mangle, or eliminate symbols. Prefer source and
build checks:

```bash
cargo check --release
rg "test_only_|from_raw|unsafe" core/src
```

Use compile-fail tests for public API crates when the forbidden call shape is
part of the user-facing contract.

## Review Checklist

Use this checklist before accepting a "physics not policy" change.

- [ ] The protected operation cannot be called with the raw resource.
- [ ] The proof type has at least one private field.
- [ ] Raw constructors are private to the smallest practical module.
- [ ] Checked gates are the only production constructors.
- [ ] Proof tokens carry or bind to the exact resource/action they authorize.
- [ ] Canonical paths, not raw paths, are stored in path-scoped proofs.
- [ ] No `Clone`/`Copy` on the proof token unless replay is intentional.
- [ ] No fallback path bypasses the safety mechanism.
- [ ] Intermediate states have RAII cleanup when panic would otherwise strand them.
- [ ] Test bypasses are named `test_only_*` and `#[cfg(test)]` only.
- [ ] Expected denial returns a typed error; it is not an `assert!` or panic.
- [ ] The module docs explain the invariant and cite the bug class it prevents.
- [ ] `rg` confirms the raw constructor has only the intended call sites.

## Anti-Patterns

Scope-less permits:

```rust
struct Permit(bool);
```

This proves that some check happened, not that this operation is allowed.

Public minting:

```rust
pub(crate) fn new_unchecked(...) -> Permit
```

That makes the compiler enforce ceremony, not safety.

Parallel raw API:

```rust
fn read_with_hmac(conn: &mut Connection) -> ...
fn read_with_hmac_via_conn(conn: &mut TrackedReadConnection) -> ...
```

If production callers can choose the raw version, the protected version is only
documentation.

Boolean safety flags:

```rust
verify(tx, key, true)
```

Use named entrypoints or a private enum so the call site says what is being
allowed.

Unsafe bypass:

If the only way to make the seal ergonomic is `unsafe`, the design is probably
wrong for this codebase. `unsafe` can be necessary in Rust, but it is not an
acceptable shortcut around auth, audit, fd lifetime, or transaction ordering.

Over-sealing:

Do not add proof tokens for every helper. Use them at boundaries where a missed
step creates a security bug, data loss, corruption, fd race, audit lie, or
protocol-level false success.

## When To Use This Pattern

Use a type seal when:

- The invariant has already been rediscovered in review.
- A new adapter or caller is likely to miss the rule.
- Skipping the rule creates a security, audit, corruption, fd lifetime, or
  false-success bug.
- The type plumbing is small compared with the bug class it removes.

Do not use it when:

- The check is fast-changing business policy.
- The invariant only matters inside one tiny function.
- The proof token needs broad lifetime plumbing that makes callers worse.
- A runtime guard produces clearer code and the blast radius is low.

The target is not maximal type cleverness. The target is boring APIs where the
wrong call shape does not compile.
