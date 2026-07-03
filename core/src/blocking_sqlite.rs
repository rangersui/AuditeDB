//! Proof token for authorised SQLite execution gates.
//!
//! `rusqlite` is synchronous. The invariant here is not "own a connection
//! only inside `spawn_blocking`" because the engine intentionally keeps
//! read, write, and ledger connections alive in caches. The invariant is
//! narrower and enforceable: production helpers that execute SQLite must
//! require `&mut BlockingSqlite`. Production code can only mint that proof
//! through this module's gates.
//!
//! `run` is the async boundary: it mints the proof inside Tokio's blocking
//! pool. `run_scoped` is the synchronous boundary for borrowed/non-`'static`
//! engine internals that cannot cross `spawn_blocking`; it still centralises
//! proof minting, but does not claim a scheduler transition.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;

/// Proof that the current call stack is inside an Engine SQLite execution gate.
///
/// The private fields prevent construction outside this module. The
/// `Rc` marker makes the token `!Send + !Sync`, so it cannot be moved
/// out to another thread, placed in an `Arc`, or returned from
/// `run`'s blocking closure.
pub(crate) struct BlockingSqlite {
    _not_send_sync: PhantomData<Rc<()>>,
    _private: (),
}

impl BlockingSqlite {
    fn mint() -> Self {
        Self {
            _not_send_sync: PhantomData,
            _private: (),
        }
    }
}

/// Join failure from the blocking SQLite worker.
#[derive(Debug)]
pub(crate) struct BlockingJoinError {
    source: tokio::task::JoinError,
}

impl BlockingJoinError {
    pub(crate) fn is_panic(&self) -> bool {
        self.source.is_panic()
    }
}

impl fmt::Display for BlockingJoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blocking SQLite worker failed: {}", self.source)
    }
}

impl std::error::Error for BlockingJoinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<tokio::task::JoinError> for BlockingJoinError {
    fn from(source: tokio::task::JoinError) -> Self {
        Self { source }
    }
}

pub(crate) async fn run<F, R>(f: F) -> Result<R, BlockingJoinError>
where
    F: FnOnce(&mut BlockingSqlite) -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut proof = BlockingSqlite::mint();
        f(&mut proof)
    })
    .await
    .map_err(BlockingJoinError::from)
}

pub(crate) fn run_scoped<F, R>(f: F) -> R
where
    F: FnOnce(&mut BlockingSqlite) -> R,
{
    let mut proof = BlockingSqlite::mint();
    f(&mut proof)
}

/// Test-only escape hatch for direct unit tests of blocking helpers.
///
/// Production code has no direct minting path. Tests that use this bypass
/// should be testing synchronous helper behaviour, not adapter scheduling.
#[cfg(test)]
pub(crate) fn test_only_mint() -> BlockingSqlite {
    BlockingSqlite::mint()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn requires_proof(_proof: &mut BlockingSqlite) -> usize {
        42
    }

    #[tokio::test]
    async fn run_mints_proof_inside_blocking_worker() {
        let value = run(requires_proof).await.unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn test_only_mint_supports_sync_helper_tests() {
        let mut proof = test_only_mint();
        assert_eq!(requires_proof(&mut proof), 42);
    }

    #[tokio::test]
    async fn run_reports_blocking_worker_panic() {
        let err = run(|_| -> () { panic!("blocking worker panic") })
            .await
            .unwrap_err();
        assert!(err.is_panic());
    }

    #[test]
    fn run_scoped_mints_non_static_proof() {
        let local = 7;
        let value = run_scoped(|proof| requires_proof(proof) + local);
        assert_eq!(value, 49);
    }
}
