use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// Armed storage accounting reservation.
///
/// Only positive growth is published before SQLite commit. Capacity released
/// by a shrinking write remains deferred so another world cannot consume an
/// uncommitted credit. Dropping this proof restores reserved growth;
/// [`Self::commit`] publishes any deferred credit.
#[must_use = "dropping an uncommitted storage reservation rolls it back"]
pub(crate) struct PendingStorageReservation {
    counter: Arc<AtomicUsize>,
    reserved_increase: usize,
    deferred_credit: usize,
    armed: bool,
}

impl PendingStorageReservation {
    pub(super) fn mint(
        counter: Arc<AtomicUsize>,
        reserved_increase: usize,
        deferred_credit: usize,
    ) -> Self {
        Self {
            counter,
            reserved_increase,
            deferred_credit,
            armed: true,
        }
    }

    pub(crate) fn commit(mut self) {
        credit_storage_counter(&self.counter, self.deferred_credit);
        self.armed = false;
    }
}

impl Drop for PendingStorageReservation {
    fn drop(&mut self) {
        if self.armed {
            credit_storage_counter(&self.counter, self.reserved_increase);
        }
    }
}

fn credit_storage_counter(counter: &AtomicUsize, bytes: usize) {
    if bytes != 0 {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            Some(used.saturating_sub(bytes))
        });
    }
}

pub(super) fn rollback_storage_counter(
    counter: &AtomicUsize,
    previous_len: usize,
    reserved_len: usize,
    predicted_pruned_len: usize,
) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
        Some(
            used.saturating_sub(reserved_len)
                .saturating_add(previous_len)
                .saturating_add(predicted_pruned_len),
        )
    });
}

/// Pessimistic reservation for one audit append.
///
/// A write can append a format marker plus its body event. Both slots are
/// reserved before SQLite mutation. Drop refunds both; the two typed commit
/// methods keep exactly the representable event count.
#[must_use = "dropping an uncommitted audit-event reservation rolls it back"]
pub(crate) struct PendingAuditEvents {
    counter: Arc<AtomicUsize>,
    armed: bool,
}

impl PendingAuditEvents {
    const MAXIMUM: usize = 2;

    pub(super) fn reserve(counter: Arc<AtomicUsize>) -> Result<Self, ()> {
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(Self::MAXIMUM)
            })
            .map_err(|_| ())?;
        Ok(Self {
            counter,
            armed: true,
        })
    }

    pub(crate) fn commit_one(mut self) {
        credit_storage_counter(&self.counter, 1);
        self.armed = false;
    }

    pub(crate) fn commit_two(mut self) {
        self.armed = false;
    }
}

impl Drop for PendingAuditEvents {
    fn drop(&mut self) {
        if self.armed {
            credit_storage_counter(&self.counter, Self::MAXIMUM);
        }
    }
}
