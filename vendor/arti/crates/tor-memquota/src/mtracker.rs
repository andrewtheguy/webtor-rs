//! No-op accounting handles for browser queues.

use crate::{EnabledToken, Error};
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use tor_rtcompat::CoarseInstant;

/// Browser memory tracker. It deliberately performs no accounting.
#[derive(Debug, Default)]
pub struct MemoryQuotaTracker;

/// No-op memory account.
#[derive(Clone, Debug, Default)]
pub struct Account;

/// No-op participant handle.
#[derive(Clone, Debug, Default)]
pub struct Participation;

/// Weak no-op account handle.
#[derive(Clone, Debug, Default)]
pub struct WeakAccount;

/// Hooks implemented by queue receivers.
pub trait IsParticipant: Debug + Send + Sync + 'static {
    /// Return the oldest queued timestamp.
    fn get_oldest(&self, token: EnabledToken) -> Option<CoarseInstant>;

    /// Collapse the participant to reclaim its queue.
    fn reclaim(self: Arc<Self>, token: EnabledToken) -> ReclaimFuture;
}

/// Future returned by [`IsParticipant::reclaim`].
pub type ReclaimFuture = Pin<Box<dyn Future<Output = Reclaimed> + Send + Sync>>;

/// Outcome of a reclamation request.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Reclaimed {
    /// The participant is collapsing completely.
    Collapsing,
}

impl MemoryQuotaTracker {
    /// Construct the browser's no-op tracker.
    pub fn new_noop() -> Arc<Self> {
        Arc::new(Self)
    }

    /// Construct a no-op child account.
    pub fn new_account(self: &Arc<Self>, _parent: Option<&Account>) -> crate::Result<Account> {
        Ok(Account)
    }
}

impl Account {
    /// Construct an independent no-op account.
    pub const fn new_noop() -> Self {
        Self
    }

    /// Register a queue participant without retaining accounting state.
    pub fn register_participant_with<P: IsParticipant, X, E>(
        &self,
        _now: CoarseInstant,
        constructor: impl FnOnce(Participation) -> Result<(Arc<P>, X), E>,
    ) -> Result<Result<(Arc<P>, X), E>, Error> {
        Ok(constructor(Participation))
    }

    /// Construct a no-op child account.
    pub fn new_child(&self) -> crate::Result<Self> {
        Ok(Self)
    }

    /// Return a fresh no-op tracker.
    pub fn tracker(&self) -> Arc<MemoryQuotaTracker> {
        MemoryQuotaTracker::new_noop()
    }

    /// Return a weak no-op account.
    pub const fn downgrade(&self) -> WeakAccount {
        WeakAccount
    }
}

impl WeakAccount {
    /// Upgrade to a no-op account.
    pub fn upgrade(&self) -> crate::Result<Account> {
        Ok(Account)
    }

    /// No concrete tracker is retained by a browser account.
    pub fn tracker(&self) -> Weak<MemoryQuotaTracker> {
        Weak::new()
    }

    /// Construct a dangling no-op account.
    pub const fn new_dangling() -> Self {
        Self
    }
}

impl Participation {
    /// Accept a memory claim without accounting it.
    pub fn claim(&mut self, _bytes: usize) -> crate::Result<()> {
        Ok(())
    }

    /// Ignore a memory release.
    pub fn release(&mut self, _bytes: usize) {}

    /// Return the associated no-op account.
    pub const fn account(&self) -> WeakAccount {
        WeakAccount
    }

    /// End the no-op participation.
    pub fn destroy_participant(self) {}

    /// Construct a dangling no-op participation.
    pub const fn new_dangling() -> Self {
        Self
    }
}
