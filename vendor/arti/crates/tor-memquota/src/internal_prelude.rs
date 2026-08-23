//! Internal prelude
//!
//! This file contains most of the imports we wish to use, throughout this crate.
//!
//! Every module does `use crate::internal_prelude::*;`
//!
//! Exceptions:
//!
//!  * Names that are private to a module and its submodules
//!    are imported to the sub-modules via `use super::*`.
//!    (Thus, the sub-module inherits the prelude from its parent.)
//!
//!  * Broad names from specific contexts, that are unsuitable for wide imports.
//!    For example, individual cell and message names from `tor-cell`,
//!    and the types from `tor_proto::stream` other than the high-level `DataStream`.

#![allow(unused_imports)]

pub(crate) use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashSet},
    fmt::{self, Debug},
    future::Future,
    marker::PhantomData,
    mem::{self, size_of},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError, Weak},
};

pub(crate) use futures::{
    FutureExt as _, Sink, SinkExt as _, Stream, StreamExt as _,
    channel::mpsc,
    stream::FusedStream,
    task::{Spawn, SpawnError},
};

pub(crate) use std::task::Waker;

pub(crate) use {
    derive_deftly::{Deftly, define_derive_deftly, derive_deftly_adhoc},
    derive_more::{Constructor, Deref, DerefMut},
    educe::Educe,
    itertools::chain,
    paste::paste,
    pin_project::pin_project,
    thiserror::Error,
};

pub(crate) use {
    tor_async_utils::mpsc_channel_no_memquota,
    tor_async_utils::stream_peek::StreamUnobtrusivePeeker,
    tor_rtcompat::{CoarseInstant, CoarseTimeProvider, DynTimeProvider},
};

pub(crate) use crate::{
    EnabledToken,
    error::Error,
    memory_cost::{HasMemoryCost, HasTypedMemoryCost, TypedParticipation},
    mtracker::{self, Account, IsParticipant, MemoryQuotaTracker, Participation},
    private::Sealed,
};
