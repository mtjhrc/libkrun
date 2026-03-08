// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Batched virtio queue producer/consumer infrastructure.
//!
//! Provides generic queue handling suited for vectored I/O on virtio queues
//! (e.g. sending a whole descriptor chain in a single `writev`, supporting
//! partial writes, partial reads, etc.).
//!
//! The representation trait [`ChainsMemoryRepr`] allows backends to plug in
//! optimised layouts (e.g. `mmsghdr` for `sendmmsg`/`recvmmsg`).

use aliased_ioslice::RawAliasedIoSlice;
use ioslice_container_utils::{SliceOfIoSlicesExt, VecOfIoSlicesExt};
use smallvec::SmallVec;

pub mod aliased_ioslice;
pub mod ioslice_container_utils;
mod rx_queue_producer;
mod tx_queue_consumer;

pub use rx_queue_producer::{RxProducerBatch, RxQueueProducer};
pub use tx_queue_consumer::{TxConsumerBatch, TxQueueConsumer};

/// Inline capacity for per-chain iovec SmallVecs.
/// Virtio-net descriptors typically have 1–3 scatter-gather elements;
/// 4 covers that without heap allocation.
const IOVEC_INLINE_CAP: usize = 4;

/// SmallVec type aliases used by feed_with_transform callbacks.
pub type IoSliceVec<'a> = SmallVec<[aliased_ioslice::AliasedIoSlice<'a>; IOVEC_INLINE_CAP]>;
pub type IoSliceMutVec<'a> = SmallVec<[aliased_ioslice::AliasedIoSliceMut<'a>; IOVEC_INLINE_CAP]>;
type RawIoSliceVec = SmallVec<[RawAliasedIoSlice; IOVEC_INLINE_CAP]>;

/// Base trait for descriptor chain memory representation.
///
/// # Safety
///
/// - The iovecs stored in the representation point into guest memory owned by
///   the `TxQueueConsumer`/`RxQueueProducer`. The representation must not
///   outlive the consumer/producer — it must stay within the container.
/// - The consumer/producer guarantees that `clear()` is called before the
///   representation is dropped. `clear()` receives external `Meta` (e.g.,
///   `Vec` capacity) needed to correctly free owned resources. Implementors
///   must release all owned memory in `clear()`.
pub unsafe trait ChainsMemoryRepr: Sized + Send {
    /// User-defined metadata stored alongside each chain (e.g., Vec capacity).
    type Meta: Default;

    /// Pre-allocated storage shared across all chains (e.g., iovec pool).
    /// Use `()` when no pool is needed.
    type Pool;

    /// Create a pool sized for `max_chains` concurrent chains.
    fn create_pool(max_chains: usize) -> Self::Pool;

    /// Number of slices in this chain.
    fn len(&self) -> usize;

    /// Check if empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes across all slices.
    fn total_bytes(&self) -> usize;

    /// Construct from raw iovec storage, using the pool for backing memory.
    ///
    /// Called internally by `feed_with_transform` after the user's callback
    /// returns the (possibly transformed) iovecs. The raw iovecs point into
    /// guest memory whose validity is guaranteed by the calling producer/consumer.
    fn from_raw_iovecs(pool: &mut Self::Pool, iovecs: &[RawAliasedIoSlice]) -> Self;

    /// Release owned resources. Always called by the consumer/producer before
    /// drop, with the external `Meta` needed for cleanup.
    fn clear(&mut self, meta: &mut Self::Meta, pool: &mut Self::Pool);
}

/// Trait for representation types that support advancing (consuming bytes from front).
///
/// # Safety
///
/// Implementors must maintain iovec validity after advancing: the remaining
/// slices must still point to valid guest memory with correct lengths.
pub unsafe trait AdvanceBytes: ChainsMemoryRepr {
    /// Advance slices by removing consumed bytes from the front.
    fn advance(&mut self, bytes: usize);
}

/// Trait for representation types that know how many bytes were received.
///
/// Used by batch receive operations to report per-chain byte counts.
pub trait ReceivedLen: ChainsMemoryRepr {
    /// Number of bytes received into this chain.
    fn received_len(&self) -> usize;
}

/// Trait for representation types that support truncating (limiting total bytes).
///
/// # Safety
///
/// Implementors must maintain iovec validity after truncating: the remaining
/// slices must still point to valid guest memory with correct lengths.
pub unsafe trait TruncateBytes: ChainsMemoryRepr {
    /// Truncate slices to limit total bytes to `max_bytes`.
    fn truncate_bytes(&mut self, max_bytes: usize);
}

/// Wrapper around `Vec<RawAliasedIoSlice>` that implements `Send`.
///
/// # Safety
/// The raw pointers inside point to guest memory managed by the owning
/// `TxQueueConsumer`/`RxQueueProducer`. The memory is pinned and the struct
/// lifetime ensures the pointers remain valid. Transferring to another thread
/// is safe because we transfer ownership of the entire container.
#[derive(Default)]
pub struct IovecVec(pub Vec<RawAliasedIoSlice>);

// Safety: See struct-level documentation
unsafe impl Send for IovecVec {}

unsafe impl ChainsMemoryRepr for IovecVec {
    type Meta = ();
    type Pool = ();

    fn create_pool(_max_chains: usize) -> () {}

    fn len(&self) -> usize {
        self.0.len()
    }

    fn total_bytes(&self) -> usize {
        self.0.total_len()
    }

    fn from_raw_iovecs(_pool: &mut (), iovecs: &[RawAliasedIoSlice]) -> Self {
        Self(iovecs.into())
    }

    fn clear(&mut self, _meta: &mut (), _pool: &mut ()) {
        self.0.clear();
    }
}

unsafe impl AdvanceBytes for IovecVec {
    fn advance(&mut self, bytes: usize) {
        self.0.advance(bytes);
    }
}

unsafe impl TruncateBytes for IovecVec {
    fn truncate_bytes(&mut self, max_bytes: usize) {
        self.0.truncate_bytes(max_bytes);
    }
}
