// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Generic chain memory representation trait for TX/RX queue operations.
//!
//! This trait abstracts over how iovecs are represented per descriptor chain,
//! allowing different backends to use optimized representations (e.g., mmsghdr for sendmmsg).

use std::io::IoSliceMut;

use libc::iovec;

use super::iovec_utils::{advance_iovecs_vec, truncate_iovecs};

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

    /// Number of slices in this chain.
    fn len(&self) -> usize;

    /// Check if empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes across all slices.
    fn total_bytes(&self) -> usize;

    /// Release owned resources. Always called by the consumer/producer before
    /// drop, with the external `Meta` needed for cleanup.
    fn clear(&mut self, meta: &mut Self::Meta);
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

/// Wrapper around `Vec<iovec>` that implements `Send`.
///
/// # Safety
/// The raw pointers in `iovec` point to guest memory managed by the owning
/// `TxQueueConsumer`/`RxQueueProducer`. The memory is pinned and the struct
/// lifetime ensures the pointers remain valid. Transferring to another thread
/// is safe because we transfer ownership of the entire container.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct IovecVec(pub Vec<iovec>);

// Safety: See struct-level documentation
unsafe impl Send for IovecVec {}

// ChainsMemoryRepr implemented for IovecVec - the default representation type.
// Raw iovec has no lifetime, avoiding the need for fake 'static lifetimes.
unsafe impl ChainsMemoryRepr for IovecVec {
    type Meta = ();

    fn len(&self) -> usize {
        self.0.len()
    }

    fn total_bytes(&self) -> usize {
        self.0.iter().map(|s| s.iov_len).sum()
    }

    fn clear(&mut self, _meta: &mut ()) {
        self.0.clear();
    }
}

unsafe impl AdvanceBytes for IovecVec {
    fn advance(&mut self, bytes: usize) {
        // Safety: IoSliceMut is #[repr(transparent)] over iovec, so
        // &mut Vec<iovec> and &mut Vec<IoSliceMut> have the same layout.
        let slices: &mut Vec<IoSliceMut> =
            unsafe { std::mem::transmute(&mut self.0) };
        advance_iovecs_vec(slices, bytes);
    }
}

unsafe impl TruncateBytes for IovecVec {
    fn truncate_bytes(&mut self, max_bytes: usize) {
        // Safety: IoSliceMut is #[repr(transparent)] over iovec.
        let slices: &mut [IoSliceMut] = unsafe {
            std::slice::from_raw_parts_mut(self.0.as_mut_ptr() as *mut IoSliceMut, self.0.len())
        };
        let keep = truncate_iovecs(slices, max_bytes).len();
        self.0.truncate(keep);
    }
}
