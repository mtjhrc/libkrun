// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Batched virtio queue producer/consumer infrastructure.
//!
//! Raw iovecs live in a fixed-capacity ring buffer owned by the batch queue.
//! Each descriptor chain's iovecs occupy a contiguous slice of the ring; when
//! the tail has insufficient room the allocation wraps to physical index 0.
//! Per-chain metadata stores absolute ranges into the ring.  Optional
//! user-transformed state lives in a separate array aligned with the work
//! items.

use std::ops::Range;

use aliased_ioslice::{AliasedIoSlice, AliasedIoSliceMut, AnyIoSlice, RawAliasedIoSlice};

pub mod aliased_ioslice;
mod rx_queue_producer;
mod tx_queue_consumer;

pub use rx_queue_producer::{RxProducerBatch, RxQueueProducer};
pub use tx_queue_consumer::{TxConsumerBatch, TxQueueConsumer};

/// Per-chain state returned by the feed transform and stored alongside each
/// work item.
///
/// `set_iovecs` is called to update cached iovec pointers: once after feed,
/// and again after any `advance` or `truncate` that changes the live window.
/// Implementors like `MsgHdrItem` use this to keep `mmsghdr.msg_iov` in sync.
pub trait WorkItemState: Send {
    fn set_iovecs(&mut self, iovecs: &[RawAliasedIoSlice]);
}

impl WorkItemState for () {
    fn set_iovecs(&mut self, _iovecs: &[RawAliasedIoSlice]) {}
}

/// Optional trait for transformed state that records receive byte counts.
pub trait ReceivedBytes {
    fn received_bytes(&self) -> usize;
}

pub(crate) fn raw_as_io_slices<'a>(iovecs: &'a [RawAliasedIoSlice]) -> &'a [AliasedIoSlice<'a>] {
    // Safety: both wrappers are repr(transparent) over `libc::iovec`.
    unsafe { std::slice::from_raw_parts(iovecs.as_ptr() as *const AliasedIoSlice<'a>, iovecs.len()) }
}

pub(crate) fn raw_as_io_slices_mut<'a>(
    iovecs: &'a mut [RawAliasedIoSlice],
) -> &'a mut [AliasedIoSliceMut<'a>] {
    // Safety: both wrappers are repr(transparent) over `libc::iovec`.
    unsafe {
        std::slice::from_raw_parts_mut(
            iovecs.as_mut_ptr() as *mut AliasedIoSliceMut<'a>,
            iovecs.len(),
        )
    }
}

/// No-allocation sink for transformed iovecs.
///
/// This appends directly into the shared raw-iovec arena instead of collecting
/// a temporary per-chain container first.
///
/// `'iov` is the lifetime of the iovec data (guest memory).  Only iovecs that
/// live at least as long as `'iov` can be pushed, which ties the appender to
/// the descriptor chain iterator that produces the iovecs.
pub struct IovecAppender<'s, 'iov> {
    storage: &'s mut IovecStorage,
    start: usize,
    len: usize,
    total_bytes: usize,
    _marker: std::marker::PhantomData<&'iov ()>,
}

impl<'s, 'iov> IovecAppender<'s, 'iov> {
    pub(crate) fn new(storage: &'s mut IovecStorage) -> Self {
        let start = storage.end_index();
        Self {
            storage,
            start,
            len: 0,
            total_bytes: 0,
            _marker: std::marker::PhantomData,
        }
    }

    /// Append one iovec to the shared arena.
    pub fn push(&mut self, iov: impl AnyIoSlice + 'iov) {
        if iov.is_empty() {
            return;
        }

        let raw = unsafe { RawAliasedIoSlice::from_any(iov) };
        self.total_bytes += raw.len();
        self.storage.push(raw);
        self.len += 1;
    }

    /// Append an iterator of iovecs to the shared arena.
    pub fn extend<I>(&mut self, iovecs: I)
    where
        I: IntoIterator,
        I::Item: AnyIoSlice + 'iov,
    {
        for iov in iovecs {
            self.push(iov);
        }
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub(crate) fn finish(self) -> (Range<usize>, usize) {
        (self.start..self.start + self.len, self.total_bytes)
    }
}

/// Fixed-capacity ring buffer for raw iovecs.
///
/// Chains are allocated contiguously: when the tail doesn't have enough room
/// for a chain's iovecs, it wraps to physical index 0.  The gap between the
/// old tail and the buffer end is included in the chain's `allocation` so it
/// is reclaimed when the chain is released.
pub(crate) struct IovecStorage {
    buf: Box<[RawAliasedIoSlice]>,
    /// Monotonically increasing logical head / tail.
    abs_head: usize,
    abs_tail: usize,
}

// Safety: the stored iovecs point into guest memory owned by the surrounding
// queue object.
unsafe impl Send for IovecStorage {}

impl IovecStorage {
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            buf: vec![RawAliasedIoSlice::zeroed(); cap].into_boxed_slice(),
            abs_head: 0,
            abs_tail: 0,
        }
    }

    pub(crate) fn end_index(&self) -> usize {
        self.abs_tail
    }

    /// Try to reserve `count` contiguous iovec slots for the next chain.
    ///
    /// If there isn't enough room at the physical tail, the tail wraps to 0.
    /// Returns `Some(alloc_start)` on success — the absolute index *before*
    /// any padding, so the caller can build an `allocation` range that
    /// includes the wrap gap.  Returns `None` when the ring is too full.
    pub(crate) fn begin_chain(&mut self, count: usize) -> Option<usize> {
        let cap = self.buf.len();
        let saved_tail = self.abs_tail;
        let phys_tail = self.abs_tail % cap;
        if phys_tail + count > cap {
            // wrap to physical 0 — the gap is dead space
            self.abs_tail += cap - phys_tail;
        }
        if self.abs_tail + count - self.abs_head > cap {
            // not enough free slots — undo any wrap padding
            self.abs_tail = saved_tail;
            return None;
        }
        Some(saved_tail)
    }

    pub(crate) fn push(&mut self, iov: RawAliasedIoSlice) {
        let phys = self.abs_tail % self.buf.len();
        self.buf[phys] = iov;
        self.abs_tail += 1;
    }

    pub(crate) fn slice(&self, range: Range<usize>) -> &[RawAliasedIoSlice] {
        if range.is_empty() {
            return &[];
        }
        let cap = self.buf.len();
        let start = range.start % cap;
        let len = range.end - range.start;
        debug_assert!(
            start + len <= cap,
            "slice not contiguous: phys_start={start} len={len} cap={cap}"
        );
        &self.buf[start..start + len]
    }

    pub(crate) fn slice_mut(&mut self, range: Range<usize>) -> &mut [RawAliasedIoSlice] {
        if range.is_empty() {
            return &mut [];
        }
        let cap = self.buf.len();
        let start = range.start % cap;
        let len = range.end - range.start;
        debug_assert!(
            start + len <= cap,
            "slice not contiguous: phys_start={start} len={len} cap={cap}"
        );
        &mut self.buf[start..start + len]
    }

    pub(crate) fn release_front_len(&mut self, len: usize) {
        self.abs_head += len;
        debug_assert!(self.abs_head <= self.abs_tail);
    }
}

/// Queue-owned per-chain metadata.
#[derive(Debug, Clone)]
pub(crate) struct WorkItem {
    /// Virtqueue descriptor chain head index, passed back to `add_used` on completion.
    pub(crate) head_index: u16,
    /// Total byte capacity of the transformed iovec window. Used as an upper
    /// bound for `bytes_used` and for computing remaining capacity.
    pub(crate) max_bytes: usize,
    /// Cumulative bytes consumed (TX) or written (RX) so far. For RX this is
    /// the value reported to `add_used`; may be pre-seeded during feed when the
    /// transform writes data (e.g. a vnet header) before I/O begins.
    pub(crate) bytes_used: usize,
    /// Full reservation in the iovec ring, including any dead-space gap from
    /// wrapping. `allocation_len()` is used during release to advance the ring
    /// head by the correct amount.
    pub(crate) allocation: Range<usize>,
    /// Current active iovec window within the ring. Shrinks from the front on
    /// `advance` and from the back on `truncate_bytes`.
    pub(crate) live: Range<usize>,
}

impl WorkItem {
    pub(crate) fn new(
        head_index: u16,
        max_bytes: usize,
        bytes_used: usize,
        allocation: Range<usize>,
        live: Range<usize>,
    ) -> Self {
        Self {
            head_index,
            max_bytes,
            bytes_used,
            allocation,
            live,
        }
    }

    pub(crate) fn raw_slice<'a>(&self, storage: &'a IovecStorage) -> &'a [RawAliasedIoSlice] {
        storage.slice(self.live.clone())
    }

    pub(crate) fn allocation_len(&self) -> usize {
        self.allocation.len()
    }

    pub(crate) fn advance(&mut self, storage: &mut IovecStorage, bytes: usize) {
        if bytes == 0 || self.live.is_empty() {
            return;
        }

        let mut new_start = self.live.start;
        {
            let iovecs = storage.slice_mut(self.live.clone());
            let original_len = iovecs.len();
            let remaining_len = RawAliasedIoSlice::advance_slices(iovecs, bytes).len();
            new_start += original_len - remaining_len;
        }
        self.live.start = new_start;
    }

    pub(crate) fn truncate_bytes(&mut self, storage: &mut IovecStorage, max_bytes: usize) {
        let mut remaining = max_bytes;
        let mut keep = 0;
        let start = self.live.start;

        for iov in storage.slice_mut(self.live.clone()).iter_mut() {
            let len = iov.len();
            if remaining == 0 {
                break;
            }
            if remaining < len {
                iov.shorten(remaining);
                keep += 1;
                remaining = 0;
                break;
            }
            remaining -= len;
            keep += 1;
        }

        if remaining == 0 {
            self.live.end = start + keep;
        }
    }
}
