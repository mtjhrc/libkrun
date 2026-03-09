// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Batched virtio queue producer/consumer infrastructure.
//!
//! Raw iovecs always live in one shared contiguous arena owned by the batch
//! queue. Per-chain metadata stores only ranges into that arena. Optional
//! user-transformed state lives in a separate array aligned with the work
//! items, so pointer-bearing state like `mmsghdr` can be rebuilt whenever the
//! arena moves.

use std::alloc::{self, Layout};
use std::ops::Range;
use std::ptr::NonNull;

use aliased_ioslice::{AliasedIoSlice, AliasedIoSliceMut, AnyIoSlice, RawAliasedIoSlice};
use ioslice_container_utils::SliceOfIoSlicesExt;

pub mod aliased_ioslice;
pub mod ioslice_container_utils;
mod rx_queue_producer;
mod tx_queue_consumer;

pub use rx_queue_producer::{RxProducerBatch, RxQueueProducer};
pub use tx_queue_consumer::{TxConsumerBatch, TxQueueConsumer};

/// Compact reclaimed prefix once it becomes meaningfully large.
const IOVEC_COMPACT_THRESHOLD: usize = 64;

/// Optional user-owned transformed state aligned 1:1 with the work items.
///
/// The transform callback receives an iterator over the descriptor chain and an
/// [`IovecAppender`] that writes directly into the queue-owned raw iovec arena.
/// If the state needs pointers into that arena, rebuild them here from the
/// current live slice.
pub trait WorkItemState: Send {
    fn fixup_iovecs(&mut self, iovecs: &[RawAliasedIoSlice]);
}

impl WorkItemState for () {
    fn fixup_iovecs(&mut self, _iovecs: &[RawAliasedIoSlice]) {}
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
pub struct IovecAppender<'a> {
    storage: &'a mut IovecStorage,
    start: usize,
    len: usize,
    total_bytes: usize,
    moved: bool,
}

impl<'a> IovecAppender<'a> {
    pub(crate) fn new(storage: &'a mut IovecStorage) -> Self {
        let start = storage.end_index();
        Self {
            storage,
            start,
            len: 0,
            total_bytes: 0,
            moved: false,
        }
    }

    /// Append one iovec to the shared arena.
    pub fn push(&mut self, iov: impl AnyIoSlice) {
        if iov.is_empty() {
            return;
        }

        let raw = unsafe { RawAliasedIoSlice::from_any(iov) };
        self.total_bytes += raw.len();
        self.moved |= self.storage.push(raw);
        self.len += 1;
    }

    /// Append an iterator of iovecs to the shared arena.
    pub fn extend<I>(&mut self, iovecs: I)
    where
        I: IntoIterator,
        I::Item: AnyIoSlice,
    {
        for iov in iovecs {
            self.push(iov);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub(crate) fn finish(self) -> (Range<usize>, bool, usize) {
        (self.start..self.start + self.len, self.moved, self.total_bytes)
    }
}

/// Manual heap array for the shared raw-iovec arena.
pub(crate) struct RawIovecArray {
    ptr: NonNull<RawAliasedIoSlice>,
    len: usize,
    cap: usize,
}

impl Default for RawIovecArray {
    fn default() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            cap: 0,
        }
    }
}

// Safety: the stored iovecs point into guest memory owned by the surrounding
// queue object.
unsafe impl Send for RawIovecArray {}

impl RawIovecArray {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        if capacity == 0 {
            return Self::default();
        }

        let layout = Layout::array::<RawAliasedIoSlice>(capacity).unwrap();
        let ptr = unsafe { alloc::alloc(layout) as *mut RawAliasedIoSlice };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| alloc::handle_alloc_error(layout));

        Self {
            ptr,
            len: 0,
            cap: capacity,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[RawAliasedIoSlice] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [RawAliasedIoSlice] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    fn extend_from_slice(&mut self, data: &[RawAliasedIoSlice]) -> bool {
        if data.is_empty() {
            return false;
        }

        let moved = self.reserve(data.len());
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.ptr.as_ptr().add(self.len),
                data.len(),
            );
        }
        self.len += data.len();
        moved
    }

    fn reserve(&mut self, additional: usize) -> bool {
        let required = self.len + additional;
        if required <= self.cap {
            return false;
        }

        let new_cap = required.max(self.cap.saturating_mul(2)).max(8);
        let new_layout = Layout::array::<RawAliasedIoSlice>(new_cap).unwrap();
        let new_ptr = unsafe { alloc::alloc(new_layout) as *mut RawAliasedIoSlice };
        let new_ptr = NonNull::new(new_ptr).unwrap_or_else(|| alloc::handle_alloc_error(new_layout));

        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.as_ptr(), new_ptr.as_ptr(), self.len);
        }

        if self.cap > 0 {
            let old_layout = Layout::array::<RawAliasedIoSlice>(self.cap).unwrap();
            unsafe {
                alloc::dealloc(self.ptr.as_ptr() as *mut u8, old_layout);
            }
        }

        self.ptr = new_ptr;
        self.cap = new_cap;
        true
    }

    fn drain_prefix(&mut self, count: usize) {
        assert!(count <= self.len);
        if count == 0 {
            return;
        }

        let remaining = self.len - count;
        unsafe {
            std::ptr::copy(self.ptr.as_ptr().add(count), self.ptr.as_ptr(), remaining);
        }
        self.len = remaining;
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

impl Drop for RawIovecArray {
    fn drop(&mut self) {
        if self.cap == 0 {
            return;
        }

        let layout = Layout::array::<RawAliasedIoSlice>(self.cap).unwrap();
        unsafe {
            alloc::dealloc(self.ptr.as_ptr() as *mut u8, layout);
        }
    }
}

/// Shared contiguous raw-iovec storage.
#[derive(Default)]
pub(crate) struct IovecStorage {
    storage: RawIovecArray,
    /// Absolute index of `storage[0]`.
    base_index: usize,
    /// Number of fully released entries still resident at the front.
    reclaimed_prefix: usize,
}

impl IovecStorage {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            storage: RawIovecArray::with_capacity(capacity),
            base_index: 0,
            reclaimed_prefix: 0,
        }
    }

    pub(crate) fn end_index(&self) -> usize {
        self.base_index + self.storage.len()
    }

    pub(crate) fn reserve(&mut self, additional: usize) -> bool {
        self.storage.reserve(additional)
    }

    pub(crate) fn push(&mut self, iov: RawAliasedIoSlice) -> bool {
        self.storage.extend_from_slice(std::slice::from_ref(&iov))
    }

    pub(crate) fn slice(&self, range: Range<usize>) -> &[RawAliasedIoSlice] {
        let physical = self.physical_range(range);
        &self.storage.as_slice()[physical]
    }

    pub(crate) fn slice_mut(&mut self, range: Range<usize>) -> &mut [RawAliasedIoSlice] {
        let physical = self.physical_range(range);
        &mut self.storage.as_mut_slice()[physical]
    }

    pub(crate) fn release_front_len(&mut self, len: usize) -> bool {
        if len == 0 {
            return false;
        }

        debug_assert!(self.reclaimed_prefix + len <= self.storage.len());
        self.reclaimed_prefix += len;
        self.maybe_compact()
    }

    fn physical_range(&self, range: Range<usize>) -> Range<usize> {
        debug_assert!(range.start >= self.base_index);
        debug_assert!(range.end >= range.start);
        debug_assert!(range.end <= self.base_index + self.storage.len());
        (range.start - self.base_index)..(range.end - self.base_index)
    }

    fn maybe_compact(&mut self) -> bool {
        if self.reclaimed_prefix == 0 {
            return false;
        }

        if self.reclaimed_prefix == self.storage.len() {
            self.storage.clear();
            self.base_index += self.reclaimed_prefix;
            self.reclaimed_prefix = 0;
            return false;
        }

        if self.reclaimed_prefix < IOVEC_COMPACT_THRESHOLD
            && self.reclaimed_prefix * 2 < self.storage.len()
        {
            return false;
        }

        self.storage.drain_prefix(self.reclaimed_prefix);
        self.base_index += self.reclaimed_prefix;
        self.reclaimed_prefix = 0;
        true
    }
}

/// Queue-owned per-chain metadata.
#[derive(Debug, Clone)]
pub(crate) struct WorkItem {
    pub(crate) head_index: u16,
    pub(crate) guest_len: usize,
    pub(crate) max_bytes: usize,
    pub(crate) bytes_used: usize,
    pub(crate) finished: bool,
    /// Full reservation in the shared arena. Kept until the chain is drained.
    pub(crate) allocation: Range<usize>,
    /// Live iovec window for the current partial progress state.
    pub(crate) live: Range<usize>,
}

impl WorkItem {
    pub(crate) fn new(
        head_index: u16,
        guest_len: usize,
        max_bytes: usize,
        bytes_used: usize,
        allocation: Range<usize>,
    ) -> Self {
        Self {
            head_index,
            guest_len,
            max_bytes,
            bytes_used,
            finished: false,
            live: allocation.clone(),
            allocation,
        }
    }

    pub(crate) fn raw_slice<'a>(&self, storage: &'a IovecStorage) -> &'a [RawAliasedIoSlice] {
        storage.slice(self.live.clone())
    }

    pub(crate) fn allocation_len(&self) -> usize {
        self.allocation.end - self.allocation.start
    }

    pub(crate) fn advance(&mut self, storage: &mut IovecStorage, bytes: usize) {
        if bytes == 0 || self.live.is_empty() {
            return;
        }

        let mut new_start = self.live.start;
        {
            let iovecs = storage.slice_mut(self.live.clone());
            let original_len = iovecs.len();
            let remaining_len = iovecs.advance(bytes).len();
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
                unsafe {
                    iov.set_len(remaining);
                }
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
