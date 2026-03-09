// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RX queue producer for batched virtio receive operations.

use std::ops::Range;

use vm_memory::{GuestMemory, GuestMemoryMmap};

use super::super::queue::{DescIter, DescriptorChain, Queue};
use super::super::InterruptTransport;
use super::aliased_ioslice::{AliasedIoSliceMut, AnyIoSlice};
use super::ioslice_container_utils::SliceOfIoSlicesExt;
use super::{
    raw_as_io_slices_mut, IovecAppender, IovecStorage, ReceivedBytes, WorkItem, WorkItemState,
};

/// Iterator over the writable slices in one descriptor chain.
pub struct WritableChainIter<'a> {
    inner: DescIter<'a>,
}

impl<'a> WritableChainIter<'a> {
    fn new(head: DescriptorChain<'a>) -> Self {
        Self {
            inner: head.into_iter(),
        }
    }
}

impl<'a> Iterator for WritableChainIter<'a> {
    type Item = AliasedIoSliceMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let desc = self.inner.next()?;
            if !desc.is_write_only() {
                continue;
            }

            let len = desc.len as usize;
            let slice = desc
                .mem
                .get_slice(desc.addr, len)
                .expect("descriptor validated before transform");
            return Some(unsafe { AliasedIoSliceMut::from_volatile(&slice) });
        }
    }
}

/// RxQueueProducer owns the RX queue and batches writable descriptor chains.
pub struct RxQueueProducer<T: WorkItemState = ()> {
    queue: Queue,
    mem: GuestMemoryMmap,
    interrupt: InterruptTransport,
    max_chains: usize,
    iovecs: IovecStorage,
    work_items: Vec<WorkItem>,
    transformed: Vec<T>,
}

impl<T: WorkItemState> RxQueueProducer<T> {
    /// Create a new RxQueueProducer with the given queue, memory, and interrupt.
    pub fn new(queue: Queue, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> Self {
        let max_chains = queue.size as usize * 8;
        Self {
            queue,
            mem,
            interrupt,
            max_chains,
            iovecs: IovecStorage::with_capacity(max_chains * 4),
            work_items: Vec::with_capacity(max_chains),
            transformed: Vec::with_capacity(max_chains),
        }
    }

    /// Set the maximum number of chains to keep pending at once.
    pub fn set_max_chains(&mut self, max: usize) {
        self.max_chains = max;
        self.work_items.reserve(max.saturating_sub(self.work_items.capacity()));
        self.transformed
            .reserve(max.saturating_sub(self.transformed.capacity()));
    }

    /// Feed writable descriptor chains from the queue and transform them.
    pub fn feed_with_transform<F>(&mut self, mut transform: F) -> usize
    where
        F: for<'a, 'b> FnMut(WritableChainIter<'a>, &mut IovecAppender<'b>) -> T,
    {
        let mut added = 0;

        if let Err(e) = self.queue.disable_notification(&self.mem) {
            warn!("Failed to disable queue notifications: {e:?}");
        }

        'next_chain: while self.pending_count() < self.max_chains {
            let Some(head) = self.queue.pop(&self.mem) else {
                match self.queue.enable_notification(&self.mem) {
                    Ok(true) => continue 'next_chain,
                    Ok(false) => break 'next_chain,
                    Err(e) => {
                        error!("Failed to re-enable queue notifications: {e:?}");
                        break 'next_chain;
                    }
                }
            };

            let head_index = head.index;
            let Some((iov_count, max_bytes)) = self.validate_writable_chain(&head) else {
                error!("Invalid descriptor chain headed by {}, skipping it", head_index);
                continue 'next_chain;
            };

            if max_bytes == 0 {
                warn!("Found empty chain, ignoring it");
                continue 'next_chain;
            }

            let reserve_moved = self.iovecs.reserve(iov_count);
            let mut appender = IovecAppender::new(&mut self.iovecs);
            let state = transform(WritableChainIter::new(head), &mut appender);
            let (allocation, append_moved, transformed_bytes) = appender.finish();
            let moved = reserve_moved || append_moved;
            let bytes_used = max_bytes - transformed_bytes;

            self.work_items.push(WorkItem::new(
                head_index,
                max_bytes,
                max_bytes,
                bytes_used,
                allocation,
            ));
            self.transformed.push(state);

            if moved {
                self.fixup_all_transformed();
            } else {
                self.fixup_transformed(self.work_items.len() - 1);
            }

            added += 1;
        }

        added
    }

    /// Number of chains pending.
    pub fn pending_count(&self) -> usize {
        self.work_items.len()
    }

    /// Check if there are any pending chains.
    pub fn has_pending(&self) -> bool {
        !self.work_items.is_empty()
    }

    unsafe fn desc_to_volatile_ioslice_mut(
        &self,
        desc: &DescriptorChain,
    ) -> Option<AliasedIoSliceMut<'_>> {
        let len = desc.len as usize;
        let slice = self.mem.get_slice(desc.addr, len).ok()?;
        Some(unsafe { AliasedIoSliceMut::from_volatile(&slice) })
    }

    fn validate_writable_chain(&self, head: &DescriptorChain<'_>) -> Option<(usize, usize)> {
        let mut count = 0;
        let mut total = 0;

        for desc in head.clone().into_iter().filter(DescriptorChain::is_write_only) {
            let iov = unsafe { self.desc_to_volatile_ioslice_mut(&desc) }?;
            count += 1;
            total += iov.len();
        }

        Some((count, total))
    }

    /// Produce frames by calling the callback with a batch.
    pub fn produce<F>(&mut self, f: F) -> usize
    where
        F: for<'a> FnOnce(&mut RxProducerBatch<'a, T>),
    {
        if !self.has_pending() {
            return 0;
        }

        let compact_count;
        let finished_count;
        {
            let mut batch = RxProducerBatch {
                work_items: &mut self.work_items,
                transformed: &mut self.transformed,
                iovecs: &mut self.iovecs,
                queue: &mut self.queue,
                mem: &self.mem,
                first_unfinished: 0,
                finished_count: 0,
            };

            f(&mut batch);
            compact_count = batch.first_unfinished;
            finished_count = batch.finished_count;
        }

        self.compact(compact_count);

        if finished_count > 0 {
            self.signal_used_if_needed();
        }

        finished_count
    }

    fn compact(&mut self, count: usize) {
        if count == 0 {
            return;
        }

        let released = self.work_items[..count]
            .iter()
            .map(WorkItem::allocation_len)
            .sum();

        self.work_items.drain(..count);
        self.transformed.drain(..count);

        if self.iovecs.release_front_len(released) {
            self.fixup_all_transformed();
        }
    }

    fn fixup_transformed(&mut self, index: usize) {
        let iovecs = self.work_items[index].raw_slice(&self.iovecs);
        self.transformed[index].fixup_iovecs(iovecs);
    }

    fn fixup_all_transformed(&mut self) {
        for (item, transformed) in self.work_items.iter().zip(self.transformed.iter_mut()) {
            transformed.fixup_iovecs(item.raw_slice(&self.iovecs));
        }
    }

    fn signal_used_if_needed(&mut self) {
        match self.queue.needs_notification(&self.mem) {
            Ok(true) => self.interrupt.signal_used_queue(),
            Ok(false) => {}
            Err(e) => error!("RxQueueProducer: needs_notification error: {e}"),
        }
    }
}

impl RxQueueProducer<()> {
    /// Feed writable descriptor chains without extra transformed state.
    pub fn feed(&mut self) -> usize {
        self.feed_with_transform(|iovecs, out| {
            out.extend(iovecs);
        })
    }
}

/// Batch for producing RX chains.
pub struct RxProducerBatch<'a, T: WorkItemState> {
    work_items: &'a mut [WorkItem],
    transformed: &'a mut [T],
    iovecs: &'a mut IovecStorage,
    queue: &'a mut Queue,
    mem: &'a GuestMemoryMmap,
    /// Prefix length of consecutively finished chains.
    first_unfinished: usize,
    finished_count: usize,
}

impl<T: WorkItemState> RxProducerBatch<'_, T> {
    #[inline]
    pub fn len(&self) -> usize {
        self.work_items.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.work_items.is_empty()
    }

    #[inline]
    pub fn is_finished(&self, index: usize) -> bool {
        self.work_items[index].finished
    }

    #[inline]
    pub fn bytes_used(&self, index: usize) -> usize {
        self.work_items[index].bytes_used
    }

    #[inline]
    pub fn max_bytes(&self, index: usize) -> usize {
        self.work_items[index].max_bytes
    }

    pub fn transformed(&self, range: Range<usize>) -> &[T] {
        self.assert_range_not_finished(range.clone());
        &self.transformed[range]
    }

    pub fn transformed_mut(&mut self, range: Range<usize>) -> &mut [T] {
        self.assert_range_not_finished(range.clone());
        &mut self.transformed[range]
    }

    pub fn transformed_item(&self, index: usize) -> &T {
        &self.transformed[index]
    }

    pub fn transformed_item_mut(&mut self, index: usize) -> &mut T {
        &mut self.transformed[index]
    }

    pub fn io_slices_mut(&mut self, index: usize) -> &mut [AliasedIoSliceMut<'_>] {
        self.assert_not_finished(index);
        let live = self.work_items[index].live.clone();
        raw_as_io_slices_mut(self.iovecs.slice_mut(live))
    }

    pub fn finish_many(&mut self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }

        let range_start = range.start;
        let range_end = range.end;
        let count = range_end - range_start;

        for index in range {
            self.assert_not_finished(index);
            let item = &mut self.work_items[index];
            item.finished = true;

            if let Err(e) = self
                .queue
                .add_used(self.mem, item.head_index, item.bytes_used as u32)
            {
                error!("failed to add_used: {e}");
            }
        }

        self.finished_count += count;

        if range_start == self.first_unfinished {
            self.first_unfinished = range_end;
            while self.first_unfinished < self.work_items.len()
                && self.work_items[self.first_unfinished].finished
            {
                self.first_unfinished += 1;
            }
        }
    }

    pub fn finish(&mut self, index: usize) {
        self.finish_many(index..index + 1);
    }

    pub fn complete(&mut self, index: usize, bytes: usize) {
        self.assert_not_finished(index);
        let item = &mut self.work_items[index];
        item.bytes_used += bytes;
        debug_assert!(
            item.bytes_used <= item.max_bytes,
            "complete: bytes_used {} exceeds max_bytes {}",
            item.bytes_used,
            item.max_bytes
        );
        self.finish(index);
    }

    pub fn advance(&mut self, index: usize, bytes: usize) {
        self.assert_not_finished(index);
        let item = &mut self.work_items[index];
        item.bytes_used += bytes;
        debug_assert!(
            item.bytes_used <= item.max_bytes,
            "advance: bytes_used {} exceeds max_bytes {}",
            item.bytes_used,
            item.max_bytes
        );
        item.advance(self.iovecs, bytes);
        let iovecs = item.raw_slice(self.iovecs);
        self.transformed[index].fixup_iovecs(iovecs);
    }

    pub fn truncate(&mut self, index: usize, max_bytes: usize) {
        self.assert_not_finished(index);
        let item = &mut self.work_items[index];
        item.truncate_bytes(self.iovecs, max_bytes);
        let iovecs = item.raw_slice(self.iovecs);
        self.transformed[index].fixup_iovecs(iovecs);
    }

    #[allow(clippy::result_unit_err)]
    pub fn write_advance(&mut self, index: usize, data: &[u8]) -> Result<(), ()> {
        let written = self.io_slices_mut(index).write(data);
        if written != data.len() {
            return Err(());
        }
        self.advance(index, written);
        Ok(())
    }

    #[allow(clippy::result_unit_err)]
    pub fn write_complete(&mut self, index: usize, data: &[u8]) -> Result<(), ()> {
        let written = self.io_slices_mut(index).write(data);
        if written != data.len() {
            return Err(());
        }
        self.complete(index, written);
        Ok(())
    }

    #[track_caller]
    fn assert_not_finished(&self, index: usize) {
        assert!(!self.is_finished(index), "chain at index {index} already finished");
    }

    #[track_caller]
    fn assert_range_not_finished(&self, range: Range<usize>) {
        for index in range {
            self.assert_not_finished(index);
        }
    }
}

impl<T: WorkItemState + ReceivedBytes> RxProducerBatch<'_, T> {
    pub fn complete_received(&mut self, index: usize) {
        self.complete_received_many(index..index + 1);
    }

    pub fn complete_received_many(&mut self, range: Range<usize>) {
        for index in range.clone() {
            let item = &mut self.work_items[index];
            item.bytes_used += self.transformed[index].received_bytes();
            debug_assert!(
                item.bytes_used <= item.max_bytes,
                "complete_received_many: bytes_used {} exceeds max_bytes {}",
                item.bytes_used,
                item.max_bytes
            );
        }
        self.finish_many(range);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use crate::virtio::batch_queue::aliased_ioslice::{AnyIoSlice, RawAliasedIoSlice};
    use crate::virtio::batch_queue::ioslice_container_utils::SliceOfIoSlicesExt;
    use crate::virtio::batch_queue::{ReceivedBytes, WorkItemState};
    use crate::virtio::test_utils::{create_interrupt, ExpectedUsed, TestSetup};

    use super::RxQueueProducer;

    type TestRxProducer = RxQueueProducer;

    #[test]
    fn test_initial_state() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        assert_eq!(producer.pending_count(), 0);
        assert_eq!(producer.feed(), 0);
        assert_eq!(producer.produce(|_batch| {}), 0);
        driver.assert_used(&[]);
    }

    #[test]
    fn test_feed_single_writable_descriptor() {
        let setup = TestSetup::new();
        let (queue, _driver) = setup.create_queue(16);
        _driver.writable(&[1500]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        assert_eq!(producer.feed(), 1);
        assert_eq!(producer.pending_count(), 1);
    }

    #[test]
    fn test_feed_chained_writable_descriptors() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.writable(&[512, 1024]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        assert_eq!(producer.feed(), 1);
        assert_eq!(producer.pending_count(), 1);

        producer.produce(|batch| {
            let chain = batch.io_slices_mut(0);
            assert_eq!(chain.len(), 2);
            assert_eq!(chain[0].len(), 512);
            assert_eq!(chain[1].len(), 1024);
        });

        driver.assert_used(&[]);
    }

    #[test]
    fn test_feed_respects_max_frames() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());
        producer.set_max_chains(2);

        assert_eq!(producer.feed(), 2);
        assert_eq!(producer.pending_count(), 2);
    }

    #[test]
    fn test_produce_via_write_bytes() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.writable(&[10, 90]).writable(&[100]).writable(&[100]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        producer.feed();

        let completed = producer.produce(|batch| {
            assert_eq!(batch.max_bytes(0), 100);
            batch.write_complete(0, b"Received packet 1").unwrap();
            assert_eq!(batch.bytes_used(0), 17);

            assert_eq!(batch.max_bytes(1), 100);
            batch.write_complete(1, b"Received packet 2").unwrap();
            assert_eq!(batch.bytes_used(1), 17);

            assert_eq!(batch.max_bytes(2), 100);
            assert_eq!(batch.bytes_used(2), 0);
        });

        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 1);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"Received packet 1")),
            (1, ExpectedUsed::Writable(b"Received packet 2")),
        ]);
    }

    #[test]
    fn test_multiple_produce_cycles() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(32);

        driver
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        let feed_with_hdr = |p: &mut TestRxProducer| {
            p.feed_with_transform(|iovecs, out| {
                let mut header = b"HD".as_slice();
                for mut iov in iovecs {
                    if !header.is_empty() {
                        let written = iov.write(header);
                        header = &header[written..];
                        iov.advance(written);
                    }
                    out.push(iov);
                }
            })
        };

        assert_eq!(feed_with_hdr(&mut producer), 3);
        assert_eq!(producer.pending_count(), 3);

        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"aaaaaaaaaaaaaaaaaa").unwrap();

            let written = batch.io_slices_mut(1).write(b"bbbb");
            assert_eq!(written, 4);
            batch.advance(1, 4);
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 2);
        driver.assert_used(&[(0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa"))]);

        driver
            .writable(&[1, 1, 3, 3, 12, 6])
            .writable(&[6, 12, 6]);
        assert_eq!(feed_with_hdr(&mut producer), 2);
        assert_eq!(producer.pending_count(), 4);

        let completed = producer.produce(|batch| {
            let written = batch.io_slices_mut(0).write(b"bbbbbbbb");
            assert_eq!(written, 8);
            batch.complete(0, 8);
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 3);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa")),
            (1, ExpectedUsed::Writable(b"HDbbbbbbbbbbbb")),
        ]);

        let completed = producer.produce(|batch| {
            assert_eq!(batch.len(), 3);
            batch.write_complete(0, b"cccccccccccc").unwrap();
            batch.write_complete(1, b"dddddd").unwrap();
        });
        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 1);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa")),
            (1, ExpectedUsed::Writable(b"HDbbbbbbbbbbbb")),
            (2, ExpectedUsed::Writable(b"HDcccccccccccc")),
            (3, ExpectedUsed::Writable(b"HDdddddd")),
        ]);

        driver.writable(&[6, 12, 6]);
        assert_eq!(feed_with_hdr(&mut producer), 1);
        assert_eq!(producer.pending_count(), 2);

        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"eeee").unwrap();
            batch.write_complete(1, b"ffff").unwrap();
        });
        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 0);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa")),
            (1, ExpectedUsed::Writable(b"HDbbbbbbbbbbbb")),
            (2, ExpectedUsed::Writable(b"HDcccccccccccc")),
            (3, ExpectedUsed::Writable(b"HDdddddd")),
            (4, ExpectedUsed::Writable(b"HDeeee")),
            (5, ExpectedUsed::Writable(b"HDffff")),
        ]);
    }

    #[test]
    fn test_out_of_order_completion() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .writable(&[2, 2])
            .writable(&[2, 2])
            .writable(&[2, 2])
            .writable(&[2, 2]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        producer.feed();

        let completed = producer.produce(|batch| {
            batch.write_complete(3, b"pkt3").unwrap();
            batch.write_complete(1, b"pkt1").unwrap();
        });

        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 4);
        driver.assert_used(&[
            (3, ExpectedUsed::Writable(b"pkt3")),
            (1, ExpectedUsed::Writable(b"pkt1")),
        ]);

        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"pkt0").unwrap();
        });

        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 2);

        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"pkt2").unwrap();
        });

        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 0);
        driver.assert_used(&[
            (3, ExpectedUsed::Writable(b"pkt3")),
            (1, ExpectedUsed::Writable(b"pkt1")),
            (0, ExpectedUsed::Writable(b"pkt0")),
            (2, ExpectedUsed::Writable(b"pkt2")),
        ]);
    }

    #[derive(Default)]
    struct CustomState {
        tag: u32,
        received_len: Cell<usize>,
    }

    impl WorkItemState for CustomState {
        fn fixup_iovecs(&mut self, _iovecs: &[RawAliasedIoSlice]) {}
    }

    impl ReceivedBytes for CustomState {
        fn received_bytes(&self) -> usize {
            self.received_len.get()
        }
    }

    #[test]
    fn test_complete_received_many() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .writable(&[100])
            .writable(&[100])
            .writable(&[100])
            .writable(&[100]);

        let mut producer: RxQueueProducer<CustomState> =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        let mut tag = 0u32;
        let added = producer.feed_with_transform(|iovecs, out| {
            tag += 10;
            out.extend(iovecs);
            CustomState {
                tag,
                received_len: Cell::new(0),
            }
        });
        assert_eq!(added, 4);

        let completed = producer.produce(|batch| {
            assert_eq!(batch.len(), 4);
            assert_eq!(batch.transformed_item(0).tag, 10);
            assert_eq!(batch.transformed_item(1).tag, 20);
            assert_eq!(batch.transformed_item(2).tag, 30);
            assert_eq!(batch.transformed_item(3).tag, 40);

            let written = batch.io_slices_mut(0).write(b"aaaa");
            batch.transformed_item_mut(0).received_len.set(written);

            let written = batch.io_slices_mut(1).write(b"bbbbbbbb");
            batch.transformed_item_mut(1).received_len.set(written);

            let written = batch.io_slices_mut(3).write(b"dddddddddddd");
            batch.transformed_item_mut(3).received_len.set(written);

            batch.complete_received_many(0..2);
            batch.complete_received(3);
        });
        assert_eq!(completed, 3);
        assert_eq!(producer.pending_count(), 2);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"aaaa")),
            (1, ExpectedUsed::Writable(b"bbbbbbbb")),
            (3, ExpectedUsed::Writable(b"dddddddddddd")),
        ]);

        let completed = producer.produce(|batch| {
            assert_eq!(batch.len(), 2);
            assert_eq!(batch.transformed_item(0).tag, 30);
            assert_eq!(batch.transformed_item(1).tag, 40);

            let written = batch.io_slices_mut(0).write(b"cccccc");
            batch.transformed_item_mut(0).received_len.set(written);
            batch.complete_received(0);
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 0);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"aaaa")),
            (1, ExpectedUsed::Writable(b"bbbbbbbb")),
            (3, ExpectedUsed::Writable(b"dddddddddddd")),
            (2, ExpectedUsed::Writable(b"cccccc")),
        ]);
    }

    #[test]
    #[should_panic(expected = "already finished")]
    fn test_double_finish_panics() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.writable(&[100]);

        let mut producer: TestRxProducer =
            RxQueueProducer::new(queue, setup.mem().clone(), create_interrupt());

        producer.feed();
        producer.produce(|batch| {
            batch.complete(0, 10);
            batch.complete(0, 10);
        });
    }
}
