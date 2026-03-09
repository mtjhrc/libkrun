// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! TX queue consumer for batched virtio transmit operations.

use std::ops::Range;

use vm_memory::{GuestMemory, GuestMemoryMmap};

use super::super::queue::{DescIter, DescriptorChain, Queue};
use super::super::InterruptTransport;
use super::aliased_ioslice::{AliasedIoSlice, AnyIoSlice};
use super::{raw_as_io_slices, IovecAppender, IovecStorage, WorkItem, WorkItemState};

/// Iterator over the readable slices in one descriptor chain.
pub struct ReadableChainIter<'a> {
    inner: DescIter<'a>,
}

impl<'a> ReadableChainIter<'a> {
    fn new(head: DescriptorChain<'a>) -> Self {
        Self {
            inner: head.into_iter(),
        }
    }
}

impl<'a> Iterator for ReadableChainIter<'a> {
    type Item = AliasedIoSlice<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let desc = self.inner.next()?;
            if !desc.is_read_only() {
                continue;
            }

            let len = desc.len as usize;
            let slice = desc
                .mem
                .get_slice(desc.addr, len)
                .expect("descriptor validated before transform");
            return Some(unsafe { AliasedIoSlice::from_volatile(&slice) });
        }
    }
}

/// TxQueueConsumer owns the TX queue and batches readable descriptor chains.
pub struct TxQueueConsumer<T: WorkItemState = ()> {
    queue: Queue,
    mem: GuestMemoryMmap,
    interrupt: InterruptTransport,
    max_chains: usize,
    iovecs: IovecStorage,
    work_items: Vec<WorkItem>,
    transformed: Vec<T>,
}

impl<T: WorkItemState> TxQueueConsumer<T> {
    /// Create a new TxQueueConsumer with the given queue, memory, and interrupt.
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

    /// Feed readable descriptor chains from the queue and transform them.
    ///
    /// The callback receives an iterator over the chain's readable iovecs and
    /// an [`IovecAppender`] that writes directly into the shared arena.
    pub fn feed_with_transform<F>(&mut self, mut transform: F) -> usize
    where
        F: for<'a, 'b> FnMut(ReadableChainIter<'a>, &mut IovecAppender<'b>) -> T,
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
            let Some((iov_count, guest_len)) = self.validate_readable_chain(&head) else {
                error!("Invalid descriptor chain headed by {}, skipping it", head_index);
                continue 'next_chain;
            };

            if guest_len == 0 {
                warn!("Found empty chain, ignoring it");
                continue 'next_chain;
            }

            let reserve_moved = self.iovecs.reserve(iov_count);
            let mut appender = IovecAppender::new(&mut self.iovecs);
            let state = transform(ReadableChainIter::new(head), &mut appender);
            let (allocation, append_moved, max_bytes) = appender.finish();
            let moved = reserve_moved || append_moved;

            self.work_items.push(WorkItem::new(
                head_index,
                guest_len,
                max_bytes,
                0,
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

    /// Consume pending chains using a callback that performs the actual I/O.
    ///
    /// Returns the number of chains finished by the callback.
    pub fn consume<F>(&mut self, f: F) -> usize
    where
        F: for<'a> FnOnce(&mut TxConsumerBatch<'a, T>),
    {
        if !self.has_pending() {
            return 0;
        }

        let compact_count;
        let finished_count;
        {
            let mut batch = TxConsumerBatch {
                work_items: &mut self.work_items,
                transformed: &mut self.transformed,
                iovecs: &mut self.iovecs,
                queue: &mut self.queue,
                mem: &self.mem,
                first_finished: 0,
                finished_count: 0,
            };

            f(&mut batch);
            compact_count = batch.first_finished;
            finished_count = batch.finished_count;
        }

        self.compact(compact_count);

        if finished_count > 0 {
            self.signal_used_if_needed();
        }

        finished_count
    }

    unsafe fn desc_to_volatile_ioslice(
        &self,
        desc: &DescriptorChain,
    ) -> Option<AliasedIoSlice<'_>> {
        let len = desc.len as usize;
        let slice = self.mem.get_slice(desc.addr, len).ok()?;
        Some(unsafe { AliasedIoSlice::from_volatile(&slice) })
    }

    fn validate_readable_chain(&self, head: &DescriptorChain<'_>) -> Option<(usize, usize)> {
        let mut count = 0;
        let mut total = 0;

        for desc in head.clone().into_iter().filter(DescriptorChain::is_read_only) {
            let iov = unsafe { self.desc_to_volatile_ioslice(&desc) }?;
            count += 1;
            total += iov.len();
        }

        Some((count, total))
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
            Err(e) => error!("TxQueueConsumer: needs_notification error: {e}"),
        }
    }
}

impl TxQueueConsumer<()> {
    /// Feed readable descriptor chains without extra transformed state.
    pub fn feed(&mut self) -> usize {
        self.feed_with_transform(|iovecs, out| {
            out.extend(iovecs);
        })
    }
}

/// Batch for consuming TX chains.
pub struct TxConsumerBatch<'a, T: WorkItemState> {
    work_items: &'a mut [WorkItem],
    transformed: &'a mut [T],
    iovecs: &'a mut IovecStorage,
    queue: &'a mut Queue,
    mem: &'a GuestMemoryMmap,
    /// Prefix length of consecutively finished chains.
    first_finished: usize,
    finished_count: usize,
}

impl<T: WorkItemState> TxConsumerBatch<'_, T> {
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

    pub fn io_slices(&self, index: usize) -> &[AliasedIoSlice<'_>] {
        self.assert_not_finished(index);
        raw_as_io_slices(self.work_items[index].raw_slice(self.iovecs))
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

    pub fn total_bytes(&self) -> usize {
        self.work_items
            .iter()
            .filter(|item| !item.finished)
            .map(|item| item.max_bytes.saturating_sub(item.bytes_used))
            .sum()
    }

    pub fn finish(&mut self, index: usize) {
        self.assert_not_finished(index);
        let item = &mut self.work_items[index];
        item.finished = true;
        self.finished_count += 1;

        if let Err(e) = self
            .queue
            .add_used(self.mem, item.head_index, item.guest_len as u32)
        {
            error!("TxConsumerBatch: failed to add_used: {e}");
        }

        if index == self.first_finished {
            while self.first_finished < self.work_items.len()
                && self.work_items[self.first_finished].finished
            {
                self.first_finished += 1;
            }
        }
    }

    pub fn finish_many(&mut self, range: Range<usize>) {
        for i in range {
            self.finish(i);
        }
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

#[cfg(test)]
mod tests {
    use crate::virtio::batch_queue::aliased_ioslice::{AliasedIoSlice, AnyIoSlice};
    use crate::virtio::test_utils::{create_interrupt, ExpectedUsed, TestSetup};

    use super::TxQueueConsumer;

    type TestTxConsumer = TxQueueConsumer;

    fn read_iov(iov: &AliasedIoSlice<'_>) -> Vec<u8> {
        let mut buf = vec![0u8; iov.len()];
        iov.read(&mut buf);
        buf
    }

    #[test]
    fn test_new_consumer_is_empty() {
        let setup = TestSetup::new();
        let (queue, _driver) = setup.create_queue(16);
        let consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        assert_eq!(consumer.pending_count(), 0);
        assert!(!consumer.has_pending());
    }

    #[test]
    fn test_feed_single_descriptor() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"Hello, World!"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        let added = consumer.feed();

        assert_eq!(added, 1);
        assert_eq!(consumer.pending_count(), 1);

        let finished = consumer.consume(|batch| {
            assert_eq!(batch.len(), 1);
            assert_eq!(batch.io_slices(0).len(), 1);
            assert_eq!(read_iov(&batch.io_slices(0)[0]), b"Hello, World!");
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable(13))]);
    }

    #[test]
    fn test_feed_chained_descriptors() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"First", b"Second"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        let added = consumer.feed();

        assert_eq!(added, 1);
        assert_eq!(consumer.pending_count(), 1);

        let finished = consumer.consume(|batch| {
            assert_eq!(batch.io_slices(0).len(), 2);
            assert_eq!(read_iov(&batch.io_slices(0)[0]), b"First");
            assert_eq!(read_iov(&batch.io_slices(0)[1]), b"Second");
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable(11))]);
    }

    #[test]
    fn test_feed_multiple_frames() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"Frame1"])
            .readable(&[b"Frame2"])
            .readable(&[b"Frame3"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        let added = consumer.feed();

        assert_eq!(added, 3);
        assert_eq!(consumer.pending_count(), 3);

        let finished = consumer.consume(|batch| {
            assert_eq!(batch.len(), 3);
            batch.finish_many(0..3);
        });

        assert_eq!(finished, 3);
        driver.assert_used(&[
            (0, ExpectedUsed::Readable(6)),
            (1, ExpectedUsed::Readable(6)),
            (2, ExpectedUsed::Readable(6)),
        ]);
    }

    #[test]
    fn test_feed_respects_max_chains() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"F0"])
            .readable(&[b"F1"])
            .readable(&[b"F2"])
            .readable(&[b"F3"])
            .readable(&[b"F4"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());
        consumer.set_max_chains(2);

        assert_eq!(consumer.feed(), 2);
        assert_eq!(consumer.pending_count(), 2);
        assert_eq!(consumer.feed(), 0);
    }

    #[test]
    fn test_feed_transform_callback() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"TestData12345"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        let added = consumer.feed_with_transform(|iovecs, out| {
            let mut remaining_skip = 4;
            for mut iov in iovecs {
                if remaining_skip != 0 {
                    let advance = remaining_skip.min(iov.len());
                    iov.advance(advance);
                    remaining_skip -= advance;
                }
                out.push(iov);
            }
        });

        assert_eq!(added, 1);

        consumer.consume(|batch| {
            batch.finish(0);
        });

        driver.assert_used(&[(0, ExpectedUsed::Readable(13))]);
    }

    #[test]
    fn test_consume_and_finish_all() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"FirstChain"])
            .readable(&[b"SecondChain"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();
        assert_eq!(consumer.pending_count(), 2);

        let finished = consumer.consume(|batch| {
            assert_eq!(batch.total_bytes(), 21);
            batch.finish_many(0..batch.len());
        });

        assert_eq!(finished, 2);
        assert_eq!(consumer.pending_count(), 0);
        driver.assert_used(&[
            (0, ExpectedUsed::Readable(10)),
            (1, ExpectedUsed::Readable(11)),
        ]);
    }

    #[test]
    fn test_consume_partial() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"Chain00000"])
            .readable(&[b"Chain11111"])
            .readable(&[b"Chain22222"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();

        let finished = consumer.consume(|batch| {
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        assert_eq!(consumer.pending_count(), 2);
        driver.assert_used(&[(0, ExpectedUsed::Readable(10))]);
    }

    #[test]
    fn test_compact() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();

        let finished = consumer.consume(|batch| {
            batch.finish_many(0..3);
        });

        assert_eq!(finished, 3);
        assert_eq!(consumer.pending_count(), 2);
        driver.assert_used(&[
            (0, ExpectedUsed::Readable(4)),
            (1, ExpectedUsed::Readable(4)),
            (2, ExpectedUsed::Readable(4)),
        ]);
    }

    #[test]
    fn test_empty_queue_returns_zero() {
        let setup = TestSetup::new();
        let (queue, _driver) = setup.create_queue(16);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        assert_eq!(consumer.feed(), 0);
        assert_eq!(consumer.pending_count(), 0);
        assert_eq!(consumer.consume(|_batch| {}), 0);
    }

    #[test]
    fn test_no_finish_preserves_pending() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"TestData"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();

        assert_eq!(consumer.consume(|_batch| {}), 0);
        assert_eq!(consumer.pending_count(), 1);
        driver.assert_used(&[]);
    }

    #[test]
    fn test_remove_header_byte_tracking() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);

        let mut data = vec![0x48u8; 12];
        data.extend(vec![0x50; 100]);
        driver.readable(&[&data]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        assert_eq!(
            consumer.feed_with_transform(|iovecs, out| {
                let mut remaining_skip = 12;
                for mut iov in iovecs {
                    if remaining_skip != 0 {
                        let advance = remaining_skip.min(iov.len());
                        iov.advance(advance);
                        remaining_skip -= advance;
                    }
                    out.push(iov);
                }
            }),
            1
        );

        let finished = consumer.consume(|batch| {
            let total: usize = batch.io_slices(0).iter().map(|iov| iov.len()).sum();
            assert_eq!(total, 100);
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        assert_eq!(consumer.pending_count(), 0);
        driver.assert_used(&[(0, ExpectedUsed::Readable(112))]);
    }

    #[test]
    fn test_multi_cycle_partial_writes() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);

        let mut data = vec![0x48u8; 12];
        data.extend(vec![0x50; 100]);
        driver.readable(&[&data]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        assert_eq!(
            consumer.feed_with_transform(|iovecs, out| {
                let mut remaining_skip = 12;
                for mut iov in iovecs {
                    if remaining_skip != 0 {
                        let advance = remaining_skip.min(iov.len());
                        iov.advance(advance);
                        remaining_skip -= advance;
                    }
                    out.push(iov);
                }
            }),
            1
        );

        consumer.consume(|batch| batch.advance(0, 2));
        consumer.consume(|batch| batch.advance(0, 50));
        consumer.consume(|batch| {
            batch.advance(0, 48);
            batch.finish(0);
        });

        assert_eq!(consumer.pending_count(), 0);
        driver.assert_used(&[(0, ExpectedUsed::Readable(112))]);
    }

    #[test]
    fn test_stop_resume_across_compact() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);

        let data = vec![0x50u8; 30];
        driver.readable(&[&data]).readable(&[&data]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();
        assert_eq!(consumer.pending_count(), 2);

        consumer.consume(|batch| {
            batch.finish(0);
            batch.advance(1, 15);
        });
        assert_eq!(consumer.pending_count(), 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable(30))]);

        driver.readable(&[&data]);

        consumer.feed();
        assert_eq!(consumer.pending_count(), 2);

        consumer.consume(|batch| {
            batch.finish_many(0..2);
        });
        assert_eq!(consumer.pending_count(), 0);

        driver.assert_used(&[
            (0, ExpectedUsed::Readable(30)),
            (1, ExpectedUsed::Readable(30)),
            (2, ExpectedUsed::Readable(30)),
        ]);
    }

    #[test]
    fn test_out_of_order_finish() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"pkt0"])
            .readable(&[b"pkt1"])
            .readable(&[b"pkt2"])
            .readable(&[b"pkt3"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();
        assert_eq!(consumer.pending_count(), 4);

        let finished = consumer.consume(|batch| {
            batch.finish(3);
            batch.finish(1);
        });

        assert_eq!(finished, 2);
        assert_eq!(consumer.pending_count(), 4);
        driver.assert_used(&[
            (3, ExpectedUsed::ReadableAnyLen),
            (1, ExpectedUsed::ReadableAnyLen),
        ]);

        let finished = consumer.consume(|batch| {
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        assert_eq!(consumer.pending_count(), 2);

        let finished = consumer.consume(|batch| {
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        assert_eq!(consumer.pending_count(), 0);
        driver.assert_used(&[
            (3, ExpectedUsed::ReadableAnyLen),
            (1, ExpectedUsed::ReadableAnyLen),
            (0, ExpectedUsed::ReadableAnyLen),
            (2, ExpectedUsed::ReadableAnyLen),
        ]);
    }

    #[test]
    #[should_panic(expected = "already finished")]
    fn test_double_finish_panics() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"data"]);

        let mut consumer: TestTxConsumer =
            TxQueueConsumer::new(queue, setup.mem().clone(), create_interrupt());

        consumer.feed();
        consumer.consume(|batch| {
            batch.finish(0);
            batch.finish(0);
        });
    }
}
