// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RX queue producer for batched virtio receive operations.

use std::io::IoSliceMut;

use smallvec::SmallVec;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap};

use super::iovec_utils::write_to_iovecs;
use super::queue::{DescriptorChain, Queue};
use super::InterruptTransport;

/// A pending descriptor chain with its state.
struct PendingChain {
    head_index: u16,
    max_bytes: usize,
    bytes_used: usize,
    finished: bool,
}

/// RxQueueProducer - owns the RX queue and provides buffers for receiving.
///
/// Pops descriptor chains from the virtio RX queue and provides writable
/// iovecs for receiving data. Unfinished chains are kept pending for the next
/// produce() call; finished chains get add_used() with their byte counts.
pub struct RxQueueProducer {
    /// The virtio RX queue
    queue: Queue,
    /// Guest memory reference
    mem: GuestMemoryMmap,
    /// Interrupt for signaling guest
    interrupt: InterruptTransport,

    /// Pending chains with their state
    pending_chains: SmallVec<[PendingChain; 32]>,
    /// Writable iovecs for each pending descriptor chain
    /// the 'static is a lie! - see feed_with_transform
    pending_iovecs: SmallVec<[SmallVec<[IoSliceMut<'static>; 4]>; 32]>,
}

/// Batch for reporting received bytes per chain.
///
/// Provides access to chains and methods to mark them as complete.
/// Panics if you access or finish an already-finished chain.
pub struct RxProducerBatch<'a> {
    pending_chains: &'a mut [PendingChain],
    pending_iovecs: &'a mut [SmallVec<[IoSliceMut<'static>; 4]>],
    queue: &'a mut Queue,
    mem: &'a GuestMemoryMmap,
}

/// Advance iovecs in place by `bytes`, removing fully consumed buffers.
fn advance_iovecs<'a>(iovecs: &mut SmallVec<[IoSliceMut<'a>; 4]>, bytes: usize) {
    let mut remaining = bytes;
    while remaining > 0 && !iovecs.is_empty() {
        let first_len = iovecs[0].len();
        if first_len <= remaining {
            iovecs.remove(0);
            remaining -= first_len;
        } else {
            let first = &mut iovecs[0];
            let ptr = first.as_mut_ptr();
            let new_len = first_len - remaining;
            // Safety: advancing pointer within same allocation
            let new_slice = unsafe { std::slice::from_raw_parts_mut(ptr.add(remaining), new_len) };
            iovecs[0] = IoSliceMut::new(new_slice);
            remaining = 0;
        }
    }
}

impl RxProducerBatch<'_> {
    /// Number of pending chains.
    #[inline]
    pub fn len(&self) -> usize {
        self.pending_chains.len()
    }

    /// Returns true if there are no pending chains.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pending_chains.is_empty()
    }

    /// Get chain by index. Panics if already finished.
    ///
    /// # Lifetime guarantee
    ///
    /// The returned chain is guaranteed to remain valid and at a stable memory
    /// location until `finish()` or `complete()` is called for this index.
    /// This is important for unsafe code that takes raw pointers to the iovecs
    /// (e.g., for recvmmsg/sendmmsg).
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn chain_mut(&mut self, index: usize) -> &mut SmallVec<[IoSliceMut<'_>; 4]> {
        assert!(
            !self.pending_chains[index].finished,
            "chain_mut: chain at index {} already finished",
            index
        );
        // Safety: We're returning a reference with a shorter lifetime than 'static,
        // which is safe. The caller sees IoSliceMut<'_> tied to our borrow.
        unsafe {
            &mut *(&mut self.pending_iovecs[index]
                as *mut SmallVec<[IoSliceMut<'static>; 4]>
                as *mut SmallVec<[IoSliceMut<'_>; 4]>)
        }
    }

    /// Write data to chain and advance (without finishing). Returns bytes written.
    ///
    /// This is a convenience method for partial receives where you need to write
    /// some data (like a header) but the frame is not yet complete.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn write_advance(&mut self, index: usize, data: &[u8]) -> usize {
        let written = write_to_iovecs(self.chain_mut(index), data);
        if written > 0 {
            self.advance(index, written);
        }
        written
    }

    /// Write data to chain and complete it. Returns error if data doesn't fit.
    ///
    /// This is a convenience method that writes the data, advances bytes_used,
    /// and finishes the chain in one call.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` if the chain doesn't have enough space for all the data.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn write_complete(&mut self, index: usize, data: &[u8]) -> Result<(), ()> {
        let written = write_to_iovecs(self.chain_mut(index), data);
        if written != data.len() {
            return Err(());
        }
        self.complete(index, written);
        Ok(())
    }

    /// Get bytes already received for chain at index.
    #[inline]
    pub fn bytes_used(&self, index: usize) -> usize {
        self.pending_chains[index].bytes_used
    }

    /// Get maximum bytes the chain can hold.
    #[inline]
    pub fn max_bytes(&self, index: usize) -> usize {
        self.pending_chains[index].max_bytes
    }

    /// Advance bytes used for chain at index (partial receive).
    ///
    /// Also advances the iovecs in place, removing consumed buffers.
    /// Chain remains pending for next produce() call.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn advance(&mut self, index: usize, bytes: usize) {
        assert!(
            !self.pending_chains[index].finished,
            "advance: chain at index {} already finished",
            index
        );
        let chain = &mut self.pending_chains[index];
        chain.bytes_used += bytes;
        debug_assert!(
            chain.bytes_used <= chain.max_bytes,
            "advance: bytes_used {} exceeds max_bytes {}",
            chain.bytes_used,
            chain.max_bytes
        );
        advance_iovecs(&mut self.pending_iovecs[index], bytes);
    }

    /// Mark chain at index as finished.
    ///
    /// Calls add_used immediately. Chain will be removed after callback returns.
    /// Can be called out-of-order.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn finish(&mut self, index: usize) {
        let chain = &mut self.pending_chains[index];
        assert!(
            !chain.finished,
            "finish: chain at index {} already finished",
            index
        );
        chain.finished = true;
        log::trace!(
            "RxProducerBatch::finish: index={} head_index={} bytes_used={}",
            index,
            chain.head_index,
            chain.bytes_used
        );
        if let Err(e) = self.queue.add_used(self.mem, chain.head_index, chain.bytes_used as u32) {
            log::error!("RxProducerBatch: failed to add_used: {e}");
        }
    }

    /// Convenience: advance bytes and finish in one call.
    ///
    /// # Panics
    ///
    /// Panics if the chain at `index` has already been finished.
    pub fn complete(&mut self, index: usize, bytes: usize) {
        self.advance(index, bytes);
        self.finish(index);
    }
}


impl RxQueueProducer {
    /// Create a new RxQueueProvider with the given queue, memory, and interrupt.
    pub fn new(queue: Queue, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> Self {
        Self {
            queue,
            mem,
            interrupt,
            pending_chains: SmallVec::new(),
            pending_iovecs: SmallVec::new(),
        }
    }

    /// Number of chains currently pending (ready for receive).
    pub fn pending_count(&self) -> usize {
        self.pending_chains.len()
    }

    /// Feed descriptor chains from queue up to max_frames.
    ///
    /// Returns the number of new frames added.
    pub fn feed(&mut self, max_frames: usize) -> usize {
        self.feed_with_transform(max_frames, |_iovecs| {
            // No transformation
        })
    }

    /// Feed descriptor chains from queue, applying callback to each.
    ///
    /// The callback receives mutable iovecs from the descriptor chain and can:
    /// - Write header data (e.g., vnet header for RX)
    /// - Skip bytes by advancing iovecs in place
    ///
    /// This is useful for prepending headers that the guest expects but the
    /// network backend doesn't provide.
    ///
    /// Returns the number of frames added.
    pub fn feed_with_transform<F>(&mut self, max_frames: usize, mut transform: F) -> usize
    where
        F: for<'a> FnMut(&mut SmallVec<[IoSliceMut<'a>; 4]>),
    {
        let mut added = 0;

        while self.pending_count() < max_frames {
            let Some(head) = self.queue.pop(&self.mem) else {
                break;
            };

            let head_index = head.index;
            // Safety: The 'static lifetime here is a lie - the slices actually point into
            // `self.mem`. This is safe because:
            // 1. `self` owns `mem`, so the memory outlives these iovecs
            // 2. The iovecs are stored in `self.pending_iovecs` (requires 'static for storage)
            // 3. The HRTB `for<'a>` on callbacks erases the 'static before user code sees it
            // 4. All access goes through `produce()` which borrows `&mut self`, preventing
            //    use-after-free (can't drop self while iovecs are in use)
            let mut iovecs: SmallVec<[IoSliceMut<'static>; 4]> = SmallVec::new();
            let mut valid = true;

            for desc in head.into_iter() {
                // Only process writable descriptors (guest-writable = receive buffer)
                if desc.is_write_only() {
                    if let Some(iov) = self.desc_to_ioslice_mut(&desc) {
                        iovecs.push(iov);
                    } else {
                        log::error!(
                            "RxQueueProvider: failed to map descriptor addr={:x} len={}",
                            desc.addr.raw_value(),
                            desc.len
                        );
                        valid = false;
                        break;
                    }
                }
            }

            if !valid || iovecs.is_empty() {
                // Invalid or empty - mark as used with 0 bytes
                if let Err(e) = self.queue.add_used(&self.mem, head_index, 0) {
                    log::error!("RxQueueProvider: failed to add_used: {e}");
                }
                continue;
            }

            let max_bytes: usize = iovecs.iter().map(|iov| iov.len()).sum();

            // Apply transformation (e.g., write vnet header and advance iovecs)
            transform(&mut iovecs);

            // Track bytes consumed by transform (header written + advanced)
            let remaining_bytes: usize = iovecs.iter().map(|iov| iov.len()).sum();
            let transform_bytes = max_bytes - remaining_bytes;

            self.pending_chains.push(PendingChain {
                head_index,
                max_bytes,
                bytes_used: transform_bytes,
                finished: false,
            });
            self.pending_iovecs.push(iovecs);
            added += 1;
        }

        added
    }

    /// Convert a descriptor to a mutable IoSlice pointing into guest memory.
    fn desc_to_ioslice_mut(&self, desc: &DescriptorChain) -> Option<IoSliceMut<'static>> {
        let len = desc.len as usize;
        let slice = self.mem.get_slice(desc.addr, len).ok()?;
        let ptr = slice.ptr_guard_mut().as_ptr();

        // Safety: We own the GuestMemoryMmap, so the memory is valid for our lifetime.
        let byte_slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
        let static_slice: &'static mut [u8] = unsafe { std::mem::transmute(byte_slice) };
        
        Some(IoSliceMut::new(static_slice))
    }

    /// Produce frames by calling the callback with a batch.
    ///
    /// The callback receives an `RxProducerBatch` which provides access to chains
    /// and methods to mark them as complete. Returns the number of chains finished.
    pub fn produce<F>(&mut self, f: F) -> usize
    where
        F: for<'a> FnOnce(&mut RxProducerBatch<'a>),
    {
        if self.pending_chains.is_empty() {
            return 0;
        }

        {
            let mut batch = RxProducerBatch {
                pending_chains: &mut self.pending_chains,
                pending_iovecs: &mut self.pending_iovecs,
                queue: &mut self.queue,
                mem: &self.mem,
            };
            f(&mut batch);
        }

        // Remove finished chains (can be out-of-order, so remove all marked finished)
        let mut finished_count = 0;
        let mut i = 0;
        while i < self.pending_chains.len() {
            if self.pending_chains[i].finished {
                self.pending_chains.remove(i);
                self.pending_iovecs.remove(i);
                finished_count += 1;
            } else {
                i += 1;
            }
        }

        if finished_count > 0 {
            self.signal_used_if_needed();
        }

        finished_count
    }

    /// Signal used queue interrupt if needed.
    fn signal_used_if_needed(&mut self) {
        match self.queue.needs_notification(&self.mem) {
            Ok(true) => {
                log::trace!("RxQueueProducer: signaling used queue interrupt");
                self.interrupt.signal_used_queue();
            }
            Ok(false) => {
                log::trace!("RxQueueProducer: needs_notification returned false, not signaling");
            }
            Err(e) => {
                log::error!("RxQueueProvider: needs_notification error: {e}");
            }
        }
    }

    /// Get the raw queue for direct access.
    pub fn queue(&self) -> &Queue {
        &self.queue
    }

    /// Get mutable queue reference for notification control.
    pub fn queue_mut(&mut self) -> &mut Queue {
        &mut self.queue
    }

    /// Get memory reference.
    pub fn mem(&self) -> &GuestMemoryMmap {
        &self.mem
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::iovec_utils::write_to_iovecs;
    use crate::virtio::test_utils::{
        create_interrupt, create_memory, create_test_queue, ExpectedUsed, VirtQueueDriver,
    };

    use super::RxQueueProducer;

    #[test]
    fn test_new_producer_is_empty() {
        let mem = create_memory();
        let queue = create_test_queue();
        let _driver = VirtQueueDriver::new(&queue, &mem);
        let producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        assert_eq!(producer.pending_count(), 0);
    }

    #[test]
    fn test_feed_single_writable_descriptor() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.writable(&[1500]);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = producer.feed(10);

        assert_eq!(added, 1);
        assert_eq!(producer.pending_count(), 1);
    }

    #[test]
    fn test_feed_chained_writable_descriptors() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        // Chain of 2 writable descriptors
        driver.writable(&[512, 1024]);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = producer.feed(10);

        assert_eq!(added, 1);
        assert_eq!(producer.pending_count(), 1);

        // Verify buffer structure via produce
        producer.produce(|batch| {
            assert_eq!(batch.len(), 1);
            let chain = batch.chain_mut(0);
            assert_eq!(chain.len(), 2);
            assert_eq!(chain[0].len(), 512);
            assert_eq!(chain[1].len(), 1024);
            // Don't mark anything as finished
        });
    }

    #[test]
    fn test_feed_multiple_buffers() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        // 3 separate single-descriptor chains
        driver
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500]);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = producer.feed(10);

        assert_eq!(added, 3);
        assert_eq!(producer.pending_count(), 3);
    }

    #[test]
    fn test_feed_respects_max_frames() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500]);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = producer.feed(2);

        assert_eq!(added, 2);
        assert_eq!(producer.pending_count(), 2);
    }

    #[test]
    fn test_produce_fills_buffers() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.writable(&[1500]).writable(&[1500]);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);
        assert_eq!(producer.pending_count(), 2);

        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"Received packet 1").unwrap();
            batch.write_complete(1, b"Received packet 2").unwrap();
        });

        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 0);

        // Verify add_used was called with actual bytes written (17), not buffer capacity (1500)
        // Also verifies the content written to guest memory
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"Received packet 1")),
            (1, ExpectedUsed::Writable(b"Received packet 2")),
        ]);
    }

    #[test]
    fn test_produce_partial_fill() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500]);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);

        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"0123456789").unwrap();
            batch.write_complete(1, b"ABCDEFGHIJ").unwrap();
            // Third not filled - don't call complete
        });

        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 1);

        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"0123456789")),
            (1, ExpectedUsed::Writable(b"ABCDEFGHIJ")),
        ]);
    }

    #[test]
    fn test_produce_keeps_unused_buffers() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.writable(&[1500]).writable(&[1500]);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);

        // First produce: no data received (EAGAIN-like)
        let completed = producer.produce(|_batch| {
            // Don't complete anything
        });
        assert_eq!(completed, 0);
        assert_eq!(producer.pending_count(), 2);

        // Second produce: fill one buffer
        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"Hello").unwrap();
            // Don't complete second buffer
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 1);

        driver.assert_used(&[(0, ExpectedUsed::Writable(b"Hello"))]);
    }

    #[test]
    fn test_empty_queue_returns_zero() {
        let mem = create_memory();
        let queue = create_test_queue();
        let _driver = VirtQueueDriver::new(&queue, &mem);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        assert_eq!(producer.feed(10), 0);
        assert_eq!(producer.pending_count(), 0);
        assert_eq!(producer.produce(|_batch| {}), 0);
    }

    #[test]
    fn test_skips_read_only_descriptors() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        // Chain with readable then writable (readable should be skipped for RX)
        driver.readable_then_writable(&[b"ignored"], &[1400]);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);

        // Verify buffer structure via produce
        producer.produce(|batch| {
            assert_eq!(batch.len(), 1);
            let chain = batch.chain_mut(0);
            assert_eq!(chain.len(), 1);
            assert_eq!(chain[0].len(), 1400);
        });
    }

    #[test]
    fn test_chained_buffer_receive() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        // Chain of 3 writable descriptors forming one buffer
        driver.writable(&[100, 200, 300]);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);
        assert_eq!(producer.pending_count(), 1);

        let completed = producer.produce(|batch| {
            let mut data = vec![0xAA; 100];
            data.extend(vec![0xBB; 200]);
            data.extend(vec![0xCC; 300]);
            batch.write_complete(0, &data).unwrap();
        });

        assert_eq!(completed, 1);

        // Verify add_used reports 600 bytes and content matches
        // Chain has 3 segments: 100 bytes of 0xAA, 200 bytes of 0xBB, 300 bytes of 0xCC
        let mut expected_data = vec![0xAA; 100];
        expected_data.extend(vec![0xBB; 200]);
        expected_data.extend(vec![0xCC; 300]);
        driver.assert_used(&[(0, ExpectedUsed::Writable(&expected_data))]);
    }

    #[test]
    fn test_multiple_produce_cycles() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        // Create 4 chains, each with 3 descriptors: [6, 12, 6] = 24 bytes total
        // After 2-byte header skip: [4, 12, 6] = 22 bytes usable
        driver
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6]);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        // First feed: get 2 buffers, skip 2-byte header from each
        let added = producer.feed_with_transform(2, |iovecs| {
            // Write 2-byte header, then advance past it
            write_to_iovecs(iovecs, b"HD");
            super::advance_iovecs(iovecs, 2);
        });
        assert_eq!(added, 2);
        assert_eq!(producer.pending_count(), 2);

        // First produce:
        // - Chain 0: write "AAAABBBBBBBBBBBBCC" (18 bytes) spanning all 3 iovecs, complete
        // - Chain 1: write "XXXX" (4 bytes), partial advance, don't complete
        // Note: header bytes are automatically tracked by feed_with_transform
        let completed = producer.produce(|batch| {
            // Chain 0: spans [4, 12, 2] of the available [4, 12, 6]
            batch.write_complete(0, b"AAAABBBBBBBBBBBBCC").unwrap();

            // Chain 1: partial write, just 4 bytes into first iovec
            let written = write_to_iovecs(batch.chain_mut(1), b"XXXX");
            assert_eq!(written, 4);
            batch.advance(1, 4);
            // Don't complete - leave pending
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 1);

        // Second feed: get 1 more (1 pending + 1 new = 2)
        let added = producer.feed_with_transform(2, |iovecs| {
            write_to_iovecs(iovecs, b"HD");
            super::advance_iovecs(iovecs, 2);
        });
        assert_eq!(added, 1);
        assert_eq!(producer.pending_count(), 2);

        // Second produce:
        // - Chain 0 (was chain 1): iovecs already advanced, write "YYYYYYYY" (8 more), complete
        // - Chain 1 (chain 2): fresh chain, write spanning iovecs, complete
        let completed = producer.produce(|batch| {
            // Chain 0: continue after previous 4 bytes, write 8 more
            // Use write_to_iovecs + complete since we already have partial bytes_used
            let written = write_to_iovecs(batch.chain_mut(0), b"YYYYYYYY");
            assert_eq!(written, 8);
            batch.complete(0, 8); // adds to existing bytes_used

            // Chain 1: fresh chain, write spanning first 2 iovecs
            batch.write_complete(1, b"ZZZZZZZZZZZZ").unwrap(); // 12 bytes: fills [4] + 8 of [12]
        });
        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 0);

        // Verify used ring:
        // Chain 0: "HD" (header) + "AAAABBBBBBBBBBBBCC" (18 bytes) = 20 bytes total
        // Chain 1: "HD" (header) + "XXXXYYYYYYYY" (12 bytes) = 14 bytes total
        // Chain 2: "HD" (header) + "ZZZZZZZZZZZZ" (12 bytes) = 14 bytes total
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"HDAAAABBBBBBBBBBBBCC")),
            (1, ExpectedUsed::Writable(b"HDXXXXYYYYYYYY")),
            (2, ExpectedUsed::Writable(b"HDZZZZZZZZZZZZ")),
        ]);
    }

    #[test]
    fn test_selective_completion() {
        // Verify that only explicitly completed chains are removed.
        // With the new API, completion is explicit via batch.finish().
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500]);

        let mut producer = RxQueueProducer::new(queue.clone(), mem.clone(), create_interrupt());

        producer.feed(10);
        assert_eq!(producer.pending_count(), 3);

        // Complete only buffer 0, leave 1 and 2 pending
        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"pkt0").unwrap();
            // Don't complete buffers 1 and 2
        });

        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 2); // buffers 1 and 2 kept

        driver.assert_used(&[(0, ExpectedUsed::Writable(b"pkt0"))]);
    }
}
