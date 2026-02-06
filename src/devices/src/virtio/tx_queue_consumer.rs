// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! TX queue consumer for batched virtio transmit operations.

use std::io::IoSlice;

use smallvec::SmallVec;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap};

use super::iovec_utils::iovecs_len;
use super::queue::{DescriptorChain, Queue};
use super::InterruptTransport;

/// Metadata for a chain in the batch - tracks origin for add_used()
#[derive(Debug, Clone, Copy)]
struct ChainMeta {
    /// Descriptor chain head index for queue.add_used()
    head_index: u16,
    /// Total bytes in iovecs (for I/O completion tracking)
    total_len: usize,
    /// Bytes from guest descriptors (for add_used reporting)
    guest_len: usize,
    /// Whether this chain has been marked as completed
    completed: bool,
}

/// Batch for consuming TX chains.
///
/// Provides access to pending chains and methods to mark them as complete.
/// Supports both chain-based completion (whole messages) and byte-based
/// completion (for backends that track partial progress).
///
/// Panics if you access or complete an already-completed chain.
pub struct TxConsumerBatch<'a> {
    chain_iovecs: &'a [SmallVec<[IoSlice<'static>; 4]>],
    chain_meta: &'a mut [ChainMeta],
    queue: &'a mut Queue,
    mem: &'a GuestMemoryMmap,
    /// Tracks bytes for partial chain completion
    partial_bytes: &'a mut usize,
    /// Number of chains completed in this batch
    completed_count: usize,
}

impl TxConsumerBatch<'_> {
    /// Number of pending chains in this batch.
    #[inline]
    pub fn len(&self) -> usize {
        self.chain_iovecs.len()
    }

    /// Returns true if there are no pending chains.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.chain_iovecs.is_empty()
    }

    /// Get a single chain by index.
    ///
    /// # Lifetime guarantee
    ///
    /// The returned chain is guaranteed to remain valid and at a stable memory
    /// location until `complete_chains()` or `complete_bytes()` marks it complete.
    /// This is important for unsafe code that takes raw pointers to the iovecs.
    ///
    /// # Panics
    ///
    /// Panics if index is out of bounds or if the chain has already been completed.
    pub fn chain(&self, index: usize) -> &SmallVec<[IoSlice<'_>; 4]> {
        assert!(
            !self.chain_meta[index].completed,
            "chain: chain at index {} already completed",
            index
        );
        // Safety: We're returning with a shorter lifetime than 'static
        unsafe {
            &*(&self.chain_iovecs[index] as *const SmallVec<[IoSlice<'static>; 4]>
                as *const SmallVec<[IoSlice<'_>; 4]>)
        }
    }

    /// Mark the first N chains as complete.
    ///
    /// Use this when your I/O operation returns the number of complete
    /// messages sent. Calls add_used() for each completed chain.
    ///
    /// # Panics
    ///
    /// Panics if any of the first N chains have already been completed.
    pub fn complete_chains(&mut self, count: usize) {
        for i in 0..count {
            if i >= self.chain_meta.len() {
                break;
            }
            let meta = &mut self.chain_meta[i];
            assert!(
                !meta.completed,
                "complete_chains: chain at index {} already completed",
                i
            );
            meta.completed = true;
            log::trace!(
                "TxConsumerBatch::complete_chains: index={} head_index={} guest_len={}",
                i,
                meta.head_index,
                meta.guest_len
            );
            if let Err(e) = self.queue.add_used(self.mem, meta.head_index, meta.guest_len as u32) {
                log::error!("TxConsumerBatch: failed to add_used: {e}");
            }
            self.completed_count += 1;
        }
    }

    /// Complete chains by byte count.
    ///
    /// Use this when your I/O operation returns a byte count. Chains are
    /// marked complete (add_used called) when enough bytes have been consumed.
    /// Handles partial chain progress across multiple calls.
    pub fn complete_bytes(&mut self, bytes: usize) {
        *self.partial_bytes += bytes;

        // Complete chains while we have enough bytes
        for meta in self.chain_meta.iter_mut() {
            if meta.completed {
                continue; // Skip already completed chains
            }
            if *self.partial_bytes >= meta.total_len {
                meta.completed = true;
                log::trace!(
                    "TxConsumerBatch::complete_bytes: head_index={} guest_len={}",
                    meta.head_index,
                    meta.guest_len
                );
                if let Err(e) = self.queue.add_used(self.mem, meta.head_index, meta.guest_len as u32) {
                    log::error!("TxConsumerBatch: failed to add_used: {e}");
                }
                *self.partial_bytes -= meta.total_len;
                self.completed_count += 1;
            } else {
                break; // Not enough bytes for next chain
            }
        }
    }

    /// Get the number of chains completed so far in this batch.
    #[inline]
    pub fn completed_count(&self) -> usize {
        self.completed_count
    }

    /// Get total bytes across all pending (non-completed) chains.
    pub fn total_bytes(&self) -> usize {
        self.chain_meta
            .iter()
            .filter(|m| !m.completed)
            .map(|m| m.total_len)
            .sum()
    }
}

/// TxQueueConsumer - owns the TX queue and manages chain batching.
///
/// Generic abstraction: pulls descriptor chains from virtio queue,
/// applies a user-provided callback to transform each chain into iovecs,
/// batches results, handles add_used() after send.
///
/// # Safety
///
/// The iovecs stored in `chain_iovecs` point into guest memory owned by `mem`.
/// The lifetime is erased to 'static because the struct owns the memory reference.
/// This is safe as long as:
/// 1. The struct outlives any use of the iovecs
/// 2. The guest memory is not unmapped while iovecs are in use
pub struct TxQueueConsumer {
    /// The virtio TX queue (owned)
    queue: Queue,
    /// Guest memory reference
    mem: GuestMemoryMmap,
    /// Interrupt for signaling guest
    interrupt: InterruptTransport,

    /// Per-chain iovecs (outer vec = chains, inner = iovecs per chain)
    /// Safety: these point into `mem` which is owned by this struct
    /// the 'static is a lie! - see feed_with_transform
    chain_iovecs: SmallVec<[SmallVec<[IoSlice<'static>; 4]>; 32]>,
    /// Metadata for each chain (parallel to chain_iovecs)
    chain_meta: SmallVec<[ChainMeta; 32]>,
    // TODO: Implement a proper HeaderAllocator that the feed() callback can use to safely
    // allocate header bytes and get IoSlice<'static> references. The allocator would:
    // 1. Use a pre-reserved Vec<u8> buffer to prevent reallocation
    // 2. Provide an alloc(&[u8]) -> IoSlice<'static> method
    // 3. Handle the unsafe lifetime extension internally
    // For now, we use Box::leak in the callback code as a temporary workaround.

    /// Number of chains fully sent
    sent_chains: usize,
    /// Bytes consumed from the first pending chain (for partial write tracking)
    partial_bytes: usize,
}

impl TxQueueConsumer {
    /// Create a new TxQueueConsumer with the given queue, memory, and interrupt.
    pub fn new(queue: Queue, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> Self {
        Self {
            queue,
            mem,
            interrupt,
            chain_iovecs: SmallVec::new(),
            chain_meta: SmallVec::new(),
            sent_chains: 0,
            partial_bytes: 0,
        }
    }

    /// Feed descriptor chains from queue (simple version).
    ///
    /// This is the common case - just sums the byte count of each chain.
    /// For advanced use cases (e.g., inserting headers), use `feed_with_transform`.
    pub fn feed(&mut self, max_chains: usize) -> usize {
        self.feed_with_transform(max_chains, |_iovecs| {
            // No transformation - lengths computed automatically
        })
    }

    /// Feed descriptor chains from queue, applying callback to each.
    ///
    /// The callback receives mutable iovecs from the descriptor chain and can:
    /// - Skip bytes (e.g., vnet header) by using `IoSlice::advance_slices`
    /// - Insert header iovecs (e.g., length prefix for stream sockets)
    /// - Modify data in place
    ///
    /// Returns the number of chains added to the batch.
    ///
    /// # Arguments
    /// * `max_chains` - Maximum chains to feed (including already pending)
    /// * `transform` - Callback to transform each descriptor chain's iovecs
    ///
    /// The callback can transform the iovecs (skip bytes, add headers, etc).
    /// Both the original chain length (for add_used) and the final length
    /// (for completion tracking) are computed automatically.
    ///
    pub fn feed_with_transform<F>(&mut self, max_chains: usize, mut transform_chain: F) -> usize
    where
        F: for<'a> FnMut(&mut SmallVec<[IoSlice<'a>; 4]>),
    {
        let mut added = 0;

        while self.pending_count() < max_chains {
            let Some(head) = self.queue.pop(&self.mem) else {
                break;
            };
            let head_index = head.index;

            // Build iovecs from descriptor chain.
            //
            // Safety: The 'static lifetime here is a lie - the slices actually point into
            // `self.mem`. This is safe because:
            // 1. `self` owns `mem`, so the memory outlives these iovecs
            // 2. The iovecs are stored in `self.chain_iovecs` (requires 'static for storage)
            // 3. The HRTB `for<'a>` on callbacks erases the 'static before user code sees it
            // 4. All access goes through `consume()` which borrows `&mut self`, preventing
            //    use-after-free (can't drop self while iovecs are in use)
            let mut iovecs: SmallVec<[IoSlice<'static>; 4]> = SmallVec::new();
            let mut valid = true;

            for desc in head.into_iter() {
                // Only process readable descriptors (guest-readable = data to send)
                if desc.is_read_only() {
                    if let Some(iov) = self.desc_to_ioslice(&desc) {
                        iovecs.push(iov);
                    } else {
                        log::error!(
                            "TxQueueConsumer: failed to map descriptor addr={:x} len={}",
                            desc.addr.raw_value(),
                            desc.len
                        );
                        valid = false;
                        break;
                    }
                }
            }

            if !valid || iovecs.is_empty() {
                // Invalid or empty descriptor chain - mark as used with 0 bytes
                if let Err(e) = self.queue.add_used(&self.mem, head_index, 0) {
                    log::error!("TxQueueConsumer: failed to add_used: {e}");
                }
                continue;
            }

            // Compute original chain length before transformation
            let guest_len = iovecs_len(&iovecs);

            // Apply user callback to transform iovecs
            transform_chain(&mut iovecs);

            // Compute final length after transformation
            let total_len = iovecs_len(&iovecs);

            self.chain_iovecs.push(iovecs);
            self.chain_meta.push(ChainMeta {
                head_index,
                total_len,
                guest_len,
                completed: false,
            });
            added += 1;
        }

        added
    }

    /// Convert a descriptor to an IoSlice pointing into guest memory.
    ///
    /// Returns None if the descriptor's memory region cannot be found or mapped.
    ///
    /// # Safety
    /// The returned IoSlice has 'static lifetime but actually points into `self.mem`.
    /// This is safe because `self` owns `mem` and the IoSlice won't outlive `self`.
    fn desc_to_ioslice(&self, desc: &DescriptorChain) -> Option<IoSlice<'static>> {
        let len = desc.len as usize;
        let slice = self.mem.get_slice(desc.addr, len).ok()?;
        let ptr = slice.ptr_guard_mut().as_ptr();

        // Safety: We own the GuestMemoryMmap, so the memory is valid for our lifetime.
        // The slice points into pinned guest memory that won't move.
        let byte_slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        // Transmute to 'static - safe because we own the memory reference
        let static_slice: &'static [u8] = unsafe { std::mem::transmute(byte_slice) };

        Some(IoSlice::new(static_slice))
    }

    /// Number of chains pending (not yet sent)
    pub fn pending_count(&self) -> usize {
        self.chain_meta.len() - self.sent_chains
    }

    /// Check if there are any pending chains
    pub fn has_pending(&self) -> bool {
        self.pending_count() > 0
    }

    /// Consume pending chains using a callback that performs the actual I/O.
    ///
    /// The callback receives a `TxConsumerBatch` which provides:
    /// - `chain(i)` - access to chain iovecs by index (panics if already completed)
    /// - `complete_chains(n)` - mark first N chains as complete
    /// - `complete_bytes(n)` - mark chains complete based on byte count
    ///
    /// Returns the number of chains completed. Completed chains are removed
    /// from the pending list and interrupt is signaled if needed.
    pub fn consume<F>(&mut self, f: F) -> usize
    where
        F: for<'a> FnOnce(&mut TxConsumerBatch<'a>),
    {
        if !self.has_pending() {
            return 0;
        }

        let completed_count;
        {
            let pending_iovecs = &self.chain_iovecs[self.sent_chains..];
            let pending_meta = &mut self.chain_meta[self.sent_chains..];

            let mut batch = TxConsumerBatch {
                chain_iovecs: pending_iovecs,
                chain_meta: pending_meta,
                queue: &mut self.queue,
                mem: &self.mem,
                partial_bytes: &mut self.partial_bytes,
                completed_count: 0,
            };

            f(&mut batch);
            completed_count = batch.completed_count;
        }

        // Update sent_chains based on what was completed
        self.sent_chains += completed_count;

        if completed_count > 0 {
            self.signal_used_if_needed();
        }

        self.compact();
        completed_count
    }

    /// Clear completed chains from buffers.
    ///
    /// Call this after processing to free memory from completed chains.
    /// Note: `partial_bytes` is preserved - it tracks bytes consumed from the
    /// first pending chain (now at index 0 after compact).
    pub fn compact(&mut self) {
        if self.sent_chains > 0 {
            self.chain_iovecs.drain(..self.sent_chains);
            self.chain_meta.drain(..self.sent_chains);
            self.sent_chains = 0;
        }
    }

    /// Signal used queue interrupt if needed.
    fn signal_used_if_needed(&mut self) {
        match self.queue.needs_notification(&self.mem) {
            Ok(true) => self.interrupt.signal_used_queue(),
            Ok(false) => {} // No notification needed
            Err(e) => {
                log::error!("TxQueueConsumer: needs_notification error: {e}");
            }
        }
    }

    /// Get the raw queue for direct access (e.g., for enable/disable_notification).
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
    use std::io::IoSlice;

    use crate::virtio::test_utils::{
        create_interrupt, create_memory, create_test_queue, ExpectedUsed, VirtQueueDriver,
    };

    use super::TxQueueConsumer;

    #[test]
    fn test_new_consumer_is_empty() {
        let mem = create_memory();
        let queue = create_test_queue();
        let consumer = TxQueueConsumer::new(queue, mem.clone(), create_interrupt());

        assert_eq!(consumer.pending_count(), 0);
        assert!(!consumer.has_pending());
    }

    #[test]
    fn test_feed_single_descriptor() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.readable(&[b"Hello, World!"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |_iovecs| {});

        assert_eq!(added, 1);
        assert_eq!(consumer.pending_count(), 1);
        assert!(consumer.has_pending());

        // Verify chain content via consume callback
        let completed = consumer.consume(|batch| {
            assert_eq!(batch.len(), 1);
            assert_eq!(batch.chain(0).len(), 1);
            assert_eq!(&*batch.chain(0)[0], b"Hello, World!");
            batch.complete_bytes(13);
        });

        assert_eq!(completed, 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable(13))]);
    }

    #[test]
    fn test_feed_chained_descriptors() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        // Chain of two descriptors
        driver.readable(&[b"First", b"Second"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |_iovecs| {});

        assert_eq!(added, 1);
        assert_eq!(consumer.pending_count(), 1);

        let completed = consumer.consume(|batch| {
            assert_eq!(batch.chain(0).len(), 2);
            assert_eq!(&*batch.chain(0)[0], b"First");
            assert_eq!(&*batch.chain(0)[1], b"Second");
            batch.complete_bytes(11);
        });

        assert_eq!(completed, 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable(11))]);
    }

    #[test]
    fn test_feed_multiple_frames() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .readable(&[b"Frame1"])
            .readable(&[b"Frame2"])
            .readable(&[b"Frame3"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |_iovecs| {});

        assert_eq!(added, 3);
        assert_eq!(consumer.pending_count(), 3);

        let completed = consumer.consume(|batch| {
            assert_eq!(batch.len(), 3);
            batch.complete_bytes(18); // 6 + 6 + 6
        });

        assert_eq!(completed, 3);
        driver.assert_used(&[
            (0, ExpectedUsed::Readable(6)),
            (1, ExpectedUsed::Readable(6)),
            (2, ExpectedUsed::Readable(6)),
        ]);
    }

    #[test]
    fn test_feed_respects_max_frames() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .readable(&[b"F0"])
            .readable(&[b"F1"])
            .readable(&[b"F2"])
            .readable(&[b"F3"])
            .readable(&[b"F4"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(2, |_iovecs| {});
        assert_eq!(added, 2);
        assert_eq!(consumer.pending_count(), 2);

        // Already at limit
        let added2 = consumer.feed_with_transform(2, |_iovecs| {});
        assert_eq!(added2, 0);
        assert_eq!(consumer.pending_count(), 2);
    }

    #[test]
    fn test_feed_transform_callback() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.readable(&[b"TestData12345"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |iovecs| {
            // Skip 4 bytes (like skipping vnet header)
            let mut slices: &mut [IoSlice] = iovecs;
            IoSlice::advance_slices(&mut slices, 4);
        });

        assert_eq!(added, 1);

        consumer.consume(|batch| {
            batch.complete_bytes(9); // payload only
        });

        // Original guest length is 13, not 9
        driver.assert_used(&[(0, ExpectedUsed::Readable(13))]);
    }

    #[test]
    fn test_consume_and_complete_bytes() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.readable(&[b"FirstChain"]).readable(&[b"SecondChain"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed_with_transform(10, |_iovecs| {});
        assert_eq!(consumer.pending_count(), 2);

        let completed = consumer.consume(|batch| {
            assert_eq!(batch.total_bytes(), 21);
            batch.complete_bytes(batch.total_bytes());
        });

        assert_eq!(completed, 2);
        assert_eq!(consumer.pending_count(), 0);

        driver.assert_used(&[
            (0, ExpectedUsed::Readable(10)),
            (1, ExpectedUsed::Readable(11)),
        ]);
    }

    #[test]
    fn test_consume_partial_bytes() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .readable(&[b"Chain00000"])
            .readable(&[b"Chain11111"])
            .readable(&[b"Chain22222"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed_with_transform(10, |_iovecs| {});

        let completed = consumer.consume(|batch| {
            batch.complete_bytes(15);
        });

        // Only first chain complete (10 bytes), 5 bytes into second
        assert_eq!(completed, 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable(10))]);
    }

    #[test]
    fn test_compact() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed_with_transform(10, |_iovecs| {});
        assert_eq!(consumer.pending_count(), 5);

        // Advance 12 bytes = 3 complete chains (compact is called internally)
        let completed = consumer.consume(|batch| {
            batch.complete_bytes(12);
        });
        assert_eq!(completed, 3);
        assert_eq!(consumer.pending_count(), 2);

        driver.assert_used(&[
            (0, ExpectedUsed::Readable(4)),
            (1, ExpectedUsed::Readable(4)),
            (2, ExpectedUsed::Readable(4)),
        ]);
    }

    #[test]
    fn test_empty_queue_returns_zero() {
        let mem = create_memory();
        let queue = create_test_queue();
        let _driver = VirtQueueDriver::new(&queue, &mem);
        // Don't add any descriptors

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |_iovecs| {});

        assert_eq!(added, 0);
        assert_eq!(consumer.pending_count(), 0);
        // consume returns 0 when no pending chains
        let completed = consumer.consume(|_batch| {});
        assert_eq!(completed, 0);
    }

    #[test]
    fn test_no_completion_preserves_pending() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.readable(&[b"TestData"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed_with_transform(10, |_iovecs| {});

        // Callback doesn't complete anything (simulating EAGAIN/WouldBlock)
        let completed = consumer.consume(|_batch| {
            // Don't call complete_bytes or complete_chains
        });
        assert_eq!(completed, 0);
        assert_eq!(consumer.pending_count(), 1);

        // Nothing should be in used ring yet
        assert_eq!(driver.used_count(), 0);
    }

    // ========================================================================
    // Header manipulation tests
    // ========================================================================

    #[test]
    fn test_remove_header_byte_tracking() {
        // Guest provides [header (12) | payload (100)].
        // Transform skips header. byte_count = 100 (payload only).
        // I/O returns 100 → chain complete.
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        let mut data = vec![0x48u8; 12]; // header
        data.extend(vec![0x50; 100]); // payload
        driver.readable(&[&data]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |iovecs| {
            let mut slices: &mut [IoSlice] = iovecs;
            IoSlice::advance_slices(&mut slices, 12);
        });
        assert_eq!(added, 1);

        let completed = consumer.consume(|batch| {
            // Sum bytes in chain 0 (should be 100, not 112)
            let total: usize = batch.chain(0).iter().map(|iov| iov.len()).sum();
            assert_eq!(total, 100); // payload only
            batch.complete_bytes(100);
        });

        assert_eq!(completed, 1);
        assert_eq!(consumer.pending_count(), 0);

        // add_used reports ORIGINAL guest length (112), not transformed (100)
        driver.assert_used(&[(0, ExpectedUsed::Readable(112))]);
    }

    #[test]
    fn test_skip_header_byte_tracking() {
        // Guest provides [virtio_header (12) | payload (100)].
        // Transform skips virtio header.
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        let mut data = vec![0x48u8; 12];
        data.extend(vec![0x50; 100]);
        driver.readable(&[&data]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |iovecs| {
            let mut slices: &mut [IoSlice] = iovecs;
            IoSlice::advance_slices(&mut slices, 12);
        });
        assert_eq!(added, 1);

        let completed = consumer.consume(|batch| {
            batch.complete_bytes(100);
        });
        assert_eq!(completed, 1);
        assert_eq!(consumer.pending_count(), 0);

        // add_used reports ORIGINAL guest length (112)
        driver.assert_used(&[(0, ExpectedUsed::Readable(112))]);
    }

    #[test]
    fn test_partial_send_with_header_removed() {
        // 2 chains: [header (10) | payload (50)] each.
        // After removing headers: 50 bytes per chain.
        // I/O returns 75: completes chain 1 (50), partial chain 2 (25).
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        let mut data1 = vec![0x48u8; 10];
        data1.extend(vec![0x50; 50]);
        let mut data2 = vec![0x48u8; 10];
        data2.extend(vec![0x51; 50]);
        driver.readable(&[&data1]).readable(&[&data2]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |iovecs| {
            let mut slices: &mut [IoSlice] = iovecs;
            IoSlice::advance_slices(&mut slices, 10);
        });
        assert_eq!(added, 2);

        let completed = consumer.consume(|batch| {
            batch.complete_bytes(75);
        });
        assert_eq!(completed, 1);
        assert_eq!(consumer.pending_count(), 1); // chain 2 partial

        // Only chain 1 complete (original 60 bytes)
        driver.assert_used(&[(0, ExpectedUsed::Readable(60))]);
    }

    #[test]
    fn test_multi_cycle_partial_writes() {
        // Tricky scenario: partial writes across multiple cycles.
        // Chain layout after transform: payload only (100 bytes after skipping 12-byte header)
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        let mut data = vec![0x48u8; 12]; // virtio header (skipped)
        data.extend(vec![0x50; 100]); // payload
        driver.readable(&[&data]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |iovecs| {
            let mut slices: &mut [IoSlice] = iovecs;
            IoSlice::advance_slices(&mut slices, 12);
        });
        assert_eq!(added, 1);

        // Cycle 1: 2 bytes sent (partial)
        consumer.consume(|batch| batch.complete_bytes(2));
        assert_eq!(consumer.pending_count(), 1);

        // Cycle 2: 50 more bytes (total 52)
        consumer.consume(|batch| batch.complete_bytes(50));
        assert_eq!(consumer.pending_count(), 1);

        // Cycle 3: remaining 48 bytes
        consumer.consume(|batch| batch.complete_bytes(48));
        assert_eq!(consumer.pending_count(), 0);

        // add_used reports ORIGINAL guest length (112)
        driver.assert_used(&[(0, ExpectedUsed::Readable(112))]);
    }

    #[test]
    fn test_multi_cycle_multiple_chains() {
        // 3 chains of 40 bytes each (after header removal) = 120 bytes total.
        // Cycle 1: 25 bytes (partial chain 1)
        // Cycle 2: 60 bytes (completes chain 1, completes chain 2, partial chain 3)
        // Cycle 3: no progress (simulating WouldBlock)
        // Cycle 4: 35 bytes (completes chain 3)
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        let mut data = vec![0x48u8; 10]; // 10-byte header
        data.extend(vec![0x50; 40]); // 40-byte payload
        driver.readable(&[&data]).readable(&[&data]).readable(&[&data]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        let added = consumer.feed_with_transform(10, |iovecs| {
            let mut slices: &mut [IoSlice] = iovecs;
            IoSlice::advance_slices(&mut slices, 10); // skip 10-byte header
        });
        assert_eq!(added, 3);
        assert_eq!(consumer.pending_count(), 3);

        // Cycle 1: 25 bytes (partial chain 1)
        consumer.consume(|batch| batch.complete_bytes(25));
        assert_eq!(consumer.pending_count(), 3); // no chain complete yet

        // Cycle 2: 60 bytes → total 85 bytes
        // Chain 1: 40 bytes (complete at 40)
        // Chain 2: 40 bytes (complete at 80)
        // Chain 3: 5 bytes into it (at 85)
        consumer.consume(|batch| batch.complete_bytes(60));
        assert_eq!(consumer.pending_count(), 1); // chains 1,2 complete

        // Cycle 3: no progress (simulating WouldBlock)
        consumer.consume(|_batch| {
            // Don't advance anything
        });
        assert_eq!(consumer.pending_count(), 1); // still pending

        // Cycle 4: 35 bytes (completes chain 3)
        consumer.consume(|batch| batch.complete_bytes(35));
        assert_eq!(consumer.pending_count(), 0); // all done

        // Verify add_used was called for all 3 chains with ORIGINAL guest lengths (50 each)
        driver.assert_used(&[
            (0, ExpectedUsed::Readable(50)),
            (1, ExpectedUsed::Readable(50)),
            (2, ExpectedUsed::Readable(50)),
        ]);
    }

    #[test]
    fn test_stop_resume_across_compact() {
        // Feed 2 chains, partial send, compact, feed more, continue.
        // This tests that state is preserved when guest adds more descriptors mid-stream.
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        // First batch: 2 chains of 30 bytes each
        let data = vec![0x50u8; 30];
        driver.readable(&[&data]).readable(&[&data]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed_with_transform(10, |_iovecs| {});
        assert_eq!(consumer.pending_count(), 2);

        // Send 45 bytes (chain 1 complete, 15 into chain 2)
        consumer.consume(|batch| batch.complete_bytes(45));
        assert_eq!(consumer.pending_count(), 1);

        // Compact removes completed chain 1
        // (compact is called automatically in consume, but let's verify state)

        // Guest adds more descriptors (simulating queue refill)
        driver.readable(&[&data]); // chain 3

        consumer.feed_with_transform(10, |_iovecs| {});
        assert_eq!(consumer.pending_count(), 2); // chain 2 (partial) + chain 3

        // Send remaining 15 of chain 2 + all 30 of chain 3 = 45
        consumer.consume(|batch| batch.complete_bytes(45));
        assert_eq!(consumer.pending_count(), 0);
    }
}
