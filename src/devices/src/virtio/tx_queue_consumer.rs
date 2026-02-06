// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! TX queue consumer for batched virtio transmit operations.

use std::io::IoSlice;

use smallvec::SmallVec;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap};

use super::iovec_utils::iovecs_len;
use super::queue::{DescriptorChain, Queue};
use super::InterruptTransport;

/// Result of a consume callback - indicates how much was consumed.
#[derive(Debug, Clone, Copy)]
pub enum Consumed {
    /// Number of bytes consumed (e.g., from writev return value)
    Bytes(usize),
    /// Number of complete descriptor chains consumed (e.g., from sendmmsg return value)
    Chains(usize),
}

/// Metadata for a frame in the batch - tracks origin for add_used()
#[derive(Debug, Clone, Copy)]
struct FrameMeta {
    /// Descriptor chain head index for queue.add_used()
    head_index: u16,
    /// Total bytes in iovecs (for I/O completion tracking)
    total_len: usize,
    /// Bytes from guest descriptors (for add_used reporting)
    guest_len: usize,
}

/// TxQueueConsumer - owns the TX queue and manages frame batching.
///
/// Generic abstraction: pulls descriptor chains from virtio queue,
/// applies a user-provided callback to transform each chain into iovecs,
/// batches results, handles add_used() after send.
///
/// # Safety
///
/// The iovecs stored in `frame_iovecs` point into guest memory owned by `mem`.
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

    /// Per-frame iovecs (outer vec = frames, inner = iovecs per frame)
    /// Safety: these point into `mem` which is owned by this struct
    frame_iovecs: SmallVec<[SmallVec<[IoSlice<'static>; 4]>; 32]>,
    /// Metadata for each frame (parallel to frame_iovecs)
    frame_meta: SmallVec<[FrameMeta; 32]>,
    // TODO: Implement a proper HeaderAllocator that the feed() callback can use to safely
    // allocate header bytes and get IoSlice<'static> references. The allocator would:
    // 1. Use a pre-reserved Vec<u8> buffer to prevent reallocation
    // 2. Provide an alloc(&[u8]) -> IoSlice<'static> method
    // 3. Handle the unsafe lifetime extension internally
    // For now, we use Box::leak in the callback code as a temporary workaround.

    /// Number of frames fully sent
    sent_frames: usize,
    /// Bytes consumed from the first pending frame (for partial write tracking)
    partial_bytes: usize,
}

impl TxQueueConsumer {
    /// Create a new TxQueueConsumer with the given queue, memory, and interrupt.
    pub fn new(queue: Queue, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> Self {
        Self {
            queue,
            mem,
            interrupt,
            frame_iovecs: SmallVec::new(),
            frame_meta: SmallVec::new(),
            sent_frames: 0,
            partial_bytes: 0,
        }
    }

    /// Feed descriptor chains from queue (simple version).
    ///
    /// This is the common case - just sums the byte count of each chain.
    /// For advanced use cases (e.g., inserting headers), use `feed_with_transform`.
    pub fn feed(&mut self, max_frames: usize) -> usize {
        self.feed_with_transform(max_frames, |_iovecs| {
            // No transformation - lengths computed automatically
        })
    }

    /// Feed descriptor chains from queue, applying callback to each.
    ///
    /// The callback receives mutable iovecs from the descriptor chain and can:
    /// - Skip bytes (e.g., vnet header) by using `IoSlice::advance_slices`
    /// - Insert header iovecs (e.g., frame length for stream sockets)
    /// - Modify data in place
    ///
    /// Returns the number of frames added to the batch.
    ///
    /// # Arguments
    /// * `max_frames` - Maximum frames to feed (including already pending)
    /// * `transform` - Callback to transform each descriptor chain's iovecs
    ///
    /// The callback can transform the iovecs (skip bytes, add headers, etc).
    /// Both the original chain length (for add_used) and the final length
    /// (for completion tracking) are computed automatically.
    ///
    pub fn feed_with_transform<F>(&mut self, max_frames: usize, mut transform_chain: F) -> usize
    where
        F: for<'a> FnMut(&mut SmallVec<[IoSlice<'a>; 4]>),
    {
        let mut added = 0;

        while self.pending_count() < max_frames {
            let Some(head) = self.queue.pop(&self.mem) else {
                break;
            };
            let head_index = head.index;

            // Build iovecs from descriptor chain.
            //
            // Safety: The 'static lifetime here is a lie - the slices actually point into
            // `self.mem`. This is safe because:
            // 1. `self` owns `mem`, so the memory outlives these iovecs
            // 2. The iovecs are stored in `self.frame_iovecs` (requires 'static for storage)
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

            self.frame_iovecs.push(iovecs);
            self.frame_meta.push(FrameMeta {
                head_index,
                total_len,
                guest_len,
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

    /// Number of frames pending (not yet sent)
    pub fn pending_count(&self) -> usize {
        self.frame_meta.len() - self.sent_frames
    }

    /// Check if there are any pending frames
    pub fn has_pending(&self) -> bool {
        self.pending_count() > 0
    }

    /// Consume pending chains using a callback that performs the actual I/O.
    ///
    /// The callback receives the chain iovecs and returns `Ok(Consumed::Bytes(n))`
    /// or `Ok(Consumed::Chains(n))` to indicate how much was consumed.
    ///
    // TODO: Switch to a completer pattern like rx_queue_producer uses, where the
    // callback receives a completer object to mark chains as complete.
    ///
    /// The consumer then:
    /// - Advances by the returned amount (completing chains as appropriate)
    /// - Calls add_used() for completed chains
    /// - Signals interrupt if needed
    /// - Compacts internal buffers
    ///
    /// On error (e.g., EAGAIN), pending chains are kept for retry later.
    pub fn consume<F, E>(&mut self, f: F) -> Result<Consumed, E>
    where
        F: for<'a> FnOnce(&[SmallVec<[IoSlice<'a>; 4]>]) -> Result<Consumed, E>,
    {
        if !self.has_pending() {
            return Ok(Consumed::Chains(0));
        }

        match f(&self.frame_iovecs[self.sent_frames..]) {
            Ok(consumed) => {
                match consumed {
                    Consumed::Bytes(bytes) => self.advance_bytes(bytes),
                    Consumed::Chains(count) => self.advance_chains(count),
                }
                self.compact();
                Ok(consumed)
            }
            Err(e) => Err(e),
        }
    }

    /// Advance by N complete chains (e.g., from sendmmsg return value).
    ///
    /// Calls add_used() for each completed chain and signals interrupt.
    pub fn advance_chains(&mut self, count: usize) {
        for _ in 0..count {
            if self.sent_frames >= self.frame_meta.len() {
                break;
            }
            let meta = &self.frame_meta[self.sent_frames];
            if let Err(e) = self.queue.add_used(&self.mem, meta.head_index, meta.guest_len as u32) {
                log::error!("TxQueueConsumer: failed to add_used: {e}");
            }
            self.sent_frames += 1;
        }
        self.signal_used_if_needed();
    }

    /// Advance by N bytes, completing chains as bytes are consumed.
    ///
    /// Calls add_used() for completed chains and signals interrupt.
    pub fn advance_bytes(&mut self, bytes: usize) {
        self.partial_bytes += bytes;

        // Complete frames while we have enough bytes
        while self.sent_frames < self.frame_meta.len() {
            let meta = &self.frame_meta[self.sent_frames];
            if self.partial_bytes >= meta.total_len {
                if let Err(e) = self.queue.add_used(&self.mem, meta.head_index, meta.guest_len as u32) {
                    log::error!("TxQueueConsumer: failed to add_used: {e}");
                }
                self.partial_bytes -= meta.total_len;
                self.sent_frames += 1;
            } else {
                break;
            }
        }

        self.signal_used_if_needed();
    }

    /// Clear completed frames from buffers.
    ///
    /// Call this after processing to free memory from completed frames.
    /// Note: `partial_bytes` is preserved - it tracks bytes consumed from the
    /// first pending frame (now at index 0 after compact).
    pub fn compact(&mut self) {
        if self.sent_frames > 0 {
            self.frame_iovecs.drain(..self.sent_frames);
            self.frame_meta.drain(..self.sent_frames);
            self.sent_frames = 0;
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

    use super::{Consumed, TxQueueConsumer};

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

        // Verify frame content via consume callback
        consumer
            .consume(|frames| {
                assert_eq!(frames.len(), 1);
                assert_eq!(frames[0].len(), 1);
                assert_eq!(&*frames[0][0], b"Hello, World!");
                Ok::<_, ()>(Consumed::Bytes(13))
            })
            .unwrap();

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

        consumer
            .consume(|frames| {
                assert_eq!(frames[0].len(), 2);
                assert_eq!(&*frames[0][0], b"First");
                assert_eq!(&*frames[0][1], b"Second");
                Ok::<_, ()>(Consumed::Bytes(11))
            })
            .unwrap();

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

        consumer
            .consume(|frames| {
                assert_eq!(frames.len(), 3);
                Ok::<_, ()>(Consumed::Bytes(18))
            })
            .unwrap();

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

        consumer
            .consume(|_| Ok::<_, ()>(Consumed::Bytes(9)))
            .unwrap();

        // Original guest length is 13, not 9
        driver.assert_used(&[(0, ExpectedUsed::Readable(13))]);
    }

    #[test]
    fn test_consume_and_advance_bytes() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.readable(&[b"FirstFrame"]).readable(&[b"SecondFrame"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed_with_transform(10, |_iovecs| {});
        assert_eq!(consumer.pending_count(), 2);

        let result = consumer.consume(|frames| {
            let total: usize = frames
                .iter()
                .flat_map(|f| f.iter())
                .map(|iov| iov.len())
                .sum();
            Ok::<_, ()>(Consumed::Bytes(total))
        });

        assert!(matches!(result, Ok(Consumed::Bytes(21))));
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
            .readable(&[b"Frame00000"])
            .readable(&[b"Frame11111"])
            .readable(&[b"Frame22222"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed_with_transform(10, |_iovecs| {});

        let result = consumer.consume(|_frames| Ok::<_, ()>(Consumed::Bytes(15)));
        assert!(matches!(result, Ok(Consumed::Bytes(15))));

        // Only first frame complete (10 bytes), 5 bytes into second
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

        // Advance 12 bytes = 3 complete frames
        consumer.advance_bytes(12);
        assert_eq!(consumer.pending_count(), 2);

        consumer.compact();
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
        assert!(matches!(
            consumer.consume(|_| Ok::<_, ()>(Consumed::Bytes(0))),
            Ok(Consumed::Chains(0))
        ));
    }

    #[test]
    fn test_consume_error_preserves_pending() {
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);
        driver.readable(&[b"TestData"]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed_with_transform(10, |_iovecs| {});

        let result: Result<Consumed, &str> = consumer.consume(|_| Err("EAGAIN"));
        assert!(result.is_err());
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
        // writev returns 100 → frame complete.
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

        let result = consumer.consume(|frames| {
            let total: usize = frames
                .iter()
                .flat_map(|f| f.iter())
                .map(|iov| iov.len())
                .sum();
            assert_eq!(total, 100); // payload only
            Ok::<_, ()>(Consumed::Bytes(100))
        });

        assert!(matches!(result, Ok(Consumed::Bytes(100))));
        assert_eq!(consumer.pending_count(), 0);

        // add_used reports ORIGINAL guest length (112), not transformed (100)
        driver.assert_used(&[(0, ExpectedUsed::Readable(112))]);
    }

    #[test]
    fn test_add_header_byte_tracking() {
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

        let result = consumer.consume(|_frames| Ok::<_, ()>(Consumed::Bytes(100)));
        assert!(matches!(result, Ok(Consumed::Bytes(100))));
        assert_eq!(consumer.pending_count(), 0);

        // add_used reports ORIGINAL guest length (112)
        driver.assert_used(&[(0, ExpectedUsed::Readable(112))]);
    }

    #[test]
    fn test_partial_send_with_header_removed() {
        // 2 frames: [header (10) | payload (50)] each.
        // After removing headers: 50 bytes per frame.
        // writev returns 75: completes frame 1 (50), partial frame 2 (25).
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

        let result = consumer.consume(|_frames| Ok::<_, ()>(Consumed::Bytes(75)));
        assert!(matches!(result, Ok(Consumed::Bytes(75))));
        assert_eq!(consumer.pending_count(), 1); // frame 2 partial

        // Only frame 1 complete (original 60 bytes)
        driver.assert_used(&[(0, ExpectedUsed::Readable(60))]);
    }

    #[test]
    fn test_multi_cycle_partial_writes_with_added_header() {
        // Tricky scenario: partial writes across multiple cycles.
        // Frame layout after transform: payload only (100 bytes after skipping 12-byte header)
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
        consumer.consume(|_| Ok::<_, ()>(Consumed::Bytes(2))).unwrap();
        assert_eq!(consumer.pending_count(), 1);

        // Cycle 2: 50 more bytes (total 52)
        consumer.consume(|_| Ok::<_, ()>(Consumed::Bytes(50))).unwrap();
        assert_eq!(consumer.pending_count(), 1);

        // Cycle 3: remaining 48 bytes
        consumer.consume(|_| Ok::<_, ()>(Consumed::Bytes(48))).unwrap();
        assert_eq!(consumer.pending_count(), 0);

        // add_used reports ORIGINAL guest length (112)
        driver.assert_used(&[(0, ExpectedUsed::Readable(112))]);
    }

    #[test]
    fn test_multi_cycle_multiple_frames() {
        // 3 frames of 40 bytes each (after header removal) = 120 bytes total.
        // Cycle 1: 25 bytes (partial frame 1)
        // Cycle 2: 60 bytes (completes frame 1, completes frame 2, partial frame 3)
        // Cycle 3: EAGAIN (no progress)
        // Cycle 4: 35 bytes (completes frame 3)
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

        // Cycle 1: 25 bytes (partial frame 1)
        consumer
            .consume(|_| Ok::<_, ()>(Consumed::Bytes(25)))
            .unwrap();
        assert_eq!(consumer.pending_count(), 3); // no frame complete yet

        // Cycle 2: 60 bytes → total 85 bytes
        // Frame 1: 40 bytes (complete at 40)
        // Frame 2: 40 bytes (complete at 80)
        // Frame 3: 5 bytes into it (at 85)
        consumer
            .consume(|_| Ok::<_, ()>(Consumed::Bytes(60)))
            .unwrap();
        assert_eq!(consumer.pending_count(), 1); // frames 1,2 complete

        // Cycle 3: EAGAIN
        let result: Result<Consumed, &str> = consumer.consume(|_| Err("EAGAIN"));
        assert!(result.is_err());
        assert_eq!(consumer.pending_count(), 1); // still pending

        // Cycle 4: 35 bytes (completes frame 3)
        consumer
            .consume(|_| Ok::<_, ()>(Consumed::Bytes(35)))
            .unwrap();
        assert_eq!(consumer.pending_count(), 0); // all done

        // Verify add_used was called for all 3 frames with ORIGINAL guest lengths (50 each)
        driver.assert_used(&[
            (0, ExpectedUsed::Readable(50)),
            (1, ExpectedUsed::Readable(50)),
            (2, ExpectedUsed::Readable(50)),
        ]);
    }

    #[test]
    fn test_stop_resume_across_compact() {
        // Feed 2 frames, partial send, compact, feed more, continue.
        // This tests that state is preserved when guest adds more descriptors mid-stream.
        let mem = create_memory();
        let queue = create_test_queue();
        let driver = VirtQueueDriver::new(&queue, &mem);

        // First batch: 2 frames of 30 bytes each
        let data = vec![0x50u8; 30];
        driver.readable(&[&data]).readable(&[&data]);

        let mut consumer = TxQueueConsumer::new(queue.clone(), mem.clone(), create_interrupt());

        consumer.feed_with_transform(10, |_iovecs| {});
        assert_eq!(consumer.pending_count(), 2);

        // Send 45 bytes (frame 1 complete, 15 into frame 2)
        consumer
            .consume(|_| Ok::<_, ()>(Consumed::Bytes(45)))
            .unwrap();
        assert_eq!(consumer.pending_count(), 1);

        // Compact removes completed frame 1
        // (compact is called automatically in consume, but let's verify state)

        // Guest adds more descriptors (simulating queue refill)
        driver.readable(&[&data]); // frame 3

        consumer.feed_with_transform(10, |_iovecs| {});
        assert_eq!(consumer.pending_count(), 2); // frame 2 (partial) + frame 3

        // Send remaining 15 of frame 2 + all 30 of frame 3 = 45
        consumer
            .consume(|_| Ok::<_, ()>(Consumed::Bytes(45)))
            .unwrap();
        assert_eq!(consumer.pending_count(), 0);
    }
}
