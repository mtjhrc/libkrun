// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! TX queue consumer for batched virtio transmit operations.

use std::io::IoSlice;

use smallvec::SmallVec;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap};

use super::queue::{DescriptorChain, Queue};
use super::InterruptTransport;

/// Metadata for a frame in the batch - tracks origin for add_used()
#[derive(Debug, Clone, Copy)]
struct FrameMeta {
    /// Descriptor chain head index for queue.add_used()
    head_index: u16,
    /// Bytes in this frame (for stream socket partial write tracking)
    byte_count: usize,
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
    /// Cumulative byte offsets for stream socket partial write tracking
    cumulative_bytes: SmallVec<[usize; 32]>,
    // TODO: Implement a proper HeaderAllocator that the feed() callback can use to safely
    // allocate header bytes and get IoSlice<'static> references. The allocator would:
    // 1. Use a pre-reserved Vec<u8> buffer to prevent reallocation
    // 2. Provide an alloc(&[u8]) -> IoSlice<'static> method
    // 3. Handle the unsafe lifetime extension internally
    // For now, we use Box::leak in the callback code as a temporary workaround.

    /// Number of frames fully sent
    sent_frames: usize,
    /// For stream sockets: bytes sent within partially-sent frame
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
            cumulative_bytes: SmallVec::new(),
            sent_frames: 0,
            partial_bytes: 0,
        }
    }

    /// Feed descriptor chains from queue, applying callback to each.
    ///
    /// The callback receives mutable iovecs from the descriptor chain and can:
    /// - Skip bytes (e.g., vnet header) by using `IoSlice::advance_slices`
    /// - Insert header iovecs (e.g., frame length for stream sockets)
    /// - Modify data in place
    /// - Return the total byte count
    ///
    /// Returns the number of frames added to the batch.
    ///
    /// # Arguments
    /// * `max_frames` - Maximum frames to feed (including already pending)
    /// * `transform` - Callback to transform each descriptor chain's iovecs
    ///
    /// # Callback signature
    /// `FnMut(&mut SmallVec<[IoSlice<'static>; 4]>) -> usize`
    /// - Arg: mutable iovecs from descriptor chain
    /// - Returns: total byte count
    ///
    // TODO: The IoSlice lifetime should ideally be tied to &self rather than 'static,
    // but this causes borrow checker conflicts. The 'static is safe because
    // TxQueueConsumer owns the GuestMemoryMmap and outlives all IoSlice usage.
    pub fn feed<F>(&mut self, max_frames: usize, mut transform_chain: F) -> usize
    where
        F: FnMut(&mut SmallVec<[IoSlice<'static>; 4]>) -> usize,
    {
        let mut added = 0;

        while self.pending_count() < max_frames {
            let Some(head) = self.queue.pop(&self.mem) else {
                break;
            };
            let head_index = head.index;

            // Build iovecs from descriptor chain
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

            // Apply user callback to transform iovecs
            let byte_count = transform_chain(&mut iovecs);

            let cumulative = self.cumulative_bytes.last().copied().unwrap_or(0) + byte_count;

            self.frame_iovecs.push(iovecs);
            self.frame_meta.push(FrameMeta {
                head_index,
                byte_count,
            });
            self.cumulative_bytes.push(cumulative);
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

    /// Get pending frame iovec slices for sendmmsg/sendmsg_x.
    ///
    /// Returns a slice of per-frame iovec arrays, starting from the first unsent frame.
    pub fn frame_iovecs(&self) -> &[SmallVec<[IoSlice<'static>; 4]>] {
        &self.frame_iovecs[self.sent_frames..]
    }

    /// Consume pending frames using a callback that performs the actual I/O.
    ///
    /// The callback receives the frame iovecs and returns `Ok(bytes_written)`.
    /// The consumer then:
    /// - Advances by the returned bytes (completing frames as appropriate)
    /// - Calls add_used() for completed frames
    /// - Signals interrupt if needed
    /// - Compacts internal buffers
    ///
    /// On error (e.g., EAGAIN), pending frames are kept for retry later.
    ///
    /// Returns the number of bytes consumed on success.
    pub fn consume<F, E>(&mut self, f: F) -> Result<usize, E>
    where
        F: FnOnce(&[SmallVec<[IoSlice<'static>; 4]>]) -> Result<usize, E>,
    {
        if !self.has_pending() {
            return Ok(0);
        }

        match f(self.frame_iovecs()) {
            Ok(bytes) => {
                self.advance_bytes(bytes);
                self.compact();
                Ok(bytes)
            }
            Err(e) => Err(e),
        }
    }

    /// Advance by N bytes (for stream sockets - writev returns byte count).
    ///
    /// Calls add_used() for completed frames and signals interrupt.
    pub fn advance_bytes(&mut self, bytes: usize) {
        // Calculate total bytes sent so far (including this call)
        let base = if self.sent_frames > 0 {
            self.cumulative_bytes[self.sent_frames - 1]
        } else {
            0
        };
        let total_sent = base + self.partial_bytes + bytes;

        // Find and complete frames
        while self.sent_frames < self.frame_meta.len() {
            if self.cumulative_bytes[self.sent_frames] <= total_sent {
                let meta = &self.frame_meta[self.sent_frames];
                if let Err(e) = self.queue.add_used(&self.mem, meta.head_index, 0) {
                    log::error!("TxQueueConsumer: failed to add_used: {e}");
                }
                self.sent_frames += 1;
            } else {
                break;
            }
        }

        // Update partial bytes for current incomplete frame
        let new_base = if self.sent_frames > 0 {
            self.cumulative_bytes[self.sent_frames - 1]
        } else {
            0
        };
        self.partial_bytes = total_sent - new_base;

        self.signal_used_if_needed();
    }

    /// Clear completed frames from buffers.
    ///
    /// Call this after processing to free memory from completed frames.
    ///
    /// Note: `partial_bytes` is preserved across compact because it tracks bytes
    /// sent into the first pending frame (which was at index `sent_frames` before
    /// compact and becomes index 0 after compact).
    pub fn compact(&mut self) {
        if self.sent_frames > 0 {
            self.frame_iovecs.drain(..self.sent_frames);
            self.frame_meta.drain(..self.sent_frames);

            // Recalculate cumulative bytes
            let offset = if self.sent_frames <= self.cumulative_bytes.len() {
                self.cumulative_bytes
                    .get(self.sent_frames - 1)
                    .copied()
                    .unwrap_or(0)
            } else {
                0
            };
            self.cumulative_bytes.drain(..self.sent_frames);
            for c in &mut self.cumulative_bytes {
                *c -= offset;
            }

            self.sent_frames = 0;
            // Note: partial_bytes is NOT reset - it tracks bytes sent into the
            // first remaining frame (now at index 0).
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
