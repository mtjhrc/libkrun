// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RX queue provider for batched virtio receive operations.

use std::io::IoSliceMut;

use smallvec::SmallVec;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap};

use super::queue::{DescriptorChain, Queue};
use super::InterruptTransport;

/// RxQueueProvider - owns the RX queue and provides buffers for receiving.
///
/// Pops descriptor chains from the virtio RX queue and provides writable
/// iovecs for receiving data. Unused buffers are kept pending for the next
/// produce() call; used buffers get add_used() with their byte counts.
pub struct RxQueueProducer {
    /// The virtio RX queue (owned)
    queue: Queue,
    /// Guest memory reference
    mem: GuestMemoryMmap,
    /// Interrupt for signaling guest
    interrupt: InterruptTransport,

    /// Pending descriptor chain head indices
    pending_heads: SmallVec<[u16; 32]>,
    /// Writable iovecs for each pending descriptor chain
    pending_iovecs: SmallVec<[SmallVec<[IoSliceMut<'static>; 4]>; 32]>,
}


impl RxQueueProducer {
    /// Create a new RxQueueProvider with the given queue, memory, and interrupt.
    pub fn new(queue: Queue, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> Self {
        Self {
            queue,
            mem,
            interrupt,
            pending_heads: SmallVec::new(),
            pending_iovecs: SmallVec::new(),
        }
    }

    /// Number of buffers currently pending (ready for receive).
    pub fn pending_count(&self) -> usize {
        self.pending_heads.len()
    }

    /// Feed descriptor chains from queue up to max_frames.
    ///
    /// Returns the number of new frames added.
    pub fn feed(&mut self, max_frames: usize) -> usize {
        let mut added = 0;

        while self.pending_count() < max_frames {
            let Some(head) = self.queue.pop(&self.mem) else {
                break;
            };

            let head_index = head.index;
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

            self.pending_heads.push(head_index);
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

    /// Get pending buffers for receiving.
    pub fn buffers(&mut self) -> &mut [SmallVec<[IoSliceMut<'static>; 4]>] {
        &mut self.pending_iovecs
    }

    /// Produce frames by calling the callback with pending buffers.
    ///
    /// The callback receives writable iovecs and returns byte counts for each
    /// frame that was filled. Frames with bytes > 0 are marked as used and
    /// removed; frames with 0 bytes are kept pending for next call.
    ///
    /// Returns the number of frames completed.
    pub fn produce<F>(&mut self, f: F) -> usize
    where
        F: FnOnce(&mut [SmallVec<[IoSliceMut<'static>; 4]>]) -> SmallVec<[usize; 32]>,
    {
        if self.pending_heads.is_empty() {
            return 0;
        }

        let byte_counts = f(&mut self.pending_iovecs);

        // Process results - complete frames with bytes until first zero.
        // Once we hit a zero-byte frame, all remaining frames are kept pending
        // (receive is sequential, so if frame N is empty, frame N+1 can't have data).
        let mut completed = 0;

        for (i, &head_index) in self.pending_heads.iter().enumerate() {
            let bytes = byte_counts.get(i).copied().unwrap_or(0);

            if bytes > 0 {
                // Frame was filled - mark as used
                if let Err(e) = self.queue.add_used(&self.mem, head_index, bytes as u32) {
                    log::error!("RxQueueProvider: failed to add_used: {e}");
                }
                completed += 1;
            } else {
                // First unfilled frame - stop processing, keep this and all remaining
                break;
            }
        }

        // Remove completed frames from the front
        if completed > 0 {
            self.pending_heads.drain(..completed);
            self.pending_iovecs.drain(..completed);
            self.signal_used_if_needed();
        }

        completed
    }

    /// Signal used queue interrupt if needed.
    fn signal_used_if_needed(&mut self) {
        match self.queue.needs_notification(&self.mem) {
            Ok(true) => self.interrupt.signal_used_queue(),
            Ok(false) => {}
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
