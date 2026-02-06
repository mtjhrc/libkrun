// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared test utilities for TxQueueConsumer and RxQueueProducer tests.

use std::cell::Cell;

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::legacy::DummyIrqChip;
use crate::virtio::queue::tests::{VirtQueue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::InterruptTransport;

// Memory layout constants
pub const QUEUE_ADDR: u64 = 0;
pub const DATA_ADDR: u64 = 0x2000;
pub const MEM_SIZE: u64 = 0x10000;
pub const QUEUE_SIZE: u16 = 16;

/// Create a GuestMemoryMmap for testing
pub fn create_memory() -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE as usize)]).unwrap()
}

/// Create an InterruptTransport for testing
pub fn create_interrupt() -> InterruptTransport {
    InterruptTransport::new(DummyIrqChip::new().into(), "test".to_string()).unwrap()
}

/// Helper to read data from guest memory
pub fn read_data(mem: &GuestMemoryMmap, addr: GuestAddress, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    mem.read(&mut buf, addr).unwrap();
    buf
}

/// Stateful test harness for VirtQueue that persists across multiple add cycles.
/// Simulates a guest driver that adds descriptors, waits for device to consume,
/// then adds more descriptors.
#[allow(dead_code)]
pub struct VirtQueueHarness<'a> {
    vq: VirtQueue<'a>,
    mem: &'a GuestMemoryMmap,
    /// Next descriptor table index to use
    desc_idx: Cell<usize>,
    /// Next available ring index (matches vq.avail.idx)
    avail_idx: Cell<usize>,
    /// Next memory address for data allocation
    next_addr: Cell<u64>,
}

#[allow(dead_code)]
impl<'a> VirtQueueHarness<'a> {
    pub fn new(mem: &'a GuestMemoryMmap) -> Self {
        let vq = VirtQueue::new(GuestAddress(QUEUE_ADDR), mem, QUEUE_SIZE);
        Self {
            vq,
            mem,
            desc_idx: Cell::new(0),
            avail_idx: Cell::new(0),
            next_addr: Cell::new(DATA_ADDR),
        }
    }

    /// Create the Queue for the consumer/provider.
    pub fn create_queue(&self) -> crate::virtio::Queue {
        self.vq.create_queue()
    }

    /// Add a readable frame (single descriptor chain) with given data.
    pub fn add_readable(&self, data: &[u8]) {
        let addr = self.next_addr.get();
        let size = data.len() as u64;
        self.next_addr.set(addr + std::cmp::max(size, 0x100));
        assert!(self.next_addr.get() <= MEM_SIZE, "out of memory");

        self.mem.write(data, GuestAddress(addr)).unwrap();

        let idx = self.desc_idx.get();
        assert!(idx < QUEUE_SIZE as usize, "descriptor table full");
        self.vq.dtable[idx].set(addr, data.len() as u32, 0, 0);
        self.desc_idx.set(idx + 1);

        let avail = self.avail_idx.get();
        self.vq.avail.ring[avail].set(idx as u16);
        self.avail_idx.set(avail + 1);
        self.vq.avail.idx.set(self.avail_idx.get() as u16);
    }

    /// Add a writable buffer (single descriptor chain) with given size.
    pub fn add_writable(&self, len: u32) {
        let addr = self.next_addr.get();
        self.next_addr.set(addr + std::cmp::max(len as u64, 0x100));
        assert!(self.next_addr.get() <= MEM_SIZE, "out of memory");

        let idx = self.desc_idx.get();
        assert!(idx < QUEUE_SIZE as usize, "descriptor table full");
        self.vq.dtable[idx].set(addr, len, VIRTQ_DESC_F_WRITE, 0);
        self.desc_idx.set(idx + 1);

        let avail = self.avail_idx.get();
        self.vq.avail.ring[avail].set(idx as u16);
        self.avail_idx.set(avail + 1);
        self.vq.avail.idx.set(self.avail_idx.get() as u16);
    }

    /// Add a chained readable frame (multiple descriptors forming one chain).
    pub fn add_readable_chained(&self, segments: &[&[u8]]) {
        assert!(!segments.is_empty());
        let head_idx = self.desc_idx.get();

        for (i, data) in segments.iter().enumerate() {
            let addr = self.next_addr.get();
            let size = data.len() as u64;
            self.next_addr.set(addr + std::cmp::max(size, 0x100));
            assert!(self.next_addr.get() <= MEM_SIZE, "out of memory");

            self.mem.write(data, GuestAddress(addr)).unwrap();

            let idx = self.desc_idx.get();
            assert!(idx < QUEUE_SIZE as usize, "descriptor table full");

            let is_last = i == segments.len() - 1;
            let flags = if is_last { 0 } else { VIRTQ_DESC_F_NEXT };
            let next = if is_last { 0 } else { (idx + 1) as u16 };

            self.vq.dtable[idx].set(addr, data.len() as u32, flags, next);
            self.desc_idx.set(idx + 1);
        }

        let avail = self.avail_idx.get();
        self.vq.avail.ring[avail].set(head_idx as u16);
        self.avail_idx.set(avail + 1);
        self.vq.avail.idx.set(self.avail_idx.get() as u16);
    }

    /// Add a chained writable buffer (multiple descriptors forming one chain).
    pub fn add_writable_chained(&self, sizes: &[u32]) {
        assert!(!sizes.is_empty());
        let head_idx = self.desc_idx.get();

        for (i, &len) in sizes.iter().enumerate() {
            let addr = self.next_addr.get();
            self.next_addr.set(addr + std::cmp::max(len as u64, 0x100));
            assert!(self.next_addr.get() <= MEM_SIZE, "out of memory");

            let idx = self.desc_idx.get();
            assert!(idx < QUEUE_SIZE as usize, "descriptor table full");

            let is_last = i == sizes.len() - 1;
            let flags = VIRTQ_DESC_F_WRITE | if is_last { 0 } else { VIRTQ_DESC_F_NEXT };
            let next = if is_last { 0 } else { (idx + 1) as u16 };

            self.vq.dtable[idx].set(addr, len, flags, next);
            self.desc_idx.set(idx + 1);
        }

        let avail = self.avail_idx.get();
        self.vq.avail.ring[avail].set(head_idx as u16);
        self.avail_idx.set(avail + 1);
        self.vq.avail.idx.set(self.avail_idx.get() as u16);
    }
}

/// Helper for building descriptor chains in tests.
pub struct DescChainBuilder<'a, 'b> {
    vq: &'a VirtQueue<'b>,
    mem: &'a GuestMemoryMmap,
    desc_idx: usize,
    avail_idx: usize,
    chain_head: Option<u16>,
    prev_desc: Option<u16>,
    next_addr: u64,
}

impl<'a, 'b> DescChainBuilder<'a, 'b> {
    fn new(vq: &'a VirtQueue<'b>, mem: &'a GuestMemoryMmap) -> Self {
        Self {
            vq,
            mem,
            desc_idx: 0,
            avail_idx: 0,
            chain_head: None,
            prev_desc: None,
            next_addr: DATA_ADDR,
        }
    }

    /// Add a readable descriptor with data (for TX).
    pub fn readable(mut self, data: &[u8]) -> Self {
        let addr = self.next_addr;
        let size = data.len() as u64;
        self.next_addr += std::cmp::max(size, 0x100);
        assert!(self.next_addr <= MEM_SIZE, "descriptor data exceeds guest memory");

        self.mem.write(data, GuestAddress(addr)).unwrap();
        self.add_desc(addr, data.len() as u32, 0);
        self
    }

    /// Add a writable descriptor buffer (for RX).
    pub fn writable(mut self, len: u32) -> Self {
        let addr = self.next_addr;
        self.next_addr += std::cmp::max(len as u64, 0x100);
        assert!(self.next_addr <= MEM_SIZE, "descriptor buffer exceeds guest memory");

        self.add_desc(addr, len, VIRTQ_DESC_F_WRITE);
        self
    }

    /// End the current chain and make it available.
    pub fn end_chain(mut self) -> Self {
        if let Some(head) = self.chain_head.take() {
            assert!(self.avail_idx < QUEUE_SIZE as usize, "available ring overflow");
            self.vq.avail.ring[self.avail_idx].set(head);
            self.avail_idx += 1;
            self.vq.avail.idx.set(self.avail_idx as u16);
        }
        self.prev_desc = None;
        self
    }

    /// Add multiple readable frames (each is a separate chain).
    pub fn readable_frames(mut self, frames: &[&[u8]]) -> Self {
        for data in frames {
            self = self.readable(data).end_chain();
        }
        self
    }

    /// Add multiple writable buffers (each is a separate chain).
    pub fn writable_buffers(mut self, sizes: &[u32]) -> Self {
        for &size in sizes {
            self = self.writable(size).end_chain();
        }
        self
    }

    fn add_desc(&mut self, addr: u64, len: u32, flags: u16) {
        let idx = self.desc_idx;
        assert!(idx < QUEUE_SIZE as usize, "descriptor table overflow");
        self.desc_idx += 1;

        if let Some(prev) = self.prev_desc {
            let old_flags = self.vq.dtable[prev as usize].flags.get();
            self.vq.dtable[prev as usize].flags.set(old_flags | VIRTQ_DESC_F_NEXT);
            self.vq.dtable[prev as usize].next.set(idx as u16);
        } else {
            self.chain_head = Some(idx as u16);
        }

        self.vq.dtable[idx].set(addr, len, flags, 0);
        self.prev_desc = Some(idx as u16);
    }
}

/// Extension trait for VirtQueue setup.
pub trait VirtQueueExt<'a> {
    fn builder<'b>(&'a self, mem: &'a GuestMemoryMmap) -> DescChainBuilder<'a, 'b>
    where
        'a: 'b;
}

impl<'a> VirtQueueExt<'a> for VirtQueue<'a> {
    fn builder<'b>(&'a self, mem: &'a GuestMemoryMmap) -> DescChainBuilder<'a, 'b>
    where
        'a: 'b,
    {
        DescChainBuilder::new(self, mem)
    }
}
