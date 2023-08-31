// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::virtio::net::{passt, MAX_BUFFER_SIZE, QUEUE_SIZE, QUEUE_SIZES, RX_INDEX, TX_INDEX};
use crate::virtio::{
    ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_NET, VIRTIO_MMIO_INT_VRING,
};
use crate::Error as DeviceError;
use std::io::Write;
use std::os::fd::RawFd;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::{cmp, mem, result};
use utils::eventfd::EventFd;
use utils::net::mac::{MacAddr, MAC_ADDR_LEN};

const VIRTIO_F_VERSION_1: u32 = 32;

use crate::legacy::Gic;
use crate::Error::PasstError;
use virtio_bindings::virtio_net::{
    virtio_net_hdr_v1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4,
    VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_MAC,
};
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

enum FrontendError {
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    ReadOnlyDescriptor,
}

use crate::virtio::net::passt::Passt;
use crate::virtio::net::{Error, Result};

pub(crate) fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

// This initializes to all 0 the virtio_net_hdr part of a buf and return the length of the header
// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2050006
fn write_virtio_net_hdr(buf: &mut [u8]) -> usize {
    let len = vnet_hdr_len();
    buf[0..len].fill(0);
    len
}

#[derive(Clone, Copy)]
pub struct ConfigSpace {
    pub guest_mac: [u8; MAC_ADDR_LEN],
}

impl Default for ConfigSpace {
    fn default() -> ConfigSpace {
        ConfigSpace {
            guest_mac: [0; MAC_ADDR_LEN],
        }
    }
}

unsafe impl ByteValued for ConfigSpace {}

pub struct Net {
    pub(crate) id: String,

    passt: Passt,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: Vec<EventFd>,

    rx_deferred_irqs: bool,

    rx_bytes_read: usize,
    rx_frame_buf: [u8; MAX_BUFFER_SIZE],

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],
    tx_frame_len: usize,

    pub(crate) interrupt_status: Arc<AtomicUsize>,
    pub(crate) interrupt_evt: EventFd,

    pub(crate) config_space: ConfigSpace,
    pub(crate) guest_mac: Option<MacAddr>,

    pub(crate) device_state: DeviceState,
    pub(crate) activate_evt: EventFd,

    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,
}

impl Net {
    /// Create a new virtio network device using passt
    pub fn new(id: String, guest_mac: Option<&MacAddr>) -> Result<Self> {
        // TODO: make configurable
        const PASST_SOCK_NAME: &str = "/tmp/passt_1.socket";

        let passt = Passt::connect_to_socket(PASST_SOCK_NAME)?;
        log::info!("Connected to passt @ {PASST_SOCK_NAME}");
        let mut avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        let mut config_space = ConfigSpace::default();
        if let Some(mac) = guest_mac {
            config_space.guest_mac.copy_from_slice(mac.get_bytes());
            // When this feature isn't available, the driver generates a random MAC address.
            // Otherwise, it should attempt to read the device MAC address from the config space.
            avail_features |= 1 << VIRTIO_NET_F_MAC;
        }

        let mut queue_evts = Vec::new();
        for _ in QUEUE_SIZES.iter() {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
        }

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        Ok(Net {
            id,
            passt,
            avail_features,
            acked_features: 0u64,
            queues,
            queue_evts,
            rx_deferred_irqs: false,
            rx_bytes_read: 0,
            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_len: 0,
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            config_space,
            guest_mac: guest_mac.copied(),
            intc: None,
            irq_line: None,
        })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the MAC of this net device.
    pub fn guest_mac(&self) -> Option<&MacAddr> {
        self.guest_mac.as_ref()
    }

    fn signal_used_queue(&mut self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        if let Some(intc) = &self.intc {
            intc.lock().unwrap().set_irq(self.irq_line.unwrap());
            Ok(())
        } else {
            self.interrupt_evt.write(1).map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
        }
    }

    fn signal_rx_used_queue(&mut self) -> result::Result<(), DeviceError> {
        if self.rx_deferred_irqs {
            self.signal_used_queue()?;
            self.rx_deferred_irqs = false;
        }

        Ok(())
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest.
    fn do_write_frame_to_guest(&mut self) -> std::result::Result<(), FrontendError> {
        let mut result: std::result::Result<(), FrontendError> = Ok(());
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let queue = &mut self.queues[RX_INDEX];
        let head_descriptor = queue.pop(mem).ok_or_else(|| FrontendError::EmptyQueue)?;
        let head_index = head_descriptor.index;

        let mut frame_slice = &self.rx_frame_buf[..self.rx_bytes_read];

        let frame_len = frame_slice.len();
        let mut maybe_next_descriptor = Some(head_descriptor);
        while let Some(descriptor) = &maybe_next_descriptor {
            if frame_slice.is_empty() {
                break;
            }

            if !descriptor.is_write_only() {
                result = Err(FrontendError::ReadOnlyDescriptor);
                break;
            }

            let len = std::cmp::min(frame_slice.len(), descriptor.len as usize);
            match mem.write_slice(&frame_slice[..len], descriptor.addr) {
                Ok(()) => {
                    frame_slice = &frame_slice[len..];
                }
                Err(e) => {
                    log::error!("Failed to write slice: {:?}", e);
                    result = Err(FrontendError::GuestMemory(e));
                    break;
                }
            };

            maybe_next_descriptor = descriptor.next_descriptor();
        }
        if result.is_ok() && !frame_slice.is_empty() {
            log::warn!("Receiving buffer is too small to hold frame of current size");
            result = Err(FrontendError::DescriptorChainTooSmall);
        }

        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() { 0 } else { frame_len as u32 };
        queue.add_used(mem, head_index, used_len);
        self.rx_deferred_irqs = true;

        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. In case of an error retries
    // the operation if possible. Returns true if the operation was successfull.
    fn write_frame_to_guest(&mut self) -> bool {
        let max_iterations = self.queues[RX_INDEX].actual_size();
        for _ in 0..max_iterations {
            match self.do_write_frame_to_guest() {
                Ok(()) => return true,
                Err(FrontendError::EmptyQueue) => {
                    return false;
                }
                Err(_) => {
                    // retry
                    continue;
                }
            }
        }

        false
    }

    fn process_rx(&mut self) -> result::Result<(), DeviceError> {
        // Read as many frames as possible.
        loop {
            match self.read_into_rx_frame_buf_from_passt() {
                Ok(()) => {
                    // TODO: check for errors
                    self.write_frame_to_guest();
                }
                Err(e) => {
                    match e {
                        passt::Error::WouldBlock => (),
                        _ => {
                            log::error!("Failed to read from passt: {:?}", e);
                            return Err(DeviceError::PasstError);
                        }
                    };
                    break;
                }
            }
        }

        // At this point we processed as many Rx frames as possible.
        // We have to wake the guest if at least one descriptor chain has been used.
        self.signal_rx_used_queue()
    }

    fn process_tx(&mut self) -> result::Result<(), DeviceError> {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let has_unfinished_write = self.passt_has_unfinished_write();
        let mut raise_irq = false;
        let tx_queue = &mut self.queues[TX_INDEX];


        if has_unfinished_write {
            log::trace!("process_tx: not processing, because passt has an unfinished write");
            /*while let Some(head) = tx_queue.pop(mem) {
                tx_queue.add_used(mem, head.index, 0);
            }
            self.signal_used_queue()?;*/
            return Ok(());
        }

        while let Some(head) = tx_queue.pop(mem) {
            let head_index = head.index;
            let mut read_count = 0;
            let mut next_desc = Some(head);

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    self.tx_iovec.clear();
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                read_count += desc.len as usize;
                next_desc = desc.next_descriptor();
            }

            read_count = 0;
            // Copy buffer from across multiple descriptors.
            // TODO(performance - Issue #420): change this to use `writev()` instead of `write()`
            // and get rid of the intermediate buffer.
            for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                let limit = cmp::min(read_count + desc_len, self.tx_frame_buf.len());

                let read_result =
                    mem.read_slice(&mut self.tx_frame_buf[read_count..limit], desc_addr);
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        log::error!("Failed to read slice: {:?}", e);
                        read_count = 0;
                        break;
                    }
                }
            }

            macro_rules! mark_used {
                () => {{
                    self.tx_frame_len = 0;
                    raise_irq = true;
                    tx_queue.add_used(mem, head_index, 0);
                }};
            }

            self.tx_frame_len = read_count;
            match self
                .passt
                .write_frame(vnet_hdr_len(), &mut self.tx_frame_buf[..read_count])
            {
                Ok(()) => mark_used!(),
                Err(passt::WriteError::NothingWritten) => {
                    log::trace!("process_tx: nothing written to passt, dropping frame");
                    tx_queue.add_used(mem, head_index, 0);
                    while let Some(head) = tx_queue.pop(mem) {
                        tx_queue.add_used(mem, head.index, 0);
                    }
                    break;
                    //mark_used!();
                }
                Err(passt::WriteError::PartialWrite) => {
                    log::trace!("process_tx: partial write");
                    // we hold on to the frame, return the descriptor to the guest,
                    // and stop processing any more frames
                    tx_queue.add_used(mem, head_index, 0);
                    while let Some(head) = tx_queue.pop(mem) {
                        tx_queue.add_used(mem, head.index, 0);
                    }
                    raise_irq = true;
                    break;
                }
                Err(e @ passt::WriteError::Internal(_)) => {
                    log::error!("Failed to write to passt: {:?}", e);
                    return Err(PasstError);
                }
            }
        }

        if raise_irq {
            self.signal_used_queue()?;
        }

        Ok(())
    }

    pub(crate) fn process_passt_socket_writeable(&mut self) {
        match self
            .passt
            .try_finish_write(vnet_hdr_len(), &self.tx_frame_buf[..self.tx_frame_len])
        {
            Ok(()) | Err(passt::WriteError::PartialWrite | passt::WriteError::NothingWritten) => (),
            Err(e @ passt::WriteError::Internal(_)) => {
                log::error!("try_finish_write failed: {e:?}");
            }
        }
    }

    /// Fills self.rx_frame_buf with an ethernet frame from passt and prepends virtio_net_hdr to it
    fn read_into_rx_frame_buf_from_passt(&mut self) -> passt::Result<()> {
        // TODO: consider having less variables inside the struct
        let mut len = 0;
        len += write_virtio_net_hdr(&mut self.rx_frame_buf);
        len += self.passt.read_frame(&mut self.rx_frame_buf[len..])?;
        self.rx_bytes_read = len;
        Ok(())
    }

    pub fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[RX_INDEX].read() {
            log::error!("Failed to get rx event from queue: {:?}", e);
        }
    }

    pub fn process_passt_rx_event(&mut self) {
        self.process_rx().unwrap_or_else(|err| {
            log::error!("Failed to process rx queue event: {err:?}");
        });
    }

    pub fn process_tx_queue_event(&mut self) {
        match self.queue_evts[TX_INDEX].read() {
            Ok(_) => {
                self.process_tx().unwrap_or_else(|err| {
                    log::error!("Failed to process tx event: {err:?}");
                });
            }
            Err(err) => {
                log::error!("Failed to get tx queue event from queue: {err:?}");
            }
        }
    }

    pub(crate) fn raw_passt_socket_fd(&self) -> RawFd {
        self.passt.raw_socket_fd()
    }

    pub(crate) fn passt_has_unfinished_write(&self) -> bool {
        self.passt.has_unfinished_write()
    }
}

impl VirtioDevice for Net {
    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_space_bytes = self.config_space.as_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset >= config_len {
            log::error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(
                &config_space_bytes[offset as usize..cmp::min(end, config_len) as usize],
            )
            .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_space_bytes = self.config_space.as_mut_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset + data_len > config_len {
            log::error!("Failed to write config space");
            return;
        }

        config_space_bytes[offset as usize..(offset + data_len) as usize].copy_from_slice(data);
        self.guest_mac = Some(MacAddr::from_bytes_unchecked(
            &self.config_space.guest_mac[..MAC_ADDR_LEN],
        ));
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            log::error!("Net: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }

    fn set_irq_line(&mut self, irq: u32) {
        self.irq_line = Some(irq);
    }
}
