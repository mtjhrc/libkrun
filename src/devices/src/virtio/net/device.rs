// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE, QUEUE_SIZES, RX_INDEX, TX_INDEX};
//use crate::virtio::net::test_utils::Mocks;
use crate::virtio::{
    ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_NET, VIRTIO_MMIO_INT_VRING,
};
use crate::Error as DeviceError;
use log::{error, warn};
use std::io::{BufReader, Read, Write};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{cmp, mem, result};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use nix::sys::socket::{AddressFamily, connect, socket, SockFlag, SockType, UnixAddr};
use utils::eventfd::EventFd;
use utils::net::mac::{MacAddr, MAC_ADDR_LEN};

const VIRTIO_F_VERSION_1: u32 = 32;

// FIXME: why is this not in virtio_bindings::virtio_net: ???
use virtio_bindings::virtio_net::{
    virtio_net_hdr_v1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MAC,
};
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

enum FrontendError {
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    ReadOnlyDescriptor,
}

use crate::virtio::net::{Result, Error};
use crate::virtio::net::Error::{IO, TryAgain};
//#[cfg(test)]
//use crate::virtio::net::test_utils::Mocks;

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

    pub(crate) passt_socket: RawFd,
    passt_buffered_reader: BufReader<UnixStream>,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: Vec<EventFd>,

    rx_deferred_irqs: bool,

    rx_bytes_read: usize,
    rx_frame_buf: [u8; MAX_BUFFER_SIZE],

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],

    pub(crate) interrupt_status: Arc<AtomicUsize>,
    pub(crate) interrupt_evt: EventFd,

    pub(crate) config_space: ConfigSpace,
    pub(crate) guest_mac: Option<MacAddr>,

    pub(crate) device_state: DeviceState,
    pub(crate) activate_evt: EventFd,
}

impl Net {
    /// Create a new virtio network device using passt
    pub fn new(
        id: String,
        guest_mac: Option<&MacAddr>,
    ) -> Result<Self> {
        /*
        let tap = Tap::open_named(&tap_if_name).map_err(Error::TapOpen)?;

        // Set offload flags to match the virtio features below.
        tap.set_offload(
            net_gen::TUN_F_CSUM | net_gen::TUN_F_UFO | net_gen::TUN_F_TSO4 | net_gen::TUN_F_TSO6,
        )
        .map_err(Error::TapSetOffload)?;
        */
        //let vnet_hdr_size = vnet_hdr_len() as i32;

        //tap.set_vnet_hdr_size(vnet_hdr_size)
        //    .map_err(Error::TapSetVnetHdrSize)?;

        let passt_socket = socket(AddressFamily::Unix, SockType::Stream, SockFlag::SOCK_NONBLOCK, None)
            .map_err(Error::PasstSocketOpen)?;
        //TODO: pass name as arg
        let unix_addr = UnixAddr::new("/tmp/passt_1.socket")
            .map_err(Error::PasstSocketOpen)?;
        connect(passt_socket, &unix_addr)
            .map_err(Error::PasstSocketConnect)?;

        log::info!("Connected just fine!");

        let mut avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
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

        //TODO: should probably use std::net Unix socket in the first place and clone it
        // https://stackoverflow.com/questions/58467659/how-to-store-tcpstream-with-bufreader-and-bufwriter-in-a-data-structure
        let passt_buffered_reader = BufReader::new(
            unsafe { UnixStream::from_raw_fd(passt_socket) }
        );

        Ok(Net {
            id,
            passt_socket,
            passt_buffered_reader,
            avail_features,
            acked_features: 0u64,
            queues,
            queue_evts,
            rx_deferred_irqs: false,
            rx_bytes_read: 0,
            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            config_space,
            guest_mac: guest_mac.copied(),
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
        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            //METRICS.net.event_fails.inc();
            DeviceError::FailedSignalingUsedQueue(e)
        })?;

        self.rx_deferred_irqs = false;
        Ok(())
    }

    fn signal_rx_used_queue(&mut self) -> result::Result<(), DeviceError> {
        if self.rx_deferred_irqs {
            return self.signal_used_queue();
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
        let head_descriptor = queue.pop(mem).ok_or_else(|| {
            //METRICS.net.no_rx_avail_buffer.inc();
            FrontendError::EmptyQueue
        })?;
        let head_index = head_descriptor.index;

        let mut frame_slice = &self.rx_frame_buf[..self.rx_bytes_read];
        log::info!("Will write frame slice {} to guest: {:x?}", self.rx_bytes_read, &self.rx_frame_buf[..self.rx_bytes_read]);

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
                    //METRICS.net.rx_count.inc();
                    frame_slice = &frame_slice[len..];
                }
                Err(e) => {
                    error!("Failed to write slice: {:?}", e);
                    /*match e {
                        GuestMemoryError::PartialBuffer { .. } => &METRICS.net.rx_partial_writes,
                        _ => &METRICS.net.rx_fails,
                    }
                    .inc();*/
                    result = Err(FrontendError::GuestMemory(e));
                    break;
                }
            };

            maybe_next_descriptor = descriptor.next_descriptor();
        }
        if result.is_ok() && !frame_slice.is_empty() {
            warn!("Receiving buffer is too small to hold frame of current size");
            //METRICS.net.rx_fails.inc();
            result = Err(FrontendError::DescriptorChainTooSmall);
        }

        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() { 0 } else { frame_len as u32 };
        queue.add_used(mem, head_index, used_len);
        /*
        .map_err(|e| {
        error!("Failed to add available descriptor {}: {}", head_index, e);
        FrontendError::AddUsed
    })?;*/
        self.rx_deferred_irqs = true;

        if result.is_ok() {
            //METRICS.net.rx_bytes_count.add(frame_len);
            //METRICS.net.rx_packets_count.inc();
        }
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
            match self.read_frame_from_passt() {
                Ok(count) => {
                    self.rx_bytes_read = count;
                    self.write_frame_to_guest();
                }
                Err(e) => {
                    // The tap device is non-blocking, so any error aside from EAGAIN is
                    // unexpected.
                    match e {
                        TryAgain => {
                            error!("TryAgain while reading from passt");
                        }
                        IO(e) => {
                            error!("IO error while reading from passt: {:?}", e);
                        }
                        Error::PasstSocketRead(err) if err == nix::Error::EAGAIN => (),
                        _ => {
                            error!("Failed to read tap: {:?}", e);
                            //METRICS.net.tap_read_fails.inc();
                            return Err(DeviceError::FailedReadTap);
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

        let mut raise_irq = false;
        let tx_queue = &mut self.queues[TX_INDEX];

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
                let limit = cmp::min((read_count + desc_len) as usize, self.tx_frame_buf.len());

                let read_result = mem.read_slice(
                    &mut self.tx_frame_buf[read_count..limit as usize],
                    desc_addr,
                );
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                        //METRICS.net.tx_count.inc();
                    }
                    Err(e) => {
                        error!("Failed to read slice: {:?}", e);
                        /*match e {
                            GuestMemoryError::PartialBuffer { .. } => &METRICS.net.tx_partial_reads,
                            _ => &METRICS.net.rx_fails,
                        }
                        .inc();*/
                        read_count = 0;
                        break;
                    }
                }
            }

            let packet: Box<[u8]> = {
                // TODO: allocate the buffer in the first place...
                log::info!("read count is {read_count}");
                let actual_frame_length = read_count - vnet_hdr_len();
                let header = (actual_frame_length as u32).to_be_bytes(); //TODO assert the conversion is not lossy
                //FIXME: what are these first 12 bytes at the begining
                // they are either 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, fe
                // or 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, c0
                // and are then followed by the ethernet header
                let body = &self.tx_frame_buf[vnet_hdr_len()..read_count];
                [&header, body].concat().into()
            };

            log::info!("Writing to passt: {:x?}", &packet);

            match nix::unistd::write(self.passt_socket, &packet) {
                Ok(wrote_count) => {
                    // TODO: loop
                    log::info!("Wrote {wrote_count}/{packet_len} bytes to passt", packet_len=packet.len());
                }
                Err(e) => {
                    log::warn!("[TODO propagate] Failed to write to passt: {}", e);
                }
            };

            tx_queue.add_used(mem, head_index, 0);
            //     .map_err(DeviceError::QueueError)?;
            raise_irq = true;
        }

        if raise_irq {
            self.signal_used_queue()?;
        } else {
            //METRICS.net.no_tx_avail_buffer.inc();
        }

        Ok(())
    }

    /// Fills self.rx_frame_buf with an ethernet frame from passt and prepends virtio_net_hdr to it
    fn read_frame_from_passt(&mut self) -> Result<usize> {
        let mut len = 0;
        len += write_virtio_net_hdr(&mut self.rx_frame_buf);

        const PASST_HEADER_LEN: usize = 4;
        let frame_length: usize = {
            // each frame from passt is prepended by a 4 byte "header",that is
            // interpreted as a big-endian u32 integer and is the length of the following ethernet
            // frame.
            let mut frame_length = [0u8; PASST_HEADER_LEN];
            self.passt_buffered_reader.read_exact(&mut frame_length)
                .map_err(IO)?; // TODO: better enum
            //println!("frame length read as: {:x?}", frame_length);
            u32::from_be_bytes(frame_length) as usize
        };
        log::info!("!!! Frame from passt reported length={} read len {}", frame_length,  self.rx_frame_buf[len..len + frame_length].len());
        self.passt_buffered_reader.read_exact(&mut self.rx_frame_buf[len..len + frame_length])
            .map_err(IO)?; // TODO: better enum

        /*let mut buf = vec![0u8; frame_length];
        self.passt_buffered_reader.read_exact(&mut buf[..]);
        println!("frame read: {:x?}", &buf);
        */

        len += frame_length;

        Ok(len)
    }

    pub fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[RX_INDEX].read() {
            log::error!("Failed to get rx event from queue: {:?}", e);
        }
    }

    pub fn process_tap_rx_event(&mut self) {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        // TODO(mhrica): is this necessary?
        // While there are no available RX queue buffers and there's a deferred_frame
        // don't process any more incoming. Otherwise start processing a frame. In the
        // process the deferred_frame flag will be set in order to avoid freezing the
        // RX queue.
        if self.queues[RX_INDEX].is_empty(mem)/* && self.rx_deferred_frame*/ {
            //METRICS.net.no_rx_avail_buffer.inc();
            return;
        }

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
            error!("Failed to read config space");
            //METRICS.net.cfg_fails.inc();
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
            error!("Failed to write config space");
            //METRICS.net.cfg_fails.inc();
            return;
        }

        config_space_bytes[offset as usize..(offset + data_len) as usize].copy_from_slice(data);
        self.guest_mac = Some(MacAddr::from_bytes_unchecked(
            &self.config_space.guest_mac[..MAC_ADDR_LEN],
        ));
        //METRICS.net.mac_address_updates.inc();
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            error!("Net: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }

    fn set_irq_line(&mut self, _irq: u32) {
        todo!()
    }
}