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
use crate::virtio::{report_net_event_fail};
use crate::Error as DeviceError;
use libc::EAGAIN;
use log::{error, warn};
#[cfg(not(test))]
use std::io;
use std::io::{Read, Write};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{cmp, mem, result};
use std::mem::size_of_val;
use std::os::fd::RawFd;
use nix::dir::Type::Socket;
use nix::fcntl::{F_SETFL, fcntl, open};
use nix::sys::socket::{AddressFamily, connect, socket, SockFlag, SockType, UnixAddr};
use nix::unistd;
use nix::unistd::read;
use utils::eventfd::EventFd;
use utils::net::mac::{MacAddr, MAC_ADDR_LEN};
const VIRTIO_F_VERSION_1: u32 = 32; // FIXME: why is this not in virtio_bindings::virtio_net: ???
use virtio_bindings::virtio_net::{
    virtio_net_hdr_v1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MAC,
};
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

enum FrontendError {
    AddUsed,
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    ReadOnlyDescriptor,
}

use crate::virtio::net::{Result, Error};
use crate::virtio::net::Error::PasstSocketRead;
//#[cfg(test)]
//use crate::virtio::net::test_utils::Mocks;

pub(crate) fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

// Frames being sent/received through the network device model have a VNET header. This
// function returns a slice which holds the L2 frame bytes without this header.
fn frame_bytes_from_buf(buf: &[u8]) -> Result<&[u8]> {
    if buf.len() < vnet_hdr_len() {
        Err(Error::VnetHeaderMissing)
    } else {
        Ok(&buf[vnet_hdr_len()..])
    }
}

fn frame_bytes_from_buf_mut(buf: &mut [u8]) -> Result<&mut [u8]> {
    if buf.len() < vnet_hdr_len() {
        Err(Error::VnetHeaderMissing)
    } else {
        Ok(&mut buf[vnet_hdr_len()..])
    }
}

// This initializes to all 0 the VNET hdr part of a buf.
fn init_vnet_hdr(buf: &mut [u8]) {
    // The buffer should be larger than vnet_hdr_len.
    // TODO: any better way to set all these bytes to 0? Or is this optimized by the compiler?
    for i in &mut buf[0..vnet_hdr_len()] {
        *i = 0;
    }
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
        tap_if_name: String,
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

        Ok(Net {
            id,
            passt_socket,
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
                Err(FrontendError::EmptyQueue) | Err(FrontendError::AddUsed) => {
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
                    log::info!("Read {count} bytes from passt: {:x?}", &self.rx_frame_buf[..count]);
                    self.rx_bytes_read = count;
                    self.write_frame_to_guest();
                }
                Err(e) => {
                    // The tap device is non-blocking, so any error aside from EAGAIN is
                    // unexpected.
                    match e {
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
                let header = (read_count as u32).to_be_bytes(); //TODO assert the conversion is not lossy
                //FIXME: what are these first 12 bytes at the begining
                // they are either 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, fe
                // or 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, c0
                // and are then followed by the ethernet header
                let body = &self.tx_frame_buf[12..read_count];
                [&header, body].concat().into()
            };

            log::info!("Writing to passt: {:x?}", &packet);

            match nix::unistd::write(self.passt_socket, &packet) {
                Ok(wrote_count) => { // TODO: loop
                    log::info!("Wrote {wrote_count}/{packet_len} bytes to passt", packet_len=packet.len());
                }Err(e) => {
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


    fn read_frame_from_passt(&mut self) -> Result<usize> {
        unistd::read(self.passt_socket, &mut self.rx_frame_buf)
            .map_err(PasstSocketRead)
    }

    pub fn process_rx_queue_event(&mut self) {
        //METRICS.net.rx_queue_event_count.inc();

        if let Err(e) = self.queue_evts[RX_INDEX].read() {
            // rate limiters present but with _very high_ allowed rate
            error!("Failed to get rx queue event: {:?}", e);
            //METRICS.net.event_fails.inc();
        } else {
            // If the limiter is not blocked, resume the receiving of bytes.
            //if !self.rx_rate_limiter.is_blocked() {
                //self.resume_rx().unwrap_or_else(report_net_event_fail);
            //} else {
                //METRICS.net.rx_rate_limiter_throttled.inc();
            //}
        }
    }

    pub fn process_tap_rx_event(&mut self) {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        //METRICS.net.rx_tap_event_count.inc();

        // While there are no available RX queue buffers and there's a deferred_frame
        // don't process any more incoming. Otherwise start processing a frame. In the
        // process the deferred_frame flag will be set in order to avoid freezing the
        // RX queue.
        if self.queues[RX_INDEX].is_empty(mem)/* && self.rx_deferred_frame*/ {
            //METRICS.net.no_rx_avail_buffer.inc();
            return;
        }

        //if self.rx_deferred_frame
        // Process a deferred frame first if available. Don't read from tap again
        // until we manage to receive this deferred frame.
        //{
        //    self.handle_deferred_frame()
        //        .unwrap_or_else(report_net_event_fail);
        //} else {
            self.process_rx().unwrap_or_else(report_net_event_fail);
        //}
    }

    pub fn process_tx_queue_event(&mut self) {
        //METRICS.net.tx_queue_event_count.inc();
        if let Err(e) = self.queue_evts[TX_INDEX].read() {
            error!("Failed to get tx queue event: {:?}", e);
            //METRICS.net.event_fails.inc();
        } else {
            self.process_tx().unwrap_or_else(report_net_event_fail);
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

    fn set_irq_line(&mut self, irq: u32) {
        todo!()
    }
}
/*
#[cfg(test)]
#[macro_use]
pub mod tests {
    use super::*;
    use crate::virtio::net::device::{
        frame_bytes_from_buf, frame_bytes_from_buf_mut, init_vnet_hdr, vnet_hdr_len,
    };
    use std::net::Ipv4Addr;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::{io, mem, thread};
    use std::str::FromStr;

    use crate::check_metric_after_block;
    use crate::virtio::net::test_utils::test::TestHelper;
    use crate::virtio::net::test_utils::{
        check_used_queue_signal, default_net, if_index, inject_tap_tx_frame, set_mac, NetEvent,
        NetQueue, ReadTapMock, TapTrafficSimulator,
    };
    use crate::virtio::net::QUEUE_SIZES;
    use crate::virtio::{
        Net, VirtioDevice, MAX_BUFFER_SIZE, RX_INDEX, TX_INDEX, TYPE_NET, VIRTIO_MMIO_INT_VRING,
        VIRTQ_DESC_F_WRITE,
    };
    //use logger::{Metric, METRICS};
    use virtio_bindings::virtio_net::{
        virtio_net_hdr_v1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM,
        VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO,
        VIRTIO_NET_F_MAC,
    };
    use vm_memory::{Address, GuestMemory};

    impl Net {
        pub fn read_tap(&mut self) -> io::Result<usize> {
            match &self.mocks.read_tap {
                ReadTapMock::MockFrame(frame) => {
                    self.rx_frame_buf[..frame.len()].copy_from_slice(&frame);
                    Ok(frame.len())
                }
                ReadTapMock::Failure => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Read tap synthetically failed.",
                )),
                ReadTapMock::TapFrame => self.tap.read(&mut self.rx_frame_buf),
            }
        }
    }

    #[test]
    fn test_vnet_helpers() {
        let mut frame_buf = vec![42u8; vnet_hdr_len() - 1];
        assert_eq!(
            format!("{:?}", frame_bytes_from_buf(&frame_buf)),
            "Err(VnetHeaderMissing)"
        );
        assert_eq!(
            format!("{:?}", frame_bytes_from_buf_mut(&mut frame_buf)),
            "Err(VnetHeaderMissing)"
        );

        let mut frame_buf: [u8; MAX_BUFFER_SIZE] = [42u8; MAX_BUFFER_SIZE];

        let vnet_hdr_len_ = mem::size_of::<virtio_net_hdr_v1>();
        assert_eq!(vnet_hdr_len_, vnet_hdr_len());

        init_vnet_hdr(&mut frame_buf);
        let zero_vnet_hdr = vec![0u8; vnet_hdr_len_];
        assert_eq!(zero_vnet_hdr, &frame_buf[..vnet_hdr_len_]);

        let payload = vec![42u8; MAX_BUFFER_SIZE - vnet_hdr_len_];
        assert_eq!(payload, frame_bytes_from_buf(&frame_buf).unwrap());

        {
            let payload = frame_bytes_from_buf_mut(&mut frame_buf).unwrap();
            payload[0] = 15;
        }
        assert_eq!(frame_buf[vnet_hdr_len_], 15);
    }

    #[test]
    fn test_virtio_device_type() {
        let mut net = default_net();
        set_mac(&mut net, MacAddr::from_str("11:22:33:44:55:66").unwrap());
        assert_eq!(net.device_type(), TYPE_NET);
    }

    #[test]
    fn test_virtio_device_features() {
        let mut net = default_net();
        set_mac(&mut net, MacAddr::from_str("11:22:33:44:55:66").unwrap());

        // Test `features()` and `ack_features()`.
        let features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_MAC
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        assert_eq!(net.avail_features_by_page(0), features as u32);
        assert_eq!(net.avail_features_by_page(1), (features >> 32) as u32);
        for i in 2..10 {
            assert_eq!(net.avail_features_by_page(i), 0u32);
        }

        for i in 0..10 {
            net.ack_features_by_page(i, std::u32::MAX);
        }

        assert_eq!(net.acked_features, features);
    }

    #[test]
    fn test_virtio_device_read_config() {
        let mut net = default_net();
        set_mac(&mut net, MacAddr::from_str("11:22:33:44:55:66").unwrap());

        // Test `read_config()`. This also validates the MAC was properly configured.
        let mac = MacAddr::from_str("11:22:33:44:55:66").unwrap();
        let mut config_mac = [0u8; MAC_ADDR_LEN];
        net.read_config(0, &mut config_mac);
        assert_eq!(config_mac, mac.get_bytes());

        // Invalid read.
        config_mac = [0u8; MAC_ADDR_LEN];
        net.read_config(MAC_ADDR_LEN as u64 + 1, &mut config_mac);
        assert_eq!(config_mac, [0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
    }

    #[test]
    fn test_virtio_device_rewrite_config() {
        let mut net = default_net();
        set_mac(&mut net, MacAddr::from_str("11:22:33:44:55:66").unwrap());

        let new_config: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        net.write_config(0, &new_config);
        let mut new_config_read = [0u8; 6];
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);

        // Check that the guest MAC was updated.
        let expected_guest_mac = MacAddr::from_bytes_unchecked(&new_config);
        assert_eq!(expected_guest_mac, net.guest_mac.unwrap());
        //assert_eq!(METRICS.net.mac_address_updates.count(), 1);

        // Partial write (this is how the kernel sets a new mac address) - byte by byte.
        let new_config = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        for i in 0..new_config.len() {
            net.write_config(i as u64, &new_config[i..=i]);
        }
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);

        // Invalid write.
        net.write_config(5, &new_config);
        // Verify old config was untouched.
        new_config_read = [0u8; 6];
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);
    }

    #[test]
    fn test_rx_missing_queue_signal() {
        let mut th = TestHelper::default();
        th.activate_net();

        th.add_desc_chain(NetQueue::Rx, 0, &[(0, 4096, VIRTQ_DESC_F_WRITE)]);
        th.net().queue_evts[RX_INDEX].read().unwrap();
        /*check_metric_after_block!(
            METRICS.net.event_fails,
            1,
            th.simulate_event(NetEvent::RxQueue)
        );*/

        // Check that the used queue didn't advance.
        assert_eq!(th.rxq.used.idx.get(), 0);
    }

    #[test]
    fn test_rx_read_only_descriptor() {
        let mut th = TestHelper::default();
        th.activate_net();

        th.add_desc_chain(
            NetQueue::Rx,
            0,
            &[
                (0, 100, VIRTQ_DESC_F_WRITE),
                (1, 100, 0),
                (2, 1000, VIRTQ_DESC_F_WRITE),
            ],
        );
        let frame = th.check_rx_deferred_frame(1000);
        th.rxq.check_used_elem(0, 0, 0);

        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_short_writable_descriptor() {
        let mut th = TestHelper::default();
        th.activate_net();

        th.add_desc_chain(NetQueue::Rx, 0, &[(0, 100, VIRTQ_DESC_F_WRITE)]);
        let frame = th.check_rx_deferred_frame(1000);
        th.rxq.check_used_elem(0, 0, 0);

        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_partial_write() {
        let mut th = TestHelper::default();
        th.activate_net();

        // The descriptor chain is created so that the last descriptor doesn't fit in the
        // guest memory.
        let offset = th.mem.last_addr().raw_value() - th.data_addr() - 300;
        th.add_desc_chain(
            NetQueue::Rx,
            offset,
            &[
                (0, 100, VIRTQ_DESC_F_WRITE),
                (1, 50, VIRTQ_DESC_F_WRITE),
                (2, 4096, VIRTQ_DESC_F_WRITE),
            ],
        );
        let frame = th.check_rx_deferred_frame(1000);
        th.rxq.check_used_elem(0, 0, 0);

        th.check_rx_queue_resume(&frame);
    }

    #[test]
    fn test_rx_retry() {
        let mut th = TestHelper::default();
        th.activate_net();
        th.net().mocks.set_read_tap(ReadTapMock::TapFrame);

        // Add invalid descriptor chain - read only descriptor.
        th.add_desc_chain(
            NetQueue::Rx,
            0,
            &[
                (0, 100, VIRTQ_DESC_F_WRITE),
                (1, 100, 0),
                (2, 1000, VIRTQ_DESC_F_WRITE),
            ],
        );
        // Add invalid descriptor chain - too short.
        th.add_desc_chain(NetQueue::Rx, 1200, &[(3, 100, VIRTQ_DESC_F_WRITE)]);
        // Add invalid descriptor chain - invalid memory offset.
        th.add_desc_chain(
            NetQueue::Rx,
            th.mem.last_addr().raw_value(),
            &[(4, 1000, VIRTQ_DESC_F_WRITE)],
        );

        // Add valid descriptor chain.
        th.add_desc_chain(NetQueue::Rx, 1300, &[(5, 1000, VIRTQ_DESC_F_WRITE)]);

        // Inject frame to tap and run epoll.
        let frame = inject_tap_tx_frame(&th.net(), 1000);
        check_metric_after_block!(
            METRICS.net.rx_packets_count,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the used queue has advanced.
        assert_eq!(th.rxq.used.idx.get(), 4);
        check_used_queue_signal(&th.net(), 1);
        // Check that the invalid descriptor chains have been discarded
        th.rxq.check_used_elem(0, 0, 0);
        th.rxq.check_used_elem(1, 3, 0);
        th.rxq.check_used_elem(2, 4, 0);
        // Check that the frame wasn't deferred.
        //assert!(!th.net().rx_deferred_frame);
        // Check that the frame has been written successfully to the valid Rx descriptor chain.
        th.rxq.check_used_elem(3, 5, frame.len() as u32);
        th.rxq.dtable[5].check_data(&frame);
    }

    #[test]
    fn test_rx_complex_desc_chain() {
        let mut th = TestHelper::default();
        th.activate_net();
        th.net().mocks.set_read_tap(ReadTapMock::TapFrame);

        // Create a valid Rx avail descriptor chain with multiple descriptors.
        th.add_desc_chain(
            NetQueue::Rx,
            0,
            // Add gaps between the descriptor ids in order to ensure that we follow
            // the `next` field.
            &[
                (3, 100, VIRTQ_DESC_F_WRITE),
                (5, 50, VIRTQ_DESC_F_WRITE),
                (11, 4096, VIRTQ_DESC_F_WRITE),
            ],
        );
        // Inject frame to tap and run epoll.
        let frame = inject_tap_tx_frame(&th.net(), 1000);
        check_metric_after_block!(
            METRICS.net.rx_packets_count,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the frame wasn't deferred.
        //assert!(!th.net().rx_deferred_frame);
        // Check that the used queue has advanced.
        assert_eq!(th.rxq.used.idx.get(), 1);
        check_used_queue_signal(&th.net(), 1);
        // Check that the frame has been written successfully to the Rx descriptor chain.
        th.rxq.check_used_elem(0, 3, frame.len() as u32);
        th.rxq.dtable[3].check_data(&frame[..100]);
        th.rxq.dtable[5].check_data(&frame[100..150]);
        th.rxq.dtable[11].check_data(&frame[150..]);
    }

    #[test]
    fn test_rx_multiple_frames() {
        let mut th = TestHelper::default();
        th.activate_net();
        th.net().mocks.set_read_tap(ReadTapMock::TapFrame);

        // Create 2 valid Rx avail descriptor chains. Each one has enough space to fit the
        // following 2 frames. But only 1 frame has to be written to each chain.
        th.add_desc_chain(
            NetQueue::Rx,
            0,
            &[(0, 500, VIRTQ_DESC_F_WRITE), (1, 500, VIRTQ_DESC_F_WRITE)],
        );
        th.add_desc_chain(
            NetQueue::Rx,
            1000,
            &[(2, 500, VIRTQ_DESC_F_WRITE), (3, 500, VIRTQ_DESC_F_WRITE)],
        );
        // Inject 2 frames to tap and run epoll.
        let frame_1 = inject_tap_tx_frame(&th.net(), 200);
        let frame_2 = inject_tap_tx_frame(&th.net(), 300);
        check_metric_after_block!(
            METRICS.net.rx_packets_count,
            2,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the frames weren't deferred.
        //assert!(!th.net().rx_deferred_frame);
        // Check that the used queue has advanced.
        assert_eq!(th.rxq.used.idx.get(), 2);
        check_used_queue_signal(&th.net(), 1);
        // Check that the 1st frame was written successfully to the 1st Rx descriptor chain.
        th.rxq.check_used_elem(0, 0, frame_1.len() as u32);
        th.rxq.dtable[0].check_data(&frame_1);
        th.rxq.dtable[1].check_data(&[0; 500]);
        // Check that the 2nd frame was written successfully to the 2nd Rx descriptor chain.
        th.rxq.check_used_elem(1, 2, frame_2.len() as u32);
        th.rxq.dtable[2].check_data(&frame_2);
        th.rxq.dtable[3].check_data(&[0; 500]);
    }

    #[test]
    fn test_tx_missing_queue_signal() {
        let mut th = TestHelper::default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        th.add_desc_chain(NetQueue::Tx, 0, &[(0, 4096, 0)]);
        th.net().queue_evts[TX_INDEX].read().unwrap();
        check_metric_after_block!(
            METRICS.net.event_fails,
            1,
            th.simulate_event(NetEvent::TxQueue)
        );

        // Check that the used queue didn't advance.
        assert_eq!(th.txq.used.idx.get(), 0);
        // Check that the frame wasn't sent to the tap.
        assert!(!tap_traffic_simulator.pop_rx_packet(&mut [0; 1000]));
    }

    #[test]
    fn test_tx_writeable_descriptor() {
        let mut th = TestHelper::default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        let desc_list = [(0, 100, 0), (1, 100, VIRTQ_DESC_F_WRITE), (2, 500, 0)];
        th.add_desc_chain(NetQueue::Tx, 0, &desc_list);
        th.write_tx_frame(&desc_list, 700);
        th.event_manager.run_with_timeout(100).unwrap();

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
        check_used_queue_signal(&th.net(), 1);
        th.txq.check_used_elem(0, 0, 0);
        // Check that the frame was skipped.
        assert!(!tap_traffic_simulator.pop_rx_packet(&mut []));
    }

    #[test]
    fn test_tx_short_frame() {
        let mut th = TestHelper::default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        // Send an invalid frame (too small, VNET header missing).
        th.add_desc_chain(NetQueue::Tx, 0, &[(0, 1, 0)]);
        check_metric_after_block!(
            &METRICS.net.tx_malformed_frames,
            1,
            th.event_manager.run_with_timeout(100)
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
        check_used_queue_signal(&th.net(), 1);
        th.txq.check_used_elem(0, 0, 0);
        // Check that the frame was skipped.
        assert!(!tap_traffic_simulator.pop_rx_packet(&mut []));
    }

    #[test]
    fn test_tx_partial_read() {
        let mut th = TestHelper::default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        // The descriptor chain is created so that the last descriptor doesn't fit in the
        // guest memory.
        let offset = th.mem.last_addr().raw_value() + 1 - th.data_addr() - 300;
        let desc_list = [(0, 100, 0), (1, 50, 0), (2, 4096, 0)];
        th.add_desc_chain(NetQueue::Tx, offset, &desc_list);
        let expected_len =
            (150 + th.mem.last_addr().raw_value() + 1 - th.txq.dtable[2].addr.get()) as usize;
        th.write_tx_frame(&desc_list, expected_len);
        check_metric_after_block!(
            METRICS.net.tx_partial_reads,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
        check_used_queue_signal(&th.net(), 1);
        th.txq.check_used_elem(0, 0, 0);
        // Check that the frame was skipped.
        assert!(!tap_traffic_simulator.pop_rx_packet(&mut []));
    }

    #[test]
    fn test_tx_retry() {
        let mut th = TestHelper::default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        // Add invalid descriptor chain - writeable descriptor.
        th.add_desc_chain(
            NetQueue::Tx,
            0,
            &[(0, 100, 0), (1, 100, VIRTQ_DESC_F_WRITE), (2, 500, 0)],
        );
        // Add invalid descriptor chain - invalid memory.
        th.add_desc_chain(NetQueue::Tx, th.mem.last_addr().raw_value(), &[(3, 100, 0)]);
        // Add invalid descriptor chain - too short.
        th.add_desc_chain(NetQueue::Tx, 700, &[(0, 1, 0)]);

        // Add valid descriptor chain
        let desc_list = [(4, 1000, 0)];
        th.add_desc_chain(NetQueue::Tx, 0, &desc_list);
        let frame = th.write_tx_frame(&desc_list, 1000);

        check_metric_after_block!(
            &METRICS.net.tx_malformed_frames,
            3,
            th.event_manager.run_with_timeout(100)
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 4);
        check_used_queue_signal(&th.net(), 1);
        th.txq.check_used_elem(3, 4, 0);
        // Check that the valid frame was sent to the tap.
        let mut buf = vec![0; 1000];
        assert!(tap_traffic_simulator.pop_rx_packet(&mut buf[vnet_hdr_len()..]));
        assert_eq!(&buf, &frame);
        // Check that no other frame was sent to the tap.
        assert!(!tap_traffic_simulator.pop_rx_packet(&mut []));
    }

    #[test]
    fn test_tx_complex_descriptor() {
        let mut th = TestHelper::default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        // Add gaps between the descriptor ids in order to ensure that we follow
        // the `next` field.
        let desc_list = [(3, 100, 0), (5, 50, 0), (11, 850, 0)];
        th.add_desc_chain(NetQueue::Tx, 0, &desc_list);
        let frame = th.write_tx_frame(&desc_list, 1000);

        check_metric_after_block!(
            METRICS.net.tx_packets_count,
            1,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 1);
        check_used_queue_signal(&th.net(), 1);
        th.txq.check_used_elem(0, 3, 0);
        // Check that the frame was sent to the tap.
        let mut buf = vec![0; 1000];
        assert!(tap_traffic_simulator.pop_rx_packet(&mut buf[vnet_hdr_len()..]));
        assert_eq!(&buf[..1000], &frame[..1000]);
    }

    #[test]
    fn test_tx_multiple_frame() {
        let mut th = TestHelper::default();
        th.activate_net();
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&th.net().tap));

        // Write the first frame to the Tx queue
        let desc_list = [(0, 50, 0), (1, 100, 0), (2, 150, 0)];
        th.add_desc_chain(NetQueue::Tx, 0, &desc_list);
        let frame_1 = th.write_tx_frame(&desc_list, 300);
        // Write the second frame to the Tx queue
        let desc_list = [(3, 100, 0), (4, 200, 0), (5, 300, 0)];
        th.add_desc_chain(NetQueue::Tx, 500, &desc_list);
        let frame_2 = th.write_tx_frame(&desc_list, 600);

        check_metric_after_block!(
            METRICS.net.tx_packets_count,
            2,
            th.event_manager.run_with_timeout(100).unwrap()
        );

        // Check that the used queue advanced.
        assert_eq!(th.txq.used.idx.get(), 2);
        check_used_queue_signal(&th.net(), 1);
        th.txq.check_used_elem(0, 0, 0);
        th.txq.check_used_elem(1, 3, 0);
        // Check that the first frame was sent to the tap.
        let mut buf = vec![0; 300];
        assert!(tap_traffic_simulator.pop_rx_packet(&mut buf[vnet_hdr_len()..]));
        assert_eq!(&buf[..300], &frame_1[..300]);
        // Check that the second frame was sent to the tap.
        let mut buf = vec![0; 600];
        assert!(tap_traffic_simulator.pop_rx_packet(&mut buf[vnet_hdr_len()..]));
        assert_eq!(&buf[..600], &frame_2[..600]);
    }

    /*
    #[test]
    fn test_mac_spoofing_detection() {
        let mut net = default_net();

        let guest_mac = MacAddr::from_str("11:11:11:11:11:11").unwrap();
        let not_guest_mac = MacAddr::from_str("33:33:33:33:33:33").unwrap();
        let guest_ip = Ipv4Addr::new(10, 1, 2, 3);
        let dst_mac = MacAddr::from_str("22:22:22:22:22:22").unwrap();
        let dst_ip = Ipv4Addr::new(10, 1, 1, 1);

        let (frame_buf, frame_len) = create_arp_request(guest_mac, guest_ip, dst_mac, dst_ip);

        // Check that a legit MAC doesn't affect the spoofed MAC metric.
        /*
        check_metric_after_block!(
            &METRICS.net.tx_spoofed_mac_count,
            0,
            Net::write_to_mmds_or_tap(
                net.mmds_ns.as_mut(),
                &mut net.tx_rate_limiter,
                &frame_buf[..frame_len],
                &mut net.tap,
                Some(guest_mac),
            )
        );*/

        // Check that a spoofed MAC increases our spoofed MAC metric.
        /*
        check_metric_after_block!(
            &METRICS.net.tx_spoofed_mac_count,
            1,
            Net::write_to_mmds_or_tap(
                net.mmds_ns.as_mut(),
                &mut net.tx_rate_limiter,
                &frame_buf[..frame_len],
                &mut net.tap,
                Some(not_guest_mac),
            )
        );*/
    }*/

    #[test]
    fn test_process_error_cases() {
        let mut th = TestHelper::default();
        th.activate_net();

        // RX rate limiter events should error since the limiter is not blocked.
        // Validate that the event failed and failure was properly accounted for.
        check_metric_after_block!(
            &METRICS.net.event_fails,
            1,
            th.simulate_event(NetEvent::RxRateLimiter)
        );

        // TX rate limiter events should error since the limiter is not blocked.
        // Validate that the event failed and failure was properly accounted for.
        check_metric_after_block!(
            &METRICS.net.event_fails,
            1,
            th.simulate_event(NetEvent::TxRateLimiter)
        );
    }

    // Cannot easily test failures for:
    //  * queue_evt.read (rx and tx)
    //  * interrupt_evt.write
    #[test]
    fn test_read_tap_fail_event_handler() {
        let mut th = TestHelper::default();
        th.activate_net();
        th.net().mocks.set_read_tap(ReadTapMock::Failure);

        // The RX queue is empty and rx_deffered_frame is set.
        //th.net().rx_deferred_frame = true;
        check_metric_after_block!(
            &METRICS.net.no_rx_avail_buffer,
            1,
            th.simulate_event(NetEvent::Tap)
        );

        // Fake an avail buffer; this time, tap reading should error out.
        th.rxq.avail.idx.set(1);
        check_metric_after_block!(
            &METRICS.net.tap_read_fails,
            1,
            th.simulate_event(NetEvent::Tap)
        );
    }

    #[test]
    fn test_virtio_device() {
        let mut th = TestHelper::default();
        th.activate_net();
        let net = th.net.lock().unwrap();

        // Test queues count (TX and RX).
        let queues = net.queues();
        assert_eq!(queues.len(), QUEUE_SIZES.len());
        assert_eq!(queues[RX_INDEX].size, th.rxq.size());
        assert_eq!(queues[TX_INDEX].size, th.txq.size());

        // Test corresponding queues events.
        assert_eq!(net.queue_events().len(), QUEUE_SIZES.len());

        // Test interrupts.
        let interrupt_status = net.interrupt_status();
        interrupt_status.fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        assert_eq!(
            interrupt_status.load(Ordering::SeqCst),
            VIRTIO_MMIO_INT_VRING as usize
        );

        check_used_queue_signal(&net, 0);
    }
}
*/