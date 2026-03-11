use nix::sys::socket::{
    connect, getsockopt, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::time::Instant;
use vm_memory::GuestMemoryMmap;

use crate::virtio::batch_queue::aliased_ioslice::{AliasedIoSlice, AliasedIoSliceMut, AnyIoSlice};
use crate::virtio::batch_queue::{RxQueueProducer, TxQueueConsumer};
use crate::virtio::net::backend::ConnectError;
use crate::virtio::queue::Queue;
use crate::virtio::InterruptTransport;

use super::backend::{NetBackend, ReadError, WriteError};
use super::FRAME_HEADER_LEN;

/// Try to read/complete the frame length header using non-blocking recv.
/// Returns Some(frame_len) when complete, None if incomplete or EAGAIN.
fn try_read_frame_header(
    raw_fd: RawFd,
    header_buf: &mut [u8; FRAME_HEADER_LEN],
    header_pos: &mut usize,
    expecting: &mut Option<u32>,
) -> Option<usize> {
    if let Some(len) = *expecting {
        return Some(len as usize);
    }

    let remaining = &mut header_buf[*header_pos..];
    let ret = unsafe {
        libc::recv(
            raw_fd,
            remaining.as_mut_ptr() as *mut libc::c_void,
            remaining.len(),
            libc::MSG_DONTWAIT,
        )
    };
    match ret {
        n if n > 0 => {
            *header_pos += n as usize;
            if *header_pos == FRAME_HEADER_LEN {
                let len = u32::from_be_bytes(*header_buf);
                *expecting = Some(len);
                *header_pos = 0;
                Some(len as usize)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Read body using recvmsg with MSG_WAITALL into scatter-gather iovecs.
///
/// # Safety
/// The iovec pointer must be valid and the iovecs must describe writable memory.
unsafe fn recvmsg_waitall(raw_fd: RawFd, iov_ptr: *mut libc::iovec, iov_len: usize) -> isize {
    let mut hdr: libc::msghdr = std::mem::zeroed();
    hdr.msg_iov = iov_ptr;
    hdr.msg_iovlen = iov_len as _;

    libc::recvmsg(raw_fd, &mut hdr, libc::MSG_WAITALL)
}

pub struct Unixstream {
    fd: OwnedFd,
    backend_handles_vnet_hdr: bool,
    interrupt: InterruptTransport,
    tx_consumer: TxQueueConsumer,
    rx_producer: RxQueueProducer,
    /// Shared frame-length header buffer for TX. Written before each writev
    /// when the chain hasn't been partially sent yet.
    tx_frame_header: Box<[u8; FRAME_HEADER_LEN]>,
    /// For RX: partial frame length header buffer
    rx_header_buf: [u8; FRAME_HEADER_LEN],
    /// For RX: bytes read into rx_header_buf so far
    rx_header_pos: usize,
    /// For RX: expected frame length (None when header not yet complete)
    expecting_frame_length: Option<u32>,
    // Timing/stats counters
    rx_calls: u64,
    rx_total_frames: u64,
    rx_total_time_us: u64,
    rx_productive_calls: u64,
}

impl Unixstream {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(
        fd: OwnedFd,
        backend_handles_vnet_hdr: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Self {
        // Blocking socket — MSG_WAITALL for body reads ensures we get full
        // frames without short reads. Header reads use MSG_DONTWAIT.

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }
        if let Err(e) = setsockopt(&fd, sockopt::RcvBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_RCVBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        let iovec_capacity = tx_queue.size as usize * 2;
        let tx_consumer = TxQueueConsumer::new(tx_queue, mem.clone(), iovec_capacity);
        let rx_producer = RxQueueProducer::new(rx_queue, mem, iovec_capacity);

        Self {
            fd,
            backend_handles_vnet_hdr,
            interrupt,
            tx_consumer,
            rx_producer,
            tx_frame_header: Box::new([0u8; FRAME_HEADER_LEN]),
            rx_header_buf: [0u8; FRAME_HEADER_LEN],
            rx_header_pos: 0,
            expecting_frame_length: None,
            rx_calls: 0,
            rx_total_frames: 0,
            rx_total_time_us: 0,
            rx_productive_calls: 0,
        }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(
        path: PathBuf,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Result<Self, ConnectError> {
        #[cfg(target_os = "linux")]
        let flags = SockFlag::SOCK_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = SockFlag::empty();

        let fd = socket(AddressFamily::Unix, SockType::Stream, flags, None)
            .map_err(ConnectError::CreateSocket)?;

        let peer_addr = UnixAddr::new(&path).map_err(ConnectError::InvalidAddress)?;
        connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Ok(Self::new(
            fd,
            include_vnet_header,
            tx_queue,
            rx_queue,
            mem,
            interrupt,
        ))
    }
}

impl NetBackend for Unixstream {
    fn send(&mut self) -> Result<(), WriteError> {
        log::trace!("Unixstream::send() called");
        let skip = if !self.backend_handles_vnet_hdr {
            super::vnet_hdr_len()
        } else {
            0
        };

        let mut total_finished = 0;

        self.tx_consumer.disable_notification();

        loop {
            // Prepend a header iovec pointing to our shared tx_frame_header buffer.
            // The actual length value is written before each writev in consume().
            let header_ptr = self.tx_frame_header.as_ptr();
            self.tx_consumer.feed_with_transform(|iovecs, out| {
                if !out.reserve(iovecs.len() + 1) {
                    return None;
                }
                out.push(unsafe { AliasedIoSlice::from_raw(header_ptr, FRAME_HEADER_LEN) });
                out.extend(AliasedIoSlice::skip_bytes(iovecs, skip));
                Some(())
            });

            if !self.tx_consumer.has_pending() {
                if self.tx_consumer.enable_notification() {
                    self.tx_consumer.disable_notification();
                    continue;
                }
                break;
            }

            let raw_fd = self.fd.as_raw_fd();
            let header_ptr = self.tx_frame_header.as_mut_ptr() as *mut u32;

            // Chains have header iovec prepended; fill in the length before each writev.
            let finished = self.tx_consumer.consume(|batch| {
                for i in 0..batch.len() {
                    let chain = batch.io_slices(i);
                    if chain.is_empty() {
                        continue;
                    }

                    // On first attempt (nothing sent yet), write the payload length
                    // into the shared header buffer via raw pointer (the iovecs
                    // alias this memory, so we must not create a &mut reference).
                    if batch.bytes_used(i) == 0 {
                        let payload_len: usize =
                            AliasedIoSlice::total_len(chain[1..].iter().copied());
                        unsafe {
                            std::ptr::write_volatile(header_ptr, (payload_len as u32).to_be())
                        };
                    }

                    let ret = unsafe {
                        libc::writev(
                            raw_fd,
                            AliasedIoSlice::as_iovec_ptr(chain),
                            chain.len() as libc::c_int,
                        )
                    };
                    match ret {
                        n if n >= 0 => batch.finish(i),
                        _ => {
                            let err = nix::errno::Errno::last();
                            if err == nix::errno::Errno::EAGAIN {
                                break;
                            }
                            log::error!("writev to unixstream failed: {err:?}");
                            break;
                        }
                    }
                }
            });

            total_finished += finished;
            if finished == 0 || self.tx_consumer.has_pending() {
                break;
            }
        }

        if total_finished > 0 && self.tx_consumer.needs_notification() {
            self.interrupt.signal_used_queue();
        }

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        let raw_fd = self.fd.as_raw_fd();
        let vnet_offset = if !self.backend_handles_vnet_hdr {
            super::vnet_hdr_len()
        } else {
            0
        };

        self.rx_calls += 1;
        let frames_before = self.rx_total_frames;
        let call_start = Instant::now();

        let header_buf = &mut self.rx_header_buf;
        let header_pos = &mut self.rx_header_pos;
        let expecting = &mut self.expecting_frame_length;

        let total_finished = self.rx_producer.produce(|batch| {
            batch.disable_notification();
            let mut next = 0;

            loop {
                batch.feed();

                if batch.len() == next {
                    if batch.enable_notification() {
                        batch.disable_notification();
                        continue;
                    }
                    break;
                }

                for i in next..batch.len() {
                    next = i + 1;

                    // Read frame header (non-blocking)
                    let frame_len =
                        match try_read_frame_header(raw_fd, header_buf, header_pos, expecting) {
                            Some(len) => len,
                            None => return,
                        };

                    // Write vnet header at start of new frame
                    if batch.bytes_used(i) == 0 && vnet_offset > 0 {
                        let _ = batch.write_advance(i, &super::DEFAULT_VNET_HDR);
                    }

                    let iovecs = batch.io_slices_mut(i);
                    let ret = if !iovecs.is_empty() && iovecs[0].len() >= frame_len {
                        // Fast path: frame fits in first iovec — use recv directly
                        let iov = iovecs[0].into_iovec();
                        unsafe {
                            libc::recv(raw_fd, iov.iov_base, frame_len, libc::MSG_WAITALL)
                        }
                    } else {
                        // Slow path: frame spans multiple iovecs
                        let iovecs = AliasedIoSliceMut::truncate_slices(iovecs, frame_len);
                        unsafe {
                            recvmsg_waitall(
                                raw_fd,
                                AliasedIoSliceMut::as_iovec_ptr(iovecs) as *mut libc::iovec,
                                iovecs.len(),
                            )
                        }
                    };
                    match ret {
                        n if n > 0 && n as usize >= frame_len => {
                            batch.complete(i, n as usize);
                            *expecting = None;
                        }
                        n if n > 0 => {
                            // Short read — advance iovecs, track remaining
                            batch.advance(i, n as usize);
                            *expecting = Some((frame_len - n as usize) as u32);
                            return;
                        }
                        0 => return, // EOF
                        _ => {
                            let err = nix::errno::Errno::last();
                            if err == nix::errno::Errno::EAGAIN {
                                return;
                            }
                            log::error!("recv from unixstream failed: {err:?}");
                            return;
                        }
                    }
                }
            }
        });

        let frames_this_call = self.rx_total_frames + total_finished as u64 - frames_before;
        self.rx_total_frames += total_finished as u64;
        if frames_this_call > 0 {
            self.rx_total_time_us += call_start.elapsed().as_micros() as u64;
            self.rx_productive_calls += 1;
        }
        if self.rx_calls % 10000 == 0 {
            let avg_call_us = if self.rx_productive_calls > 0 {
                self.rx_total_time_us / self.rx_productive_calls
            } else {
                0
            };
            let avg_us_per_frame = if self.rx_total_frames > 0 {
                self.rx_total_time_us as f64 / self.rx_total_frames as f64
            } else {
                0.0
            };
            eprintln!(
                "RX stats: calls={} productive={} frames={} avg_call={}µs avg_frame={:.2}µs/f empty_calls={}",
                self.rx_calls,
                self.rx_productive_calls,
                self.rx_total_frames,
                avg_call_us,
                avg_us_per_frame,
                self.rx_calls - self.rx_productive_calls,
            );
        }

        if total_finished > 0 && self.rx_producer.needs_notification() {
            self.interrupt.signal_used_queue();
        }

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
