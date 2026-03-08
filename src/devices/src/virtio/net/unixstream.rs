use nix::sys::socket::{
    connect, getsockopt, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
};
use nix::unistd::read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::PathBuf;
use utils::fd::SetNonblockingExt;
use vm_memory::GuestMemoryMmap;

use crate::virtio::batch_queue::aliased_ioslice::AliasedIoSlice;
use crate::virtio::batch_queue::ioslice_container_utils::{SliceOfIoSlicesExt, VecOfIoSlicesExt};
use crate::virtio::batch_queue::{RxQueueProducer, TxQueueConsumer};
use crate::virtio::net::backend::ConnectError;
use crate::virtio::queue::Queue;
use crate::virtio::InterruptTransport;

use super::backend::{NetBackend, ReadError, WriteError};
use super::FRAME_HEADER_LEN;

/// Try to read/complete the frame length header.
/// Returns Some(frame_len) when complete, None if incomplete or EAGAIN.
fn try_read_frame_header(
    fd: BorrowedFd,
    header_buf: &mut [u8; FRAME_HEADER_LEN],
    header_pos: &mut usize,
    expecting: &mut Option<u32>,
) -> Option<usize> {
    if let Some(len) = *expecting {
        return Some(len as usize);
    }

    let remaining = &mut header_buf[*header_pos..];
    match read(fd, remaining) {
        Ok(n) if n > 0 => {
            *header_pos += n;
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

pub struct Unixstream {
    fd: OwnedFd,
    backend_handles_vnet_hdr: bool,
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
        // Set socket to non-blocking mode (critical for epoll-based event loop)
        if let Err(e) = fd.set_nonblocking(true) {
            log::error!("Failed to set O_NONBLOCK on the socket: {e}");
        }

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        let tx_consumer = TxQueueConsumer::new(tx_queue, mem.clone(), interrupt.clone());
        let rx_provider = RxQueueProducer::new(rx_queue, mem, interrupt);

        Self {
            fd,
            backend_handles_vnet_hdr,
            tx_consumer,
            rx_producer: rx_provider,
            tx_frame_header: Box::new([0u8; FRAME_HEADER_LEN]),
            rx_header_buf: [0u8; FRAME_HEADER_LEN],
            rx_header_pos: 0,
            expecting_frame_length: None,
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
        let flags = SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = SockFlag::empty();

        let fd = socket(AddressFamily::Unix, SockType::Stream, flags, None)
            .map_err(ConnectError::CreateSocket)?;

        // On macOS, set nonblocking after socket creation since SOCK_NONBLOCK isn't available
        #[cfg(not(target_os = "linux"))]
        fd.set_nonblocking(true).map_err(|e| {
            ConnectError::CreateSocket(nix::Error::from_raw(e.raw_os_error().unwrap_or(libc::EIO)))
        })?;
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

        // Prepend a header iovec pointing to our shared tx_frame_header buffer.
        // The actual length value is written before each writev in consume().
        let header_ptr = self.tx_frame_header.as_ptr();
        let fed = self.tx_consumer.feed_with_transform(|mut v| {
            v.advance(skip);
            v.insert(0, unsafe { AliasedIoSlice::from_raw(header_ptr, FRAME_HEADER_LEN) });
            (v, ())
        });
        log::trace!(
            "Unixstream::send() fed {} frames, pending={}",
            fed,
            self.tx_consumer.pending_count()
        );

        if !self.tx_consumer.has_pending() {
            return Ok(());
        }

        let raw_fd = self.fd.as_raw_fd();
        let header_ptr = self.tx_frame_header.as_mut_ptr() as *mut u32;

        // Chains have header iovec prepended; fill in the length before each writev.
        self.tx_consumer.consume(|batch| {
            for i in 0..batch.len() {
                let chain = batch.io_slices(i);
                if chain.is_empty() {
                    continue;
                }

                // On first attempt (nothing sent yet), write the payload length
                // into the shared header buffer via raw pointer (the iovecs
                // alias this memory, so we must not create a &mut reference).
                if batch.bytes_used(i) == 0 {
                    let payload_len: usize = chain[1..].total_len();
                    unsafe { std::ptr::write_volatile(header_ptr, (payload_len as u32).to_be()) };
                }

                let ret = unsafe {
                    libc::writev(raw_fd, chain.as_iovec_ptr(), chain.len() as libc::c_int)
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

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        let fd = self.fd.as_fd();
        let raw_fd = self.fd.as_raw_fd();
        let vnet_offset = if !self.backend_handles_vnet_hdr {
            super::vnet_hdr_len()
        } else {
            0
        };

        self.rx_producer.feed();

        let header_buf = &mut self.rx_header_buf;
        let header_pos = &mut self.rx_header_pos;
        let expecting = &mut self.expecting_frame_length;

        self.rx_producer.produce(|batch| {
            for i in 0..batch.len() {
                // Read frame header
                let frame_len = match try_read_frame_header(fd, header_buf, header_pos, expecting) {
                    Some(len) => len,
                    None => break,
                };
                let total_len = vnet_offset + frame_len;

                // Write vnet header at start of new frame
                if batch.bytes_used(i) == 0 && vnet_offset > 0 {
                    // Header is small, chain should always have space
                    let _ = batch.write_advance(i, &super::DEFAULT_VNET_HDR);
                }

                // Read payload (truncated to remaining frame bytes)
                let remaining = total_len - batch.bytes_used(i);
                let iovecs = batch.io_slices_mut(i).truncate(remaining);

                let ret = unsafe {
                    libc::readv(raw_fd, iovecs.as_iovec_ptr(), iovecs.len() as libc::c_int)
                };
                match ret {
                    n if n > 0 => {
                        batch.advance(i, n as usize);
                        if batch.bytes_used(i) >= total_len {
                            batch.finish(i);
                            *expecting = None;
                        }
                    }
                    0 => break, // EOF
                    _ => {
                        let err = nix::errno::Errno::last();
                        if err == nix::errno::Errno::EAGAIN {
                            break;
                        }
                        log::error!("readv from unixstream failed: {err:?}");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
