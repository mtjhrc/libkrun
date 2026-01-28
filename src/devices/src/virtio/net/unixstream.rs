use nix::sys::socket::{
    connect, getsockopt, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
};
use nix::sys::uio::readv;
use nix::unistd::read;
use std::io::IoSlice;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::PathBuf;
use utils::fd::SetNonblockingExt;
use vm_memory::GuestMemoryMmap;

use crate::virtio::iovec_utils::{iovecs_len, truncate_iovecs, write_to_iovecs};
use crate::virtio::net::backend::ConnectError;
use crate::virtio::queue::Queue;
use crate::virtio::rx_queue_producer::RxQueueProducer;
use crate::virtio::tx_queue_consumer::{Consumed, TxQueueConsumer};
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
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            None,
        )
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

        Ok(Self::new(fd, include_vnet_header, tx_queue, rx_queue, mem, interrupt))
    }
}

const MAX_TX_BATCH: usize = 64;
const MAX_RX_BATCH: usize = 64;

impl NetBackend for Unixstream {
    fn send(&mut self) -> Result<(), WriteError> {
        log::trace!("Unixstream::send() called");
        let skip = if !self.backend_handles_vnet_hdr {
            super::vnet_hdr_len()
        } else {
            0
        };

        // Feed frames from queue, prepending frame length header
        let fed = self.tx_consumer.feed_with_transform(MAX_TX_BATCH, |iovecs| {
            // Skip vnet header
            let mut slices: &mut [IoSlice] = iovecs;
            IoSlice::advance_slices(&mut slices, skip);

            // Calculate payload length (after vnet skip)
            let payload_len = iovecs_len(slices);

            // FIXME: This leaks memory! Need proper header storage in TxQueueConsumer.
            // For now, Box::leak the header bytes to get 'static lifetime.
            let header = Box::leak(Box::new((payload_len as u32).to_be_bytes()));
            iovecs.insert(0, IoSlice::new(header));

        });
        log::trace!("Unixstream::send() fed {} frames, pending={}", fed, self.tx_consumer.pending_count());

        if !self.tx_consumer.has_pending() {
            return Ok(());
        }

        let fd = self.fd.as_fd();

        // Frames already have header prepended, just writev each one
        let _ = self.tx_consumer.consume(|frames| {
            let mut total_bytes = 0usize;

            for frame in frames {
                if frame.is_empty() {
                    warn!("Empty frame for send!");
                    continue;
                }

                match nix::sys::uio::writev(fd, frame) {
                    Ok(n) => total_bytes += n,
                    Err(nix::errno::Errno::EAGAIN) => break,
                    Err(nix::errno::Errno::EPIPE) => return Err(WriteError::ProcessNotRunning),
                    Err(e) => return Err(WriteError::Internal(e)),
                }
            }

            Ok(Consumed::Bytes(total_bytes))
        })?;

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        let fd = unsafe { BorrowedFd::borrow_raw(self.fd.as_raw_fd()) };
        let vnet_offset = if !self.backend_handles_vnet_hdr {
            super::vnet_hdr_len()
        } else {
            0
        };

        self.rx_producer.feed(MAX_RX_BATCH);

        let header_buf = &mut self.rx_header_buf;
        let header_pos = &mut self.rx_header_pos;
        let expecting = &mut self.expecting_frame_length;

        self.rx_producer.produce(|chains, completer| {
            for (i, chain) in chains.iter_mut().enumerate() {
                // Read frame header
                let frame_len = match try_read_frame_header(fd, header_buf, header_pos, expecting) {
                    Some(len) => len,
                    None => break,
                };
                let total_len = vnet_offset + frame_len;

                // Write vnet header at start of new frame
                if completer.bytes_used(i) == 0 && vnet_offset > 0 {
                    write_to_iovecs(chain, &super::DEFAULT_VNET_HDR);
                    completer.advance(chain, i, vnet_offset);
                }

                // Read payload (truncated to remaining frame bytes)
                let remaining = total_len - completer.bytes_used(i);
                let iovecs = truncate_iovecs(chain, remaining);

                match readv(fd, iovecs) {
                    Ok(n) if n > 0 => {
                        completer.advance(chain, i, n);
                        if completer.bytes_used(i) >= total_len {
                            completer.finish(i);
                            *expecting = None;
                        }
                    }
                    _ => break,
                }
            }
        });

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
