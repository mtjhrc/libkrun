use libc::{c_int, c_void, iovec};
use nix::sys::socket::{
    connect, getsockopt, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
};
use nix::sys::uio::readv;
use nix::unistd::read;
use smallvec::SmallVec;
use std::cell::Cell;
use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::PathBuf;
use vm_memory::GuestMemoryMmap;

use crate::virtio::net::backend::ConnectError;
use crate::virtio::queue::Queue;
use crate::virtio::rx_queue_producer::RxQueueProducer;
use crate::virtio::tx_queue_consumer::TxQueueConsumer;
use crate::virtio::InterruptTransport;

use super::backend::{NetBackend, ReadError, WriteError};
use super::FRAME_HEADER_LEN;

/// Calculate how to truncate a sequence of buffers to a maximum total length.
///
/// Returns (num_buffers_to_use, last_buffer_len).
///
/// # Example
/// ```ignore
/// assert_eq!(truncate_iovecs_len(&[100, 100, 100], 150), (2, 50));
/// assert_eq!(truncate_iovecs_len(&[100, 100, 100], 300), (3, 100));
/// assert_eq!(truncate_iovecs_len(&[100, 100, 100], 50), (1, 50));
/// ```
fn truncate_iovecs_len(lengths: &[usize], max_bytes: usize) -> (usize, usize) {
    let mut total = 0;
    for (i, &len) in lengths.iter().enumerate() {
        if total + len >= max_bytes {
            return (i + 1, max_bytes - total);
        }
        total += len;
    }
    // All buffers fit within max_bytes
    (lengths.len(), lengths.last().copied().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_iovecs_len_middle() {
        // 3 buffers of 100 each, limit to 150 -> use 2, last has 50
        assert_eq!(truncate_iovecs_len(&[100, 100, 100], 150), (2, 50));
    }

    #[test]
    fn test_truncate_iovecs_len_exact_boundary() {
        // Limit exactly at buffer boundary
        assert_eq!(truncate_iovecs_len(&[100, 100, 100], 200), (2, 100));
    }

    #[test]
    fn test_truncate_iovecs_len_all_fit() {
        // All buffers fit
        assert_eq!(truncate_iovecs_len(&[100, 100, 100], 500), (3, 100));
    }

    #[test]
    fn test_truncate_iovecs_len_first_partial() {
        // Only partial first buffer
        assert_eq!(truncate_iovecs_len(&[100, 100, 100], 50), (1, 50));
    }

    #[test]
    fn test_truncate_iovecs_len_zero() {
        assert_eq!(truncate_iovecs_len(&[100, 100], 0), (1, 0));
    }

    #[test]
    fn test_truncate_iovecs_len_empty() {
        assert_eq!(truncate_iovecs_len(&[], 100), (0, 0));
    }

    #[test]
    fn test_truncate_iovecs_len_varied_sizes() {
        // Buffers: 50, 30, 80, 40 = 200 total, limit to 120
        // 50 + 30 = 80, then 40 more from third -> (3, 40)
        assert_eq!(truncate_iovecs_len(&[50, 30, 80, 40], 120), (3, 40));
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
    /// For RX: bytes of payload already received into current guest buffer
    rx_payload_received: usize,
}

impl Unixstream {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(
        fd: OwnedFd,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Self {
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
            backend_handles_vnet_hdr: include_vnet_header,
            tx_consumer,
            rx_producer: rx_provider,
            rx_header_buf: [0u8; FRAME_HEADER_LEN],
            rx_header_pos: 0,
            expecting_frame_length: None,
            rx_payload_received: 0,
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
            SockFlag::empty(),
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

    /// Try to read/complete the frame length header.
    /// Returns Some(frame_len) when complete, None if incomplete or error.
    fn try_read_frame_length(&mut self, fd: BorrowedFd) -> Option<usize> {
        if let Some(len) = self.expecting_frame_length {
            return Some(len as usize);
        }

        let remaining = &mut self.rx_header_buf[self.rx_header_pos..];
        match read(fd, remaining) {
            Ok(n) if n > 0 => {
                self.rx_header_pos += n;
                if self.rx_header_pos == FRAME_HEADER_LEN {
                    let len = u32::from_be_bytes(self.rx_header_buf);
                    self.expecting_frame_length = Some(len);
                    self.rx_header_pos = 0;
                    Some(len as usize)
                } else {
                    None // Partial header
                }
            }
            Ok(_) => None, // EOF
            Err(nix::errno::Errno::EAGAIN) => None,
            Err(e) => {
                log::error!("Unixstream recv header error: {e}");
                None
            }
        }
    }
}

const MAX_TX_BATCH: usize = 64;

impl NetBackend for Unixstream {
    fn send(&mut self) -> Result<(), WriteError> {
        log::trace!("Unixstream::send() called");
        let skip = if !self.backend_handles_vnet_hdr {
            super::vnet_hdr_len()
        } else {
            0
        };

        // Feed frames from queue
        let fed = self.tx_consumer.feed_with_transform(MAX_TX_BATCH, |iovecs| {
            let mut slices_mut: &mut [IoSlice] = iovecs;
            IoSlice::advance_slices(&mut slices_mut, skip);
            slices_mut.iter().map(|s| s.len()).sum()
        });
        log::trace!("Unixstream::send() fed {} frames, pending={}", fed, self.tx_consumer.pending_count());

        if !self.tx_consumer.has_pending() {
            return Ok(());
        }

        let fd = self.fd.as_raw_fd();

        // For stream sockets, prepend frame length header and use writev
        let _ = self.tx_consumer.consume(|frames| {
            let mut total_bytes = 0usize;

            for frame in frames {
                let frame_len: usize = frame.iter().map(|s| s.len()).sum();
                if frame_len == 0 {
                    continue;
                }

                // Build iovecs with frame header prepended
                let frame_header = (frame_len as u32).to_be_bytes();
                let mut raw_iovecs: SmallVec<[iovec; 8]> = SmallVec::new();

                raw_iovecs.push(iovec {
                    iov_base: frame_header.as_ptr() as *mut c_void,
                    iov_len: FRAME_HEADER_LEN,
                });

                for iov in frame.iter() {
                    raw_iovecs.push(iovec {
                        iov_base: iov.as_ptr() as *mut c_void,
                        iov_len: iov.len(),
                    });
                }

                let ret = unsafe {
                    libc::writev(fd, raw_iovecs.as_ptr(), raw_iovecs.len() as c_int)
                };

                if ret >= 0 {
                    let sent = ret as usize;
                    if sent >= FRAME_HEADER_LEN {
                        total_bytes += sent - FRAME_HEADER_LEN;
                    }
                } else {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        break;
                    } else if err.raw_os_error() == Some(libc::EPIPE) {
                        return Err(WriteError::ProcessNotRunning);
                    } else {
                        return Err(WriteError::Internal(nix::Error::from_raw(
                            err.raw_os_error().unwrap_or(libc::EIO),
                        )));
                    }
                }
            }

            Ok(total_bytes)
        })?;

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        log::trace!("Unixstream::recv() called");
        let vnet_offset = if !self.backend_handles_vnet_hdr {
            super::vnet_hdr_len()
        } else {
            0
        };

        let fd = unsafe { BorrowedFd::borrow_raw(self.fd.as_raw_fd()) };

        // Read/complete frame length header
        let Some(frame_len) = self.try_read_frame_length(fd) else {
            log::trace!("Unixstream::recv() no frame header yet");
            return Ok(());
        };
        log::trace!("Unixstream::recv() frame_len={}", frame_len);

        // Ensure we have a buffer for this frame
        if self.rx_producer.pending_count() == 0 {
            self.rx_producer.feed(1);
            if self.rx_producer.pending_count() == 0 {
                log::trace!("Unixstream::recv() no buffers available");
                return Ok(()); // No buffers available
            }
        }

        // Write vnet header once at the start of a new frame
        if self.rx_payload_received == 0 && vnet_offset > 0 {
            let buffers = self.rx_producer.buffers();
            if !buffers.is_empty() && !buffers[0].is_empty() {
                let first = &mut buffers[0][0];
                if first.len() >= vnet_offset {
                    first[..vnet_offset].copy_from_slice(&super::DEFAULT_VNET_HDR);
                }
            }
        }

        // Use Cell to communicate bytes read from closure
        let bytes_read = Cell::new(0usize);
        let rx_payload_received = self.rx_payload_received;

        let completed = self.rx_producer.produce(|buffers| {
            if buffers.is_empty() || buffers[0].is_empty() {
                return smallvec::smallvec![0];
            }

            let buf = &mut buffers[0];

            // Skip vnet_offset bytes from front
            let mut slices: &mut [IoSliceMut] = buf;
            IoSliceMut::advance_slices(&mut slices, vnet_offset);

            if slices.is_empty() {
                return smallvec::smallvec![0];
            }

            // Truncate to frame_len bytes
            let lengths: SmallVec<[usize; 4]> = slices.iter().map(|s| s.len()).collect();
            let (count, last_len) = truncate_iovecs_len(&lengths, frame_len);

            if count == 0 {
                return smallvec::smallvec![0];
            }

            // Build truncated iovecs
            let mut iovecs: SmallVec<[IoSliceMut; 4]> = SmallVec::new();
            for (i, iov) in slices[..count].iter_mut().enumerate() {
                let len = if i == count - 1 { last_len } else { iov.len() };
                if len > 0 {
                    iovecs.push(IoSliceMut::new(&mut iov[..len]));
                }
            }

            if iovecs.is_empty() {
                return smallvec::smallvec![0];
            }

            // Skip past already-received bytes
            let mut read_slices: &mut [IoSliceMut] = &mut iovecs;
            IoSliceMut::advance_slices(&mut read_slices, rx_payload_received);

            if read_slices.is_empty() {
                return smallvec::smallvec![0];
            }

            match readv(fd, read_slices) {
                Ok(n) if n > 0 => {
                    bytes_read.set(n);
                    let new_total = rx_payload_received + n;

                    debug_assert!(
                        new_total <= frame_len,
                        "BUG: received {} bytes but frame_len is {}",
                        new_total,
                        frame_len
                    );

                    if new_total >= frame_len {
                        // Frame complete
                        smallvec::smallvec![vnet_offset + frame_len]
                    } else {
                        // Partial read - keep buffer pending
                        smallvec::smallvec![0]
                    }
                }
                Ok(_) => {
                    log::trace!("readv returned 0 (EOF)");
                    smallvec::smallvec![0]
                }
                Err(nix::errno::Errno::EAGAIN) => {
                    smallvec::smallvec![0]
                }
                Err(e) => {
                    log::trace!("readv err: {e}");
                    smallvec::smallvec![0]
                }
            }
        });

        // Update state
        self.rx_payload_received += bytes_read.get();

        if completed > 0 {
            // Frame was completed, reset state for next frame
            self.expecting_frame_length = None;
            self.rx_payload_received = 0;
        }

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
