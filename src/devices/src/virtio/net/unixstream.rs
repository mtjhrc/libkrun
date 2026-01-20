use libc::{c_int, c_void, iovec};
use nix::sys::socket::{
    connect, getsockopt, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
};
use smallvec::SmallVec;
use std::io::{self, IoSlice};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use vm_memory::GuestMemoryMmap;

use crate::virtio::net::backend::ConnectError;
use crate::virtio::queue::Queue;
use crate::virtio::rx_queue_provider::RxQueueProvider;
use crate::virtio::tx_queue_consumer::TxQueueConsumer;
use crate::virtio::InterruptTransport;

use super::backend::{NetBackend, ReadError, WriteError};
use super::FRAME_HEADER_LEN;

pub struct Unixstream {
    fd: OwnedFd,
    include_vnet_header: bool,
    tx_consumer: TxQueueConsumer,
    rx_provider: RxQueueProvider,
    /// For RX: expected frame length (0 when not yet read)
    expecting_frame_length: u32,
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
        let rx_provider = RxQueueProvider::new(rx_queue, mem, interrupt);

        Self {
            fd,
            include_vnet_header,
            tx_consumer,
            rx_provider,
            expecting_frame_length: 0,
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
}

const MAX_TX_BATCH: usize = 64;
const MAX_RX_BATCH: usize = 1; // Stream sockets process one frame at a time

impl NetBackend for Unixstream {
    fn send(&mut self) -> Result<(), WriteError> {
        let skip = if !self.include_vnet_header {
            super::vnet_hdr_len()
        } else {
            0
        };

        // Feed frames from queue
        self.tx_consumer.feed(MAX_TX_BATCH, |iovecs| {
            let mut slices_mut: &mut [IoSlice] = iovecs;
            IoSlice::advance_slices(&mut slices_mut, skip);
            slices_mut.iter().map(|s| s.len()).sum()
        });

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
        let vnet_offset = if !self.include_vnet_header {
            super::vnet_hdr_len()
        } else {
            0
        };

        self.rx_provider.feed(MAX_RX_BATCH);

        if self.rx_provider.pending_count() == 0 {
            return Ok(());
        }

        let fd = self.fd.as_raw_fd();
        let expecting_frame_length = &mut self.expecting_frame_length;

        self.rx_provider.produce(|buffers| {
            let mut byte_counts: SmallVec<[usize; 32]> = SmallVec::new();

            for buf in buffers.iter_mut() {
                // Read frame length header if not already known
                if *expecting_frame_length == 0 {
                    let mut header = [0u8; FRAME_HEADER_LEN];
                    let ret = unsafe {
                        libc::read(fd, header.as_mut_ptr() as *mut c_void, FRAME_HEADER_LEN)
                    };
                    if ret == FRAME_HEADER_LEN as isize {
                        *expecting_frame_length = u32::from_be_bytes(header);
                    } else {
                        byte_counts.push(0);
                        break;
                    }
                }

                let frame_len = *expecting_frame_length as usize;

                // Prepend vnet header if needed
                if vnet_offset > 0 && !buf.is_empty() {
                    let first = &mut buf[0];
                    if first.len() >= vnet_offset {
                        first[..vnet_offset].copy_from_slice(&super::DEFAULT_VNET_HDR);
                    }
                }

                // Build iovecs skipping vnet header space
                let mut raw_iovecs: SmallVec<[iovec; 4]> = SmallVec::new();
                let mut total_capacity = 0;

                for (i, iov) in buf.iter().enumerate() {
                    if i == 0 && vnet_offset > 0 {
                        if iov.len() > vnet_offset {
                            let remaining = iov.len() - vnet_offset;
                            let to_recv = std::cmp::min(remaining, frame_len - total_capacity);
                            if to_recv > 0 {
                                raw_iovecs.push(iovec {
                                    iov_base: unsafe { (iov.as_ptr() as *mut u8).add(vnet_offset) as *mut c_void },
                                    iov_len: to_recv,
                                });
                                total_capacity += to_recv;
                            }
                        }
                    } else {
                        let to_recv = std::cmp::min(iov.len(), frame_len - total_capacity);
                        if to_recv > 0 {
                            raw_iovecs.push(iovec {
                                iov_base: iov.as_ptr() as *mut c_void,
                                iov_len: to_recv,
                            });
                            total_capacity += to_recv;
                        }
                    }
                    if total_capacity >= frame_len {
                        break;
                    }
                }

                if raw_iovecs.is_empty() {
                    byte_counts.push(0);
                    continue;
                }

                let ret = unsafe {
                    libc::readv(fd, raw_iovecs.as_ptr(), raw_iovecs.len() as c_int)
                };

                if ret > 0 {
                    *expecting_frame_length = 0;
                    byte_counts.push(vnet_offset + ret as usize);
                } else {
                    byte_counts.push(0);
                    break;
                }
            }

            byte_counts
        });

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
