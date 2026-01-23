use libc::{c_void, iovec, msghdr};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{
    bind, connect, getsockopt, send, setsockopt, socket, sockopt, AddressFamily, MsgFlags,
    SockFlag, SockType, UnixAddr,
};
#[cfg(target_os = "linux")]
use nix::unistd::unlink;
use smallvec::SmallVec;
use std::io::IoSlice;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use vm_memory::GuestMemoryMmap;

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use crate::virtio::queue::Queue;
use crate::virtio::rx_queue_producer::RxQueueProducer;
use crate::virtio::tx_queue_consumer::TxQueueConsumer;
use crate::virtio::InterruptTransport;

#[cfg(target_os = "macos")]
use super::socket_x::msghdr_x;

const VFKIT_MAGIC: [u8; 4] = *b"VFKT";

pub struct Unixgram {
    fd: OwnedFd,
    include_vnet_header: bool,
    tx_consumer: TxQueueConsumer,
    rx_producer: RxQueueProducer,
}

impl Unixgram {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(
        fd: OwnedFd,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Self {
        // Ensure the socket is in non-blocking mode.
        match fcntl(&fd, FcntlArg::F_GETFL) {
            Ok(flags) => match OFlag::from_bits(flags) {
                Some(flags) => {
                    if let Err(e) = fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)) {
                        warn!("error switching to non-blocking: id={fd:?}, err={e}");
                    }
                }
                None => error!("invalid fd flags id={fd:?}"),
            },
            Err(e) => error!("couldn't obtain fd flags id={fd:?}, err={e}"),
        };

        #[cfg(target_os = "macos")]
        {
            // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
            let option_value: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    &option_value as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&option_value) as libc::socklen_t,
                )
            };
        }

        let tx_consumer = TxQueueConsumer::new(tx_queue, mem.clone(), interrupt.clone());
        let rx_provider = RxQueueProducer::new(rx_queue, mem, interrupt);

        Self {
            fd,
            include_vnet_header,
            tx_consumer,
            rx_producer: rx_provider,
        }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(
        path: PathBuf,
        send_vfkit_magic: bool,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Result<Self, ConnectError> {
        // We cannot create a non-blocking socket on macOS here. This is done later in new().
        let fd = socket(
            AddressFamily::Unix,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .map_err(ConnectError::CreateSocket)?;
        let peer_addr = UnixAddr::new(&path).map_err(ConnectError::InvalidAddress)?;
        let local_addr = UnixAddr::new(&PathBuf::from(format!("{}-krun.sock", path.display())))
            .map_err(ConnectError::InvalidAddress)?;
        if let Some(path) = local_addr.path() {
            _ = unlink(path);
        }
        bind(fd.as_raw_fd(), &local_addr).map_err(ConnectError::Binding)?;

        // Connect so we don't need to use the peer address again. This also
        // allows the server to remove the socket after the connection.
        connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;

        if send_vfkit_magic {
            send(fd.as_raw_fd(), &VFKIT_MAGIC, MsgFlags::empty())
                .map_err(ConnectError::SendingMagic)?;
        }

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }
        if let Err(e) = setsockopt(&fd, sockopt::RcvBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Ok(Self::new(fd, include_vnet_header, tx_queue, rx_queue, mem, interrupt))
    }
}

const MAX_TX_BATCH: usize = 64;
const MAX_RX_BATCH: usize = 64;

impl NetBackend for Unixgram {
    fn send(&mut self) -> Result<(), WriteError> {
        let skip = if !self.include_vnet_header {
            super::vnet_hdr_len()
        } else {
            0
        };

        // Feed frames from queue
        self.tx_consumer.feed_with_transform(MAX_TX_BATCH, |iovecs| {
            let mut slices_mut: &mut [IoSlice] = iovecs;
            IoSlice::advance_slices(&mut slices_mut, skip);
            slices_mut.iter().map(|s| s.len()).sum()
        });

        if !self.tx_consumer.has_pending() {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            self.send_linux()?;
        }

        #[cfg(target_os = "macos")]
        {
            self.send_macos()?;
        }

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        let vnet_offset = if !self.include_vnet_header {
            super::vnet_hdr_len()
        } else {
            0
        };

        // Feed buffers from queue
        self.rx_producer.feed(MAX_RX_BATCH);

        if self.rx_producer.pending_count() == 0 {
            return Ok(());
        }

        let fd = self.fd.as_raw_fd();

        self.rx_producer.produce(|buffers| {
            let mut byte_counts: SmallVec<[usize; 32]> = SmallVec::new();

            for buf in buffers.iter_mut() {
                // Prepend vnet header if needed
                if vnet_offset > 0 && !buf.is_empty() {
                    let first = &mut buf[0];
                    if first.len() >= vnet_offset {
                        first[..vnet_offset].copy_from_slice(&super::DEFAULT_VNET_HDR);
                    }
                }

                // Build iovecs skipping vnet header space
                let mut raw_iovecs: SmallVec<[iovec; 4]> = SmallVec::new();
                for (i, iov) in buf.iter().enumerate() {
                    if i == 0 && vnet_offset > 0 {
                        if iov.len() > vnet_offset {
                            raw_iovecs.push(iovec {
                                iov_base: unsafe { (iov.as_ptr() as *mut u8).add(vnet_offset) as *mut c_void },
                                iov_len: iov.len() - vnet_offset,
                            });
                        }
                    } else {
                        raw_iovecs.push(iovec {
                            iov_base: iov.as_ptr() as *mut c_void,
                            iov_len: iov.len(),
                        });
                    }
                }

                if raw_iovecs.is_empty() {
                    byte_counts.push(0);
                    continue;
                }

                let mut msg: msghdr = unsafe { std::mem::zeroed() };
                msg.msg_iov = raw_iovecs.as_mut_ptr();
                msg.msg_iovlen = raw_iovecs.len() as _;

                let ret = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
                if ret > 0 {
                    byte_counts.push(vnet_offset + ret as usize);
                } else {
                    byte_counts.push(0);
                    break; // EAGAIN or error
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

#[cfg(target_os = "linux")]
impl Unixgram {
    fn send_linux(&mut self) -> Result<(), WriteError> {
        let fd = self.fd.as_raw_fd();

        // TODO: Use sendmmsg for better performance. Currently using sendmsg in a loop
        // due to complex lifetime issues with nix's MultiHeaders API.
        let _ = self.tx_consumer.consume(|frames| {
            let mut total_bytes = 0usize;

            for frame in frames.iter().take(MAX_TX_BATCH) {
                if frame.is_empty() {
                    continue;
                }

                // Build iovec array from IoSlices
                let iovecs: SmallVec<[iovec; 4]> = frame
                    .iter()
                    .map(|s| iovec {
                        iov_base: s.as_ptr() as *mut c_void,
                        iov_len: s.len(),
                    })
                    .collect();

                let mut msg: msghdr = unsafe { std::mem::zeroed() };
                msg.msg_iov = iovecs.as_ptr() as *mut iovec;
                msg.msg_iovlen = iovecs.len() as _;

                let ret = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
                if ret >= 0 {
                    total_bytes += ret as usize;
                } else {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
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
}

#[cfg(target_os = "macos")]
impl Unixgram {
    fn send_macos(&mut self) -> Result<(), WriteError> {
        let fd = self.fd.as_raw_fd();

        let _ = self.tx_consumer.consume(|frames| {
            if frames.is_empty() {
                return Ok(0usize);
            }

            // Build adjusted slices (vnet header already skipped in feed())
            let mut adjusted: SmallVec<[SmallVec<[IoSlice<'_>; 4]>; 32]> = frames
                .iter()
                .take(MAX_TX_BATCH)
                .map(|frame| frame.iter().cloned().collect())
                .collect();

            if adjusted.is_empty() {
                return Ok(0);
            }

            // Build msghdr_x array - IoSlice is repr(transparent) over iovec
            let mut msghdrs: SmallVec<[msghdr_x; 32]> = adjusted
                .iter_mut()
                .map(|slices| msghdr_x {
                    msg_iov: slices.as_mut_ptr() as *mut iovec,
                    msg_iovlen: slices.len() as c_int,
                    ..Default::default()
                })
                .collect();

            let ret = unsafe {
                super::socket_x::sendmsg_x(
                    fd,
                    msghdrs.as_ptr(),
                    msghdrs.len() as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };

            if ret < 0 {
                let err = io::Error::last_os_error();
                return match err.kind() {
                    io::ErrorKind::WouldBlock => Ok(0), // Nothing sent, keep pending
                    io::ErrorKind::BrokenPipe => Err(WriteError::ProcessNotRunning),
                    _ => Err(WriteError::Internal(nix::Error::from_raw(
                        err.raw_os_error().unwrap_or(libc::EIO),
                    ))),
                };
            }

            let messages_sent = ret as usize;
            let bytes: usize = msghdrs[..messages_sent]
                .iter()
                .map(|m| m.msg_datalen)
                .sum();

            Ok(bytes)
        })?;

        Ok(())
    }
}
