use libc::iovec;
#[cfg(target_os = "linux")]
use libc::mmsghdr;
#[cfg(target_os = "macos")]
use libc::c_int;
use nix::sys::socket::{
    bind, connect, getsockopt, send, setsockopt, socket, sockopt, AddressFamily, MsgFlags,
    SockFlag, SockType, UnixAddr,
};
use std::fs::remove_file;
use smallvec::SmallVec;
use std::io::IoSlice;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use utils::fd::SetNonblockingExt;
use vm_memory::GuestMemoryMmap;

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use crate::virtio::iovec_utils::write_to_iovecs;
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
        if let Err(e) = fd.set_nonblocking(true) {
            log::error!("Failed to set O_NONBLOCK on unixgram socket: {e}");
        }

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
            _ = remove_file(path);
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

        // Feed chains from queue, writing vnet header and advancing iovecs during feed
        self.rx_producer.feed_with_transform(MAX_RX_BATCH, |iovecs| {
            if vnet_offset > 0 {
                // Write default vnet header to beginning of buffer
                write_to_iovecs(iovecs, &super::DEFAULT_VNET_HDR);
                // Advance iovecs past vnet header so receive goes after it
                crate::virtio::iovec_utils::advance_iovecs(iovecs, vnet_offset);
            }
        });

        #[cfg(target_os = "linux")]
        self.recv_linux();

        #[cfg(target_os = "macos")]
        self.recv_macos();

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

        self.tx_consumer.consume(|batch| {
            if batch.is_empty() {
                return;
            }

            // Build mmsghdr array from chains
            let mut mmsghdrs: SmallVec<[mmsghdr; 32]> = SmallVec::new();
            for i in 0..batch.len().min(MAX_TX_BATCH) {
                let chain = batch.chain(i);
                let mut hdr: mmsghdr = unsafe { std::mem::zeroed() };
                hdr.msg_hdr.msg_iov = chain.as_ptr() as *mut iovec;
                hdr.msg_hdr.msg_iovlen = chain.len() as _;
                mmsghdrs.push(hdr);
            }

            let ret = unsafe {
                libc::sendmmsg(
                    fd,
                    mmsghdrs.as_mut_ptr(),
                    mmsghdrs.len() as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                match err.kind() {
                    std::io::ErrorKind::WouldBlock => {}
                    _ => {
                        log::error!("sendmmsg failed: {err}");
                    }
                }
                return;
            }

            batch.complete_chains(ret as usize);
        });

        Ok(())
    }

    fn recv_linux(&mut self) {
        let fd = self.fd.as_raw_fd();

        self.rx_producer.produce(|batch| {
            if batch.is_empty() {
                return;
            }

            // Build mmsghdr array - iovecs already point past vnet header from feed_with_transform
            let mut mmsghdrs: SmallVec<[mmsghdr; 32]> = SmallVec::new();

            for i in 0..batch.len() {
                let chain = batch.chain_mut(i);
                if chain.is_empty() {
                    log::error!("Empty chain in recv_linux");
                    continue;
                }

                // IoSliceMut is repr(transparent) over iovec
                let mut hdr: mmsghdr = unsafe { std::mem::zeroed() };
                hdr.msg_hdr.msg_iov = chain.as_mut_ptr() as *mut iovec;
                hdr.msg_hdr.msg_iovlen = chain.len() as _;
                mmsghdrs.push(hdr);
            }

            let ret = unsafe {
                libc::recvmmsg(
                    fd,
                    mmsghdrs.as_mut_ptr(),
                    mmsghdrs.len() as libc::c_uint,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                )
            };

            match ret {
                n if n > 0 => {
                    for i in 0..(n as usize) {
                        // vnet header bytes already tracked by feed_with_transform
                        let bytes_received = mmsghdrs[i].msg_len as usize;
                        batch.complete(i, bytes_received);
                    }
                }
                0 => log::warn!("recvmmsg returned 0 (unexpected)"),
                _ => {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::WouldBlock {
                        log::error!("recvmmsg failed: {err}");
                    }
                }
            }
        });
    }
}

#[cfg(target_os = "macos")]
impl Unixgram {
    fn send_macos(&mut self) -> Result<(), WriteError> {
        let fd = self.fd.as_raw_fd();

        self.tx_consumer.consume(|batch| {
            if batch.is_empty() {
                return;
            }

            // Build msghdr_x array from chains
            let mut msghdrs: SmallVec<[msghdr_x; 32]> = SmallVec::new();
            for i in 0..batch.len().min(MAX_TX_BATCH) {
                let chain = batch.chain(i);
                msghdrs.push(msghdr_x {
                    msg_iov: chain.as_ptr() as *mut iovec,
                    msg_iovlen: chain.len() as c_int,
                    ..Default::default()
                });
            }

            let ret = unsafe {
                super::socket_x::sendmsg_x(
                    fd,
                    msghdrs.as_ptr(),
                    msghdrs.len() as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                match err.kind() {
                    std::io::ErrorKind::WouldBlock => {}
                    _ => {
                        log::error!("sendmsg_x failed: {err}");
                    }
                }
                return;
            }

            batch.complete_chains(ret as usize);
        });

        Ok(())
    }

    fn recv_macos(&mut self) {
        let fd = self.fd.as_raw_fd();

        self.rx_producer.produce(|batch| {
            if batch.is_empty() {
                log::trace!("recv_macos: no chains available");
                return;
            }
            log::trace!("recv_macos: {} chains available", batch.len());

            // Build msghdr_x array - iovecs already point past vnet header from feed_with_transform
            let mut msghdrs: SmallVec<[msghdr_x; 32]> = SmallVec::new();

            for i in 0..batch.len() {
                let chain = batch.chain_mut(i);
                if chain.is_empty() {
                    log::error!("Empty chain in recv_macos");
                    continue;
                }

                msghdrs.push(msghdr_x {
                    msg_iov: chain.as_mut_ptr() as *mut iovec,
                    msg_iovlen: chain.len() as c_int,
                    ..Default::default()
                });
            }

            let ret = unsafe {
                super::socket_x::recvmsg_x(
                    fd,
                    msghdrs.as_mut_ptr(),
                    msghdrs.len() as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };

            match ret {
                n if n > 0 => {
                    log::trace!("recv_macos: recvmsg_x returned {n} messages");
                    for i in 0..(n as usize) {
                        // vnet header bytes already tracked by feed_with_transform
                        let bytes_received = msghdrs[i].msg_datalen;
                        log::trace!("recv_macos: message {i} has {bytes_received} bytes payload");
                        batch.complete(i, bytes_received);
                    }
                }
                0 => log::warn!("recvmsg_x returned 0 (unexpected)"),
                _ => {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::WouldBlock {
                        log::error!("recvmsg_x failed: {err}");
                    } else {
                        log::trace!("recv_macos: WouldBlock");
                    }
                }
            }
        });
    }
}
