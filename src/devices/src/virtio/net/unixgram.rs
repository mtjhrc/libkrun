#[cfg(target_os = "macos")]
use libc::c_int;
use libc::iovec;
#[cfg(target_os = "linux")]
use libc::mmsghdr;
use nix::sys::socket::{
    bind, connect, getsockopt, send, setsockopt, socket, sockopt, AddressFamily, MsgFlags,
    SockFlag, SockType, UnixAddr,
};
use std::fs::remove_file;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use utils::fd::SetNonblockingExt;
use vm_memory::GuestMemoryMmap;

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use crate::virtio::batch_queue::aliased_ioslice::{AliasedIoSlice, AliasedIoSliceMut, AnyIoSlice, RawAliasedIoSlice};
use crate::virtio::batch_queue::{ReceivedBytes, RxQueueProducer, TxQueueConsumer, WorkItemState};
use crate::virtio::queue::Queue;
use crate::virtio::InterruptTransport;

#[cfg(target_os = "macos")]
use super::socket_x::msghdr_x;

const VFKIT_MAGIC: [u8; 4] = *b"VFKT";

#[cfg(target_os = "linux")]
type RawMsgHdr = mmsghdr;

#[cfg(target_os = "macos")]
type RawMsgHdr = msghdr_x;

/// User-owned syscall header state aligned with the batch queue's work items.
#[repr(transparent)]
pub struct MsgHdrItem(RawMsgHdr);

unsafe impl Send for MsgHdrItem {}

impl Default for MsgHdrItem {
    #[cfg(target_os = "linux")]
    fn default() -> Self {
        Self(unsafe { std::mem::zeroed() })
    }

    #[cfg(target_os = "macos")]
    fn default() -> Self {
        Self(msghdr_x::default())
    }
}

impl WorkItemState for MsgHdrItem {
    fn set_iovecs(&mut self, iovecs: &[RawAliasedIoSlice]) {
        let ptr = if iovecs.is_empty() {
            std::ptr::null_mut()
        } else {
            iovecs.as_ptr() as *mut iovec
        };

        #[cfg(target_os = "linux")]
        {
            self.0.msg_hdr.msg_iov = ptr;
            self.0.msg_hdr.msg_iovlen = iovecs.len();
        }

        #[cfg(target_os = "macos")]
        {
            self.0.msg_iov = ptr;
            self.0.msg_iovlen = iovecs.len() as c_int;
        }
    }
}

impl ReceivedBytes for MsgHdrItem {
    #[cfg(target_os = "linux")]
    #[inline]
    fn received_bytes(&self) -> usize {
        self.0.msg_len as usize
    }

    #[cfg(target_os = "macos")]
    #[inline]
    fn received_bytes(&self) -> usize {
        self.0.msg_datalen
    }
}

pub struct Unixgram {
    fd: OwnedFd,
    include_vnet_header: bool,
    interrupt: InterruptTransport,
    tx_consumer: TxQueueConsumer<MsgHdrItem>,
    rx_producer: RxQueueProducer<MsgHdrItem>,
    // Temporary debug counters
    tx_send_calls: u64,
    tx_total_fed: u64,
    tx_total_sent: u64,
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

        let iovec_capacity = tx_queue.size as usize * 2;
        let tx_consumer = TxQueueConsumer::new(tx_queue, mem.clone(), iovec_capacity);
        let rx_producer = RxQueueProducer::new(rx_queue, mem, iovec_capacity);

        Self {
            fd,
            include_vnet_header,
            interrupt,
            tx_consumer,
            rx_producer,
            tx_send_calls: 0,
            tx_total_fed: 0,
            tx_total_sent: 0,
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
            log::warn!("Failed to increase SO_RCVBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
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

impl NetBackend for Unixgram {
    fn send(&mut self) -> Result<(), WriteError> {
        let skip = if !self.include_vnet_header {
            super::vnet_hdr_len()
        } else {
            0
        };

        let mut total_sent = 0;

        self.tx_consumer.disable_notification();

        loop {
            let fed = self.tx_consumer.feed_with_transform(|iovecs, out| {
                if !out.reserve(iovecs.len()) {
                    return None;
                }
                out.extend(AliasedIoSlice::skip_bytes(iovecs, skip));
                Some(MsgHdrItem::default())
            });

            if !self.tx_consumer.has_pending() {
                if self.tx_consumer.enable_notification() {
                    self.tx_consumer.disable_notification();
                    continue;
                }
                break;
            }

            self.tx_send_calls += 1;
            self.tx_total_fed += fed as u64;

            #[cfg(target_os = "linux")]
            let sent = self.send_linux()?;

            #[cfg(target_os = "macos")]
            let sent = self.send_macos()?;

            total_sent += sent;
            self.tx_total_sent += sent as u64;

            if self.tx_send_calls % 10000 == 0 {
                eprintln!(
                    "TX stats: calls={} avg_fed={:.1} avg_sent={:.1}",
                    self.tx_send_calls,
                    self.tx_total_fed as f64 / self.tx_send_calls as f64,
                    self.tx_total_sent as f64 / self.tx_send_calls as f64,
                );
            }

            // Socket blocked (EAGAIN/ENOBUFS) or partial send — wait for EPOLLOUT.
            if sent == 0 || self.tx_consumer.has_pending() {
                break;
            }
        }

        if total_sent > 0 && self.tx_consumer.needs_notification() {
            self.interrupt.signal_used_queue();
        }

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        let vnet_offset = if !self.include_vnet_header {
            super::vnet_hdr_len()
        } else {
            0
        };
        let mut total_finished = 0;

        self.rx_producer.disable_notification();

        loop {
            self.rx_producer.feed_with_transform(|iovecs, out| {
                if !out.reserve(iovecs.len()) {
                    return None;
                }
                out.extend(AliasedIoSliceMut::write_prefix(
                    iovecs,
                    &super::DEFAULT_VNET_HDR[..vnet_offset],
                ));
                let max_bytes = out.total_bytes() + vnet_offset;
                Some((max_bytes, MsgHdrItem::default()))
            });

            if !self.rx_producer.has_pending() {
                if self.rx_producer.enable_notification() {
                    self.rx_producer.disable_notification();
                    continue;
                }
                break;
            }

            #[cfg(target_os = "linux")]
            let finished = self.recv_linux();

            #[cfg(target_os = "macos")]
            let finished = self.recv_macos();

            total_finished += finished;
            if finished == 0 {
                break;
            }
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

#[cfg(target_os = "linux")]
impl Unixgram {
    fn send_linux(&mut self) -> Result<usize, WriteError> {
        let fd = self.fd.as_raw_fd();

        let sent = self.tx_consumer.consume(|batch| {
            let len = batch.len();
            let headers = batch.transformed(0..len);
            let ptr = headers.as_ptr() as *mut mmsghdr;

            let ret = unsafe { libc::sendmmsg(fd, ptr, len as libc::c_uint, libc::MSG_DONTWAIT) };

            if ret < 0 {
                let err = nix::errno::Errno::last();
                if err != nix::errno::Errno::EAGAIN {
                    log::error!("sendmmsg failed: {err}");
                }
                return;
            }

            batch.finish_many(0..ret as usize);
        });

        Ok(sent)
    }

    fn recv_linux(&mut self) -> usize {
        let fd = self.fd.as_raw_fd();

        self.rx_producer.produce(|batch| {
            let len = batch.len();
            let ret = {
                let headers = batch.transformed_mut(0..len);
                let ptr = headers.as_mut_ptr() as *mut mmsghdr;
                unsafe {
                    libc::recvmmsg(
                        fd,
                        ptr,
                        len as libc::c_uint,
                        libc::MSG_DONTWAIT,
                        std::ptr::null_mut(),
                    )
                }
            };

            match ret {
                n if n > 0 => {
                    batch.complete_received_many(0..n as usize);
                }
                0 => log::warn!("recvmmsg returned 0 (unexpected)"),
                _ => {
                    let err = nix::errno::Errno::last();
                    if err != nix::errno::Errno::EAGAIN {
                        log::error!("recvmmsg failed: {err}");
                    }
                }
            }
        })
    }
}

#[cfg(target_os = "macos")]
impl Unixgram {
    fn send_macos(&mut self) -> Result<usize, WriteError> {
        let fd = self.fd.as_raw_fd();

        let sent = self.tx_consumer.consume(|batch| {
            let len = batch.len();
            let headers = batch.transformed(0..len);
            let ptr = headers.as_ptr() as *const super::socket_x::msghdr_x;

            let ret = unsafe {
                super::socket_x::sendmsg_x(fd, ptr, len as libc::c_uint, libc::MSG_DONTWAIT)
            };

            if ret < 0 {
                let err = nix::errno::Errno::last();
                match err {
                    nix::errno::Errno::EAGAIN | nix::errno::Errno::ENOBUFS => {}
                    _ => log::error!("sendmsg_x failed: {err:?}"),
                }
                return;
            }

            batch.finish_many(0..ret as usize);
        });

        Ok(sent)
    }

    fn recv_macos(&mut self) -> usize {
        let fd = self.fd.as_raw_fd();

        self.rx_producer.produce(|batch| {
            let len = batch.len();
            let ret = {
                let headers = batch.transformed_mut(0..len);
                let ptr = headers.as_mut_ptr() as *mut super::socket_x::msghdr_x;
                unsafe {
                    super::socket_x::recvmsg_x(fd, ptr, len as libc::c_uint, libc::MSG_DONTWAIT)
                }
            };

            match ret {
                n if n > 0 => {
                    batch.complete_received_many(0..n as usize);
                }
                0 => log::warn!("recvmsg_x returned 0 (unexpected)"),
                _ => {
                    let err = nix::errno::Errno::last();
                    match err {
                        nix::errno::Errno::EAGAIN | nix::errno::Errno::ENOBUFS => {}
                        _ => log::error!("recvmsg_x failed: {err}"),
                    }
                }
            }
        })
    }
}
