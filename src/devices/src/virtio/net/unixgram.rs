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
use crate::virtio::batch_queue::aliased_ioslice::RawAliasedIoSlice;
use crate::virtio::batch_queue::ioslice_container_utils::{SliceOfIoSlicesExt, VecOfIoSlicesExt};
use crate::virtio::batch_queue::{ChainsMemoryRepr, ReceivedLen, RxQueueProducer, TxQueueConsumer};
use crate::virtio::queue::Queue;
use crate::virtio::InterruptTransport;

#[cfg(target_os = "macos")]
use super::socket_x::msghdr_x;

const VFKIT_MAGIC: [u8; 4] = *b"VFKT";

// ============================================================================
// MsgHdr - Chain representation that IS an mmsghdr/msghdr_x
// ============================================================================

#[cfg(target_os = "linux")]
type RawMsgHdr = mmsghdr;

#[cfg(target_os = "macos")]
type RawMsgHdr = msghdr_x;

/// Chain representation that wraps mmsghdr/msghdr_x.
///
/// The iovec pointer is stored directly in the header, avoiding allocation
/// of a separate mmsghdr array for sendmmsg/sendmsg_x/recvmmsg/recvmsg_x.
///
/// For RX, use `received_len()` to get the kernel-filled byte count.
///
/// # Safety
/// `from_raw_iovecs` leaks a `Box<[iovec]>` into the header pointer;
/// `clear()` reconstructs and drops it.
#[repr(transparent)]
pub struct MsgHdr(RawMsgHdr);

// Safety: The raw pointer inside points to heap memory that we have exclusive ownership of.
// Transferring to another thread is safe because we transfer ownership of the entire struct.
unsafe impl Send for MsgHdr {}

unsafe impl ChainsMemoryRepr for MsgHdr {
    type Meta = ();

    fn len(&self) -> usize {
        #[cfg(target_os = "linux")]
        {
            self.0.msg_hdr.msg_iovlen
        }
        #[cfg(target_os = "macos")]
        {
            self.0.msg_iovlen as usize
        }
    }

    fn total_bytes(&self) -> usize {
        let (ptr, len) = self.iov_ptr_len();
        if ptr.is_null() {
            0
        } else {
            let slices = unsafe { std::slice::from_raw_parts(ptr as *const iovec, len) };
            slices.iter().map(|s| s.iov_len).sum()
        }
    }

    fn from_raw_iovecs(iovecs: Vec<RawAliasedIoSlice>) -> Self {
        // into_boxed_slice() shrinks so capacity == len; clear() reconstructs
        // the same Box to deallocate.
        let boxed = iovecs.into_boxed_slice();
        let len = boxed.len();
        let iov_ptr = Box::into_raw(boxed) as *mut iovec;

        #[cfg(target_os = "linux")]
        {
            let mut hdr: mmsghdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_iov = iov_ptr;
            hdr.msg_hdr.msg_iovlen = len;
            Self(hdr)
        }

        #[cfg(target_os = "macos")]
        {
            Self(msghdr_x {
                msg_iov: iov_ptr,
                msg_iovlen: len as c_int,
                ..Default::default()
            })
        }
    }

    fn clear(&mut self, _meta: &mut Self::Meta) {
        let (ptr, len) = self.iov_ptr_len();
        if !ptr.is_null() {
            // Reconstruct the Box<[iovec]> leaked in from_raw_iovecs
            unsafe {
                let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len));
            }
            self.set_iov_null();
        }
    }
}

impl MsgHdr {
    #[inline]
    fn iov_ptr_len(&self) -> (*mut iovec, usize) {
        #[cfg(target_os = "linux")]
        {
            (self.0.msg_hdr.msg_iov, self.0.msg_hdr.msg_iovlen)
        }
        #[cfg(target_os = "macos")]
        {
            (self.0.msg_iov, self.0.msg_iovlen as usize)
        }
    }

    #[inline]
    fn set_iov_null(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.0.msg_hdr.msg_iov = std::ptr::null_mut();
            self.0.msg_hdr.msg_iovlen = 0;
        }
        #[cfg(target_os = "macos")]
        {
            self.0.msg_iov = std::ptr::null_mut();
            self.0.msg_iovlen = 0;
        }
    }
}

impl ReceivedLen for MsgHdr {
    #[cfg(target_os = "linux")]
    #[inline]
    fn received_len(&self) -> usize {
        self.0.msg_len as usize
    }

    #[cfg(target_os = "macos")]
    #[inline]
    fn received_len(&self) -> usize {
        self.0.msg_datalen
    }
}

pub struct Unixgram {
    fd: OwnedFd,
    include_vnet_header: bool,
    tx_consumer: TxQueueConsumer<MsgHdr>,
    rx_producer: RxQueueProducer<MsgHdr>,
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
        let rx_producer = RxQueueProducer::new(rx_queue, mem, interrupt);

        Self {
            fd,
            include_vnet_header,
            tx_consumer,
            rx_producer,
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

        // Feed frames from queue, skipping vnet header
        let fed = self.tx_consumer.feed_with_transform(|iovecs| {
            let mut v: Vec<_> = iovecs.collect();
            if skip > 0 {
                v.advance(skip);
            }
            (v, ())
        });
        if fed > 0 {
            log::info!(
                "TX: fed {} chains, pending={}",
                fed,
                self.tx_consumer.pending_count()
            );
        }

        if !self.tx_consumer.has_pending() {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        self.send_linux()?;

        #[cfg(target_os = "macos")]
        self.send_macos()?;

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        let vnet_offset = if !self.include_vnet_header {
            super::vnet_hdr_len()
        } else {
            0
        };
        log::info!(
            "recv: include_vnet_header={} vnet_offset={}",
            self.include_vnet_header,
            vnet_offset
        );

        // Feed chains from queue, writing vnet header and advancing iovecs during feed
        let rx_fed = self.rx_producer.feed_with_transform(|iovecs| {
            let mut v: Vec<_> = iovecs.collect();
            if vnet_offset > 0 {
                // Write default vnet header to beginning of buffer
                v.as_mut_slice().write(&super::DEFAULT_VNET_HDR);
                // Advance iovecs past vnet header so receive goes after it
                v.advance(vnet_offset);
            }
            (v, ())
        });
        if rx_fed > 0 {
            log::info!(
                "RX: fed {} chains, pending={}",
                rx_fed,
                self.rx_producer.pending_count()
            );
        }

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
            let len = batch.len();
            let chains = batch.chains(0..len);
            let ptr = chains.as_ptr() as *mut mmsghdr;

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

        Ok(())
    }

    fn recv_linux(&mut self) {
        let fd = self.fd.as_raw_fd();

        self.rx_producer.produce(|batch| {
            let len = batch.len();
            let ret = {
                let storage = batch.chains_mut(0..len);
                let ptr = storage.as_mut_ptr() as *mut mmsghdr;
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
        });
    }
}

#[cfg(target_os = "macos")]
impl Unixgram {
    fn send_macos(&mut self) -> Result<(), WriteError> {
        let fd = self.fd.as_raw_fd();

        self.tx_consumer.consume(|batch| {
            let len = batch.len();
            // Safety: No chains have been completed yet, so 0..len is valid.
            let storage = batch.chains(0..len);
            let ptr = storage.as_ptr() as *const super::socket_x::msghdr_x;

            let ret = unsafe {
                super::socket_x::sendmsg_x(
                    fd,
                    ptr,
                    len as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
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

        Ok(())
    }

    fn recv_macos(&mut self) {
        let fd = self.fd.as_raw_fd();

        self.rx_producer.produce(|batch| {
            let len = batch.len();
            let ret = {
                let storage = batch.chains_mut(0..len);
                let ptr = storage.as_mut_ptr() as *mut super::socket_x::msghdr_x;
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
        });
    }
}
