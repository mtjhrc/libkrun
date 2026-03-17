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

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum MacosSendRecvMode {
    /// Plain sendmsg/recvmsg, one packet at a time in a loop.
    Plain,
    /// sendmsg_x/recvmsg_x with configurable max batch size.
    Batched { max_batch: usize },
    /// Flatten iovecs into a contiguous buffer, then use plain send/recv.
    Copied,
}

#[cfg(target_os = "macos")]
const MACOS_MODE: MacosSendRecvMode = MacosSendRecvMode::Batched { max_batch: 32 };

/// Busy-loop iterations after each finish() call (0 = no delay).
/// Gives the guest CPU time to reclaim used buffers.
#[cfg(target_os = "macos")]
const FINISH_SPIN_ITERS: u32 = 0;

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
    tx_empty_feeds: u64,
    tx_enobufs: u64,
    tx_fed_samples: Vec<usize>,
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
            tx_empty_feeds: 0,
            tx_enobufs: 0,
            tx_fed_samples: Vec::new(),
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

        /*if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }
        if let Err(e) = setsockopt(&fd, sockopt::RcvBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_RCVBUF (performance may be decreased): {e}");
        }*/

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
            if fed > 0 {
                self.tx_fed_samples.push(fed);
            } else {
                self.tx_empty_feeds += 1;
            }
            
            if !self.tx_consumer.has_pending() {
                break
            }

            #[cfg(target_os = "linux")]
            let send_result = self.send_linux();

            #[cfg(target_os = "macos")]
            let send_result = self.send_macos();

            let sent = match send_result {
                Ok(sent) => sent,
                Err(WriteError::NothingWritten) => {
                    self.tx_enobufs += 1;
                    if total_sent > 0 && self.tx_consumer.needs_notification() {
                        self.interrupt.signal_used_queue();
                    }
                    return Err(WriteError::NothingWritten);
                }
                Err(e) => return Err(e),
            };

            total_sent += sent;
            self.tx_total_sent += sent as u64;

            if self.tx_send_calls % 10000 == 0 {
                let empty_pct = self.tx_empty_feeds as f64 / self.tx_send_calls as f64 * 100.0;
                let enobufs_pct = self.tx_enobufs as f64 / self.tx_send_calls as f64 * 100.0;
                self.tx_fed_samples.sort_unstable();
                let n = self.tx_fed_samples.len();
                if n > 0 {
                    eprintln!(
                        "TX stats: calls={} avg_fed={:.1} avg_sent={:.1} empty={:.1}% enobufs={:.1}% fed[n={} min={} med={} max={}]",
                        self.tx_send_calls,
                        self.tx_total_fed as f64 / self.tx_send_calls as f64,
                        self.tx_total_sent as f64 / self.tx_send_calls as f64,
                        empty_pct, enobufs_pct,
                        n, self.tx_fed_samples[0], self.tx_fed_samples[n / 2], self.tx_fed_samples[n - 1],
                    );
                } else {
                    eprintln!(
                        "TX stats: calls={} avg_fed={:.1} avg_sent={:.1} empty={:.1}% enobufs={:.1}% fed[n=0]",
                        self.tx_send_calls,
                        self.tx_total_fed as f64 / self.tx_send_calls as f64,
                        self.tx_total_sent as f64 / self.tx_send_calls as f64,
                        empty_pct, enobufs_pct,
                    );
                }
                self.tx_fed_samples.clear();
            }

            // Socket fully blocked — wait for EPOLLOUT.
            if sent == 0 {
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
            // If we still have pending buffers in the producer, we assume we drained the whole socket
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

    #[cfg(target_os = "macos")]
    fn write_retry_delay_us(&self) -> u64 {
        50
    }

    fn queue_avail(&self) -> (u16, u16) {
        (self.tx_consumer.queue_avail(), self.rx_producer.queue_avail())
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
        let mut got_enobufs = false;

        let sent = self.tx_consumer.consume(|batch| match MACOS_MODE {
            MacosSendRecvMode::Plain => {
                for i in 0..batch.len() {
                    let slices = batch.io_slices(i);
                    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
                    hdr.msg_iov = AliasedIoSlice::as_iovec_ptr(slices) as *mut libc::iovec;
                    hdr.msg_iovlen = slices.len() as _;
                    let ret = unsafe { libc::sendmsg(fd, &hdr, libc::MSG_DONTWAIT) };
                    if ret < 0 {
                        let err = nix::errno::Errno::last();
                        match err {
                            nix::errno::Errno::ENOBUFS => got_enobufs = true,
                            nix::errno::Errno::EAGAIN => {}
                            _ => log::error!("sendmsg failed: {err:?}"),
                        }
                        return;
                    }
                    batch.finish(i);
                    for _ in 0..FINISH_SPIN_ITERS {
                        std::hint::spin_loop();
                    }
                }
            }
            MacosSendRecvMode::Batched { max_batch } => {
                let mut i = 0;
                while i < batch.len() {
                    let chunk = max_batch.min(batch.len() - i);
                    let headers = batch.transformed(i..i + chunk);
                    let ptr = headers.as_ptr() as *const super::socket_x::msghdr_x;

                    let ret = unsafe {
                        super::socket_x::sendmsg_x(fd, ptr, chunk as libc::c_uint, libc::MSG_DONTWAIT)
                    };

                    if ret < 0 {
                        let err = nix::errno::Errno::last();
                        match err {
                            nix::errno::Errno::ENOBUFS => got_enobufs = true,
                            nix::errno::Errno::EAGAIN => {}
                            _ => log::error!("sendmsg_x failed: {err:?}"),
                        }
                        return;
                    }

                    let sent = ret as usize;
                    batch.finish_many(i..i + sent);
                    for _ in 0..FINISH_SPIN_ITERS {
                        std::hint::spin_loop();
                    }
                    i += sent;
                    if sent < chunk {
                        return;
                    }
                }
            }
            MacosSendRecvMode::Copied => {
                let mut buf = [0u8; 65536];
                for i in 0..batch.len() {
                    let slices = batch.io_slices(i);
                    let mut off = 0;
                    for s in slices {
                        off += s.read(&mut buf[off..]);
                    }
                    let ret = unsafe {
                        libc::send(fd, buf.as_ptr() as *const libc::c_void, off, libc::MSG_DONTWAIT)
                    };
                    if ret < 0 {
                        let err = nix::errno::Errno::last();
                        match err {
                            nix::errno::Errno::ENOBUFS => got_enobufs = true,
                            nix::errno::Errno::EAGAIN => {}
                            _ => log::error!("send failed: {err:?}"),
                        }
                        return;
                    }
                    batch.finish(i);
                }
            }
        });

        if sent == 0 && got_enobufs {
            return Err(WriteError::NothingWritten);
        }

        Ok(sent)
    }

    fn recv_macos(&mut self) -> usize {
        let fd = self.fd.as_raw_fd();

        self.rx_producer.produce(|batch| match MACOS_MODE {
            MacosSendRecvMode::Plain => {
                for i in 0..batch.len() {
                    let iovecs = batch.io_slices_mut(i);
                    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
                    hdr.msg_iov = AliasedIoSliceMut::as_iovec_ptr(iovecs) as *mut libc::iovec;
                    hdr.msg_iovlen = iovecs.len() as _;
                    let ret = unsafe { libc::recvmsg(fd, &mut hdr, libc::MSG_DONTWAIT) };
                    match ret {
                        n if n > 0 => {
                            batch.complete(i, n as usize);
                        }
                        0 => {
                            log::warn!("recvmsg returned 0 (unexpected)");
                            return;
                        }
                        _ => {
                            let err = nix::errno::Errno::last();
                            match err {
                                nix::errno::Errno::EAGAIN | nix::errno::Errno::ENOBUFS => {}
                                _ => log::error!("recvmsg failed: {err}"),
                            }
                            return;
                        }
                    }
                }
            }
            MacosSendRecvMode::Batched { max_batch } => {
                let mut i = 0;
                while i < batch.len() {
                    let chunk = max_batch.min(batch.len() - i);
                    let ret = {
                        let headers = batch.transformed_mut(i..i + chunk);
                        let ptr = headers.as_mut_ptr() as *mut super::socket_x::msghdr_x;
                        unsafe {
                            super::socket_x::recvmsg_x(fd, ptr, chunk as libc::c_uint, libc::MSG_DONTWAIT)
                        }
                    };

                    match ret {
                        n if n > 0 => {
                            batch.complete_received_many(i..i + n as usize);
                            i += n as usize;
                            if (n as usize) < chunk {
                                return;
                            }
                        }
                        0 => {
                            log::warn!("recvmsg_x returned 0 (unexpected)");
                            return;
                        }
                        _ => {
                            let err = nix::errno::Errno::last();
                            match err {
                                nix::errno::Errno::EAGAIN | nix::errno::Errno::ENOBUFS => {}
                                _ => log::error!("recvmsg_x failed: {err}"),
                            }
                            return;
                        }
                    }
                }
            }
            MacosSendRecvMode::Copied => {
                let mut buf = [0u8; 65536];
                for i in 0..batch.len() {
                    let ret = unsafe {
                        libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT)
                    };
                    match ret {
                        n if n > 0 => {
                            let iovecs = batch.io_slices_mut(i);
                            AliasedIoSliceMut::scatter_write(iovecs.iter().copied(), &buf[..n as usize]);
                            batch.complete(i, n as usize);
                        }
                        0 => {
                            log::warn!("recv returned 0 (unexpected)");
                            return;
                        }
                        _ => {
                            let err = nix::errno::Errno::last();
                            match err {
                                nix::errno::Errno::EAGAIN | nix::errno::Errno::ENOBUFS => {}
                                _ => log::error!("recv failed: {err}"),
                            }
                            return;
                        }
                    }
                }
            }
        })
    }
}
