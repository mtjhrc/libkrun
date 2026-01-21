use libc::{
    c_char, c_int, c_void, ifreq, size_t, IFF_NO_PI, IFF_TAP, IFF_VNET_HDR, TUN_F_CSUM,
    TUN_F_TSO4, TUN_F_TSO6, TUN_F_UFO,
};
use nix::fcntl::{fcntl, open, FcntlArg, OFlag};
use nix::sys::stat::Mode;
use nix::sys::uio::writev;
use nix::{ioctl_write_int, ioctl_write_ptr};
use smallvec::SmallVec;
use std::io::IoSlice;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::{io, mem, ptr};
use virtio_bindings::virtio_net::{
    VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO,
};
use vm_memory::{GuestMemoryMmap, VolatileSlice};

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use crate::virtio::file_traits::FileReadWriteVolatile;
use crate::virtio::queue::Queue;
use crate::virtio::rx_queue_producer::RxQueueProducer;
use crate::virtio::tx_queue_consumer::TxQueueConsumer;
use crate::virtio::InterruptTransport;

ioctl_write_ptr!(tunsetiff, b'T', 202, c_int);
ioctl_write_int!(tunsetoffload, b'T', 208);
ioctl_write_ptr!(tunsetvnethdrsz, b'T', 216, c_int);

pub struct Tap {
    fd: OwnedFd,
    include_vnet_header: bool,
    tx_consumer: TxQueueConsumer,
    rx_provider: RxQueueProducer,
}

impl Tap {
    /// Create an endpoint using the file descriptor of a tap device
    pub fn new(
        tap_name: String,
        vnet_features: u64,
        include_vnet_header: bool,
        tx_queue: Queue,
        rx_queue: Queue,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
    ) -> Result<Self, ConnectError> {
        let fd = match open("/dev/net/tun", OFlag::O_RDWR, Mode::empty()) {
            Ok(fd) => fd,
            Err(err) => return Err(ConnectError::OpenNetTun(err)),
        };

        let mut req: ifreq = unsafe { mem::zeroed() };

        unsafe {
            ptr::copy_nonoverlapping(
                tap_name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                tap_name.len(),
            );
        }

        unsafe {
            req.ifr_ifru.ifru_flags = IFF_TAP as i16 | IFF_NO_PI as i16;
            if include_vnet_header {
                req.ifr_ifru.ifru_flags |= IFF_VNET_HDR as i16;
            }
        }

        let mut offload_flags: u64 = 0;
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_CSUM)) != 0 {
            offload_flags |= TUN_F_CSUM as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO4)) != 0 {
            offload_flags |= TUN_F_TSO4 as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_TSO6)) != 0 {
            offload_flags |= TUN_F_TSO6 as u64;
        }
        if (vnet_features & (1 << VIRTIO_NET_F_GUEST_UFO)) != 0 {
            offload_flags |= TUN_F_UFO as u64;
        }

        unsafe {
            if let Err(err) = tunsetiff(fd.as_raw_fd(), &mut req as *mut _ as *mut _) {
                return Err(ConnectError::TunSetIff(io::Error::from(err)));
            }

            // TODO(slp): replace hardcoded vnet size with cons
            if let Err(err) = tunsetvnethdrsz(fd.as_raw_fd(), &12) {
                return Err(ConnectError::TunSetVnetHdrSz(io::Error::from(err)));
            }

            if let Err(err) = tunsetoffload(fd.as_raw_fd(), offload_flags) {
                return Err(ConnectError::TunSetOffload(io::Error::from(err)));
            }
        }

        match fcntl(&fd, FcntlArg::F_GETFL) {
            Ok(flags) => {
                if let Err(e) = fcntl(
                    &fd,
                    FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
                ) {
                    warn!("error switching to non-blocking: id={fd:?}, err={e}");
                }
            }
            Err(e) => error!("couldn't obtain fd flags id={fd:?}, err={e}"),
        };

        let tx_consumer = TxQueueConsumer::new(tx_queue, mem.clone(), interrupt.clone());
        let rx_provider = RxQueueProducer::new(rx_queue, mem, interrupt);

        Ok(Self {
            fd,
            include_vnet_header,
            tx_consumer,
            rx_provider,
        })
    }
}

const MAX_TX_BATCH: usize = 64;
const MAX_RX_BATCH: usize = 1; // Tap only supports one frame at a time

impl NetBackend for Tap {
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
            // Return byte count after skip
            slices_mut.iter().map(|s| s.len()).sum()
        });

        if !self.tx_consumer.has_pending() {
            return Ok(());
        }

        let fd = self.fd.as_fd();

        // Send each frame with writev (tap doesn't support batching)
        let _ = self.tx_consumer.consume(|frames| {
            let mut total_bytes = 0usize;

            for frame in frames {
                let mut slices: SmallVec<[IoSlice<'_>; 4]> = frame.iter().cloned().collect();
                let slices_ref: &mut [IoSlice] = &mut slices;

                if slices_ref.is_empty() {
                    continue;
                }

                match writev(fd, slices_ref) {
                    Ok(n) => total_bytes += n,
                    Err(nix::errno::Errno::EAGAIN) => break,
                    Err(nix::errno::Errno::EPIPE) => {
                        return Err(WriteError::ProcessNotRunning);
                    }
                    Err(e) => return Err(WriteError::Internal(e)),
                }
            }
            Ok(total_bytes)
        })?;

        Ok(())
    }

    fn recv(&mut self) -> Result<(), ReadError> {
        // Feed buffers from queue
        self.rx_provider.feed(MAX_RX_BATCH);

        if self.rx_provider.pending_count() == 0 {
            return Ok(());
        }

        let fd = self.fd.as_raw_fd();

        self.rx_provider.produce(|buffers| {
            let mut byte_counts: SmallVec<[usize; 32]> = SmallVec::new();

            for buf in buffers.iter_mut() {
                // Convert IoSliceMut to iovec for readv
                let iovecs: SmallVec<[libc::iovec; 4]> = buf
                    .iter()
                    .map(|s| libc::iovec {
                        iov_base: s.as_ptr() as *mut c_void,
                        iov_len: s.len(),
                    })
                    .collect();

                if iovecs.is_empty() {
                    byte_counts.push(0);
                    continue;
                }

                let ret = unsafe {
                    libc::readv(fd, iovecs.as_ptr(), iovecs.len() as c_int)
                };

                if ret > 0 {
                    byte_counts.push(ret as usize);
                } else {
                    byte_counts.push(0);
                    break; // EAGAIN or error, stop receiving
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

impl FileReadWriteVolatile for Tap {
    fn read_volatile(&mut self, slice: VolatileSlice) -> io::Result<usize> {
        // SAFETY: Only bytes inside the slice are accessed and the kernel handles
        // arbitrary memory for I/O.
        let ret = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                slice.ptr_guard_mut().as_ptr() as *mut c_void,
                slice.len(),
            )
        };
        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn read_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> io::Result<usize> {
        let iovecs: Vec<libc::iovec> = bufs
            .iter()
            .map(|s| libc::iovec {
                iov_base: s.ptr_guard_mut().as_ptr() as *mut c_void,
                iov_len: s.len() as size_t,
            })
            .collect();

        if iovecs.is_empty() {
            return Ok(0);
        }

        // SAFETY: Only bytes inside the buffers are accessed and the kernel handles
        // arbitrary memory for I/O.
        let ret = unsafe {
            libc::readv(self.fd.as_raw_fd(), iovecs.as_ptr(), iovecs.len() as c_int)
        };
        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn write_volatile(&mut self, slice: VolatileSlice) -> io::Result<usize> {
        // SAFETY: Only bytes inside the slice are accessed and the kernel handles
        // arbitrary memory for I/O.
        let ret = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                slice.ptr_guard().as_ptr() as *const c_void,
                slice.len(),
            )
        };
        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn write_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> io::Result<usize> {
        let iovecs: Vec<libc::iovec> = bufs
            .iter()
            .map(|s| libc::iovec {
                iov_base: s.ptr_guard_mut().as_ptr() as *mut c_void,
                iov_len: s.len() as size_t,
            })
            .collect();

        if iovecs.is_empty() {
            return Ok(0);
        }

        // SAFETY: Only bytes inside the buffers are accessed and the kernel handles
        // arbitrary memory for I/O.
        let ret = unsafe {
            libc::writev(self.fd.as_raw_fd(), iovecs.as_ptr(), iovecs.len() as c_int)
        };
        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}
