//! See https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-2920002
//! for port <-> virtio queue index mapping

use std::borrow::Cow;
use crate::legacy::ReadableFd;
use std::fs::File;
use std::io;
use std::io::ErrorKind::WouldBlock;
use std::io::Read;
use vm_memory::bitmap::BitmapSlice;
use vm_memory::volatile_memory::Error;
use vm_memory::{
    guest_memory, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryRegion,
    VolatileMemoryError, VolatileSlice,
};

#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum PortStatus {
    NotReady,
    Ready { opened: bool },
}

pub struct PortDescription {
    pub name: Cow<'static, str>,
    /// If the value is true, port represents a console in the guest
    pub console: bool,
    pub input: Option<Box<dyn ReadableFd + Send>>,
    pub output: Option<Box<dyn io::Write + Send>>,
}

pub(crate) struct Port {
    pub(crate) name: Cow<'static, str>,
    pub(crate) status: PortStatus,
    pub(crate) console: bool,
    /// Last process_rx didn't fully finish processing input.
    /// Since we use EDGE_TRIGGERED epoll, we won't be notified again and have to keep track of this.
    /// That could happen for 2 reasons:
    ///      1. We were notified by epoll before the port was opened by guest.
    ///         (we only start reading the input once the VM starts and opens the port)
    ///      2. The rx queue buffers got completely filled up before receiving before reading
    ///         the whole input.
    pub(crate) pending_rx: bool,
    /// We need to send EOF, but do it after checking and processing pending_rx.
    pub(crate) pending_eof: bool,
    // TODO: we probably also need pending output? But for that output needs to be non-blocking
    // It doesn't make sense for both of these to be None, so encode it better
    pub(crate) input: Option<Box<dyn ReadableFd + Send>>,
    pub(crate) output: Option<Box<dyn io::Write + Send>>,
}
/*
// Drop this impl once upstream vm-memory is fixed
impl ReadVolatile for Port {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        buf: &mut VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        let fd = self.input.as_ref().unwrap().as_raw_fd();

        let guard = buf.ptr_guard_mut();
        let dst = guard.as_ptr().cast::<libc::c_void>();

        // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `dst` is
        // valid for writes of length `buf.len() by the invariants upheld by the constructor
        // of `VolatileSlice`.
        let bytes_read = unsafe { libc::read(fd, dst, buf.len()) };

        if bytes_read < 0 {
            let error = io::Error::last_os_error();

            // If Error is WouldBlock/EAGAIN we don't need to mark anything as dirty, because we
            // haven't read anything otherwise mark everything as dirty, because we don't know
            // if a partial read might have happened
            if error.kind() != io::ErrorKind::WouldBlock {
                buf.bitmap().mark_dirty(0, buf.len());
            }

            Err(VolatileMemoryError::IOError(error))
        } else {
            let bytes_read = bytes_read.try_into().unwrap();
            buf.bitmap().mark_dirty(0, bytes_read);
            Ok(bytes_read)
        }
    }
}*/

impl Port {
    pub(crate) fn new(description: PortDescription) -> Self {
        Self {
            name: description.name,
            status: PortStatus::NotReady,
            pending_rx: false,
            pending_eof: false,
            console: description.console,
            output: description.output,
            input: description.input,
        }
    }

    pub(crate) fn read_until_would_block<M>(
        &mut self,
        mem: &M,
        addr: GuestAddress,
        count: usize,
    ) -> Result<usize, GuestMemoryError>
    where
        M: GuestMemory + ?Sized,
    {
        let mut buf = vec![0; count];
        let bytes_read = self.input.as_mut().unwrap().read(&mut buf[..]).map_err(GuestMemoryError::IOError)?;
        mem.write(&mut buf[..bytes_read], addr)
    }
    /*
        pub(crate) fn read_until_would_block<M>(&mut self, mem: &M, addr: GuestAddress, count: usize) -> Result<usize, GuestMemoryError>
        where
            M: GuestMemory + ?Sized,
        {
            const MAX_ACCESS_CHUNK: usize = 4096;
            let mut read_bytes = 0;
            // based on vm_memory's read_volatile, but handles WouldBlock error
            mem.try_access(count, addr, |offset, len, caddr, region| {
                // Check if something bad happened before doing unsafe things.
                assert!(offset <= count);

                let len = std::cmp::min(len, MAX_ACCESS_CHUNK);

                let mut vslice = region.get_slice(caddr, len)?;

                match self.read_volatile(&mut vslice) {
                    Ok(n) => {
                        read_bytes += n;
                        Ok(n)
                    }
                    Err(Error::IOError(io_error)) if io_error.kind() == WouldBlock => {
                        if read_bytes == 0 {
                            Err(guest_memory::Error::IOError(io_error))
                        } else {
                            Ok(0)
                        }
                    }
                    Err(e) => Err(e.into()),
                }
        }).map_err(|e| e.into())
    }
     */
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum QueueDirection {
    Rx,
    Tx,
}

#[must_use]
pub(crate) fn port_id_to_queue_idx(queue_direction: QueueDirection, port_id: usize) -> usize {
    match queue_direction {
        QueueDirection::Rx if port_id == 0 => 0,
        QueueDirection::Rx => 2 + 2 * port_id,
        QueueDirection::Tx if port_id == 0 => 1,
        QueueDirection::Tx => 2 + 2 * port_id + 1,
    }
}

#[must_use]
pub(crate) fn queue_idx_to_port_id(queue_index: usize) -> (QueueDirection, usize) {
    let port_id = match queue_index {
        0 | 1 => 0,
        2 | 3 => {
            panic!("Invalid argument: {queue_index} is not a valid receiveq nor transmitq index!")
        }
        _ => queue_index / 2 - 1,
    };

    let direction = if queue_index % 2 == 0 {
        QueueDirection::Rx
    } else {
        QueueDirection::Tx
    };

    (direction, port_id)
}

#[cfg(test)]
mod test {
    use crate::virtio::console::port::*;

    #[test]
    fn test_queue_idx_to_port_id_ok() {
        assert_eq!(queue_idx_to_port_id(0), (QueueDirection::Rx, 0));
        assert_eq!(queue_idx_to_port_id(1), (QueueDirection::Tx, 0));
        assert_eq!(queue_idx_to_port_id(4), (QueueDirection::Rx, 1));
        assert_eq!(queue_idx_to_port_id(5), (QueueDirection::Tx, 1));
        assert_eq!(queue_idx_to_port_id(6), (QueueDirection::Rx, 2));
        assert_eq!(queue_idx_to_port_id(7), (QueueDirection::Tx, 2));
    }

    #[test]
    #[should_panic]
    fn test_queue_idx_to_port_id_panic_rx_control() {
        let _ = queue_idx_to_port_id(2);
    }

    #[test]
    #[should_panic]
    fn test_queue_idx_to_port_id_panic_tx_control() {
        let _ = queue_idx_to_port_id(3);
    }
}
