use libc::{fcntl, fd_set, F_GETFL, F_SETFL, O_NONBLOCK, STDIN_FILENO, STDOUT_FILENO};
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::select::{select, FdSet, Fds};
use nix::sys::stat::Mode;
use nix::unistd::dup;
use std::{io, thread};
use std::cell::Cell;
use std::io::{stderr, stdout, Error, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;
use nix::time::{clock_gettime, ClockId};
use vm_memory::bitmap::{Bitmap, BitmapSlice};
use vm_memory::GuestMemoryError::IOError;
use vm_memory::{Bytes, ReadVolatile, VolatileMemory, VolatileMemoryError, VolatileSlice, WriteVolatile};

pub trait PortInput {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_readable(&self);
}

pub trait PortOutput {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_writable(&self);
}

pub struct PortInputFd(OwnedFd);

impl AsRawFd for PortInputFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl PortInput for PortInputFd {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> io::Result<usize> {
        // This source code is copied from vm-memory, except it fixes an issue, where
        // the original code would does not handle handle EWOULDBLOCK

        let fd = self.as_raw_fd();
        let guard = buf.ptr_guard_mut();

        let dst = guard.as_ptr().cast::<libc::c_void>();

        // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `dst` is
        // valid for writes of length `buf.len() by the invariants upheld by the constructor
        // of `VolatileSlice`.
        let bytes_read = unsafe { libc::read(fd, dst, buf.len()) };

        if bytes_read < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::WouldBlock {
                // We don't know if a partial read might have happened, so mark everything as dirty
                buf.bitmap().mark_dirty(0, buf.len());
            }

            Err(err)
        } else {
            let bytes_read = bytes_read.try_into().unwrap();
            buf.bitmap().mark_dirty(0, bytes_read);
            Ok(bytes_read)
        }
    }

    fn wait_until_readable(&self) {
        let mut poll_fds = [PollFd::new(self.as_raw_fd(), PollFlags::POLLIN)];
        poll(&mut poll_fds, -1).expect("Failed to poll");
    }
}

impl PortInputFd {
    pub fn stdin() -> Result<Self, nix::Error> {
        let fd = dup_raw_fd_into_owned(STDIN_FILENO)?;
        make_non_blocking(&fd)?;
        Ok(PortInputFd(fd))
    }
}

pub struct PortOutputFd(OwnedFd);

impl AsRawFd for PortOutputFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl PortOutput for PortOutputFd {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        self.0.write_volatile(buf).map_err(|e| match e {
            VolatileMemoryError::IOError(e) => e,
            e => {
                log::error!("Unsuported error from write_volatile: {e:?}");
                io::Error::new(ErrorKind::Other, e)
            }
        })
    }

    fn wait_until_writable(&self) {
        let mut poll_fds = [PollFd::new(self.as_raw_fd(), PollFlags::POLLOUT)];
        poll(&mut poll_fds, -1).expect("Failed to poll");
    }
}

impl PortOutputFd {
    pub fn stdout() -> Result<Self, nix::Error> {
        let fd = dup_raw_fd_into_owned(STDOUT_FILENO)?;
        make_non_blocking(&fd)?;
        Ok(PortOutputFd(fd))
    }
}

fn dup_raw_fd_into_owned(raw_fd: RawFd) -> Result<OwnedFd, nix::Error> {
    let fd = dup(raw_fd)?;
    // SAFETY: the fd is valid because dup succeeded
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn make_non_blocking(as_rw_fd: &impl AsRawFd) -> Result<(), nix::Error> {
    let fd = as_rw_fd.as_raw_fd();
    unsafe {
        let flags = fcntl(fd, F_GETFL, 0);
        if flags < 0 {
            return Err(Errno::last());
        }

        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(Errno::last());
        }
    }
    Ok(())
}

// Utility to relay log from the VM (the kernel boot log and messages from init)
// to the rust log
#[derive(Default)]
pub struct PortOutputLog {
    buf: Vec<u8>,
}

impl PortOutputLog {
    const FORCE_FLUSH_TRESHOLD: usize = 512;

    pub fn new() -> Self {
        Self::default()
    }

    fn force_flush(&mut self) {
        log::debug!(
            "[guest](no newline): {}",
            String::from_utf8_lossy(&self.buf)
        );
        self.buf.clear();
    }
}

impl PortOutput for PortOutputLog {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, Error> {
        self.buf
            .write_volatile(buf)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        let mut start = 0;
        for (i, ch) in self.buf.iter().cloned().enumerate() {
            if ch == b'\n' {
                log::error!("[guest]: {}", String::from_utf8_lossy(&self.buf[start..i]));
                start = i + 1;
            }
        }
        self.buf.drain(0..start);
        // We don't want to grow our inner buffer indefinetly!
        if self.buf.len() > PortOutputLog::FORCE_FLUSH_TRESHOLD {
            self.force_flush()
        }
        Ok(buf.len())
    }

    fn wait_until_writable(&self) {
        return;
    }
}


pub struct PortInputSigInt {
    ready: Cell<bool>,
}

impl PortInputSigInt {
    pub fn new() -> Self {
        PortInputSigInt {
            ready: Cell::new(false),
        }
    }
}

impl PortInput for PortInputSigInt {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, Error> {
        if self.ready.get() {
            buf.copy_from(&[3u8]); //ASCII 'ETX', -> generates SIGINIT
            Ok(1)
        }else {
            Err(io::Error::from(ErrorKind::WouldBlock))
        }
    }

    fn wait_until_readable(&self) {
        thread::sleep(Duration::from_secs(3));
        self.ready.replace(true);
    }
}
