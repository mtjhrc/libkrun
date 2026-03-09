//! Passt-backed mock unixgram backend for virtio-net tests (Linux only)

use crate::test_net::passt;
use crate::{krun_call, ShouldRun, TestSetup};
use krun_sys::COMPAT_NET_FEATURES;
use nix::libc;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::thread;

type KrunAddNetUnixgramFn = unsafe extern "C" fn(
    ctx_id: u32,
    c_path: *const std::ffi::c_char,
    fd: std::ffi::c_int,
    c_mac: *mut u8,
    features: u32,
    flags: u32,
) -> i32;

fn get_krun_add_net_unixgram() -> KrunAddNetUnixgramFn {
    let symbol = CString::new("krun_add_net_unixgram").unwrap();
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
    assert!(!ptr.is_null(), "krun_add_net_unixgram not found");
    unsafe { std::mem::transmute(ptr) }
}

fn socketpair_datagram() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn dup_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let duped = unsafe { libc::dup(fd.as_raw_fd()) };
    if duped < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(duped) })
    }
}

fn dup_raw_fd(fd: RawFd) -> io::Result<OwnedFd> {
    let duped = unsafe { libc::dup(fd) };
    if duped < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(duped) })
    }
}

fn write_all(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let written = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if written < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to passt relay",
            ));
        }
        buf = &buf[written as usize..];
    }
    Ok(())
}

fn read_exact(fd: RawFd, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let read = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if read < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "relay peer closed",
            ));
        }
        let (_, rest) = buf.split_at_mut(read as usize);
        buf = rest;
    }
    Ok(())
}

fn relay_unixgram_to_passt(unixgram_fd: OwnedFd, passt_fd: OwnedFd) -> io::Result<()> {
    let mut frame = [0u8; 65562];
    loop {
        let received = unsafe {
            libc::recv(
                unixgram_fd.as_raw_fd(),
                frame.as_mut_ptr() as *mut libc::c_void,
                frame.len(),
                0,
            )
        };
        if received < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if received == 0 {
            return Ok(());
        }

        let len = (received as u32).to_be_bytes();
        write_all(passt_fd.as_raw_fd(), &len)?;
        write_all(passt_fd.as_raw_fd(), &frame[..received as usize])?;
    }
}

fn relay_passt_to_unixgram(passt_fd: OwnedFd, unixgram_fd: OwnedFd) -> io::Result<()> {
    let mut len_buf = [0u8; 4];
    let mut frame = Vec::new();

    loop {
        read_exact(passt_fd.as_raw_fd(), &mut len_buf)?;
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        frame.resize(frame_len, 0);
        read_exact(passt_fd.as_raw_fd(), &mut frame)?;

        let sent = unsafe {
            libc::send(
                unixgram_fd.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
    }
}

fn start_relay(unixgram_fd: OwnedFd, passt_fd: RawFd) -> io::Result<()> {
    let unixgram_rx = dup_fd(&unixgram_fd)?;
    let unixgram_tx = dup_fd(&unixgram_fd)?;
    let passt_rx = dup_raw_fd(passt_fd)?;
    let passt_tx = dup_raw_fd(passt_fd)?;

    thread::spawn(move || {
        let _ = relay_unixgram_to_passt(unixgram_rx, passt_tx);
    });
    thread::spawn(move || {
        let _ = relay_passt_to_unixgram(passt_rx, unixgram_tx);
    });

    Ok(())
}

pub(crate) fn should_run() -> ShouldRun {
    passt::should_run()
}

pub(crate) fn setup_backend(ctx: u32, _test_setup: &TestSetup) -> anyhow::Result<()> {
    let passt_fd = unsafe { OwnedFd::from_raw_fd(passt::start_passt()?) };
    let (krun_fd, relay_fd) = socketpair_datagram()?;
    start_relay(relay_fd, passt_fd.as_raw_fd())?;

    let mut mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

    unsafe {
        krun_call!(get_krun_add_net_unixgram()(
            ctx,
            std::ptr::null(),
            krun_fd.into_raw_fd(),
            mac.as_mut_ptr(),
            COMPAT_NET_FEATURES,
            0,
        ))?;
    }
    Ok(())
}
