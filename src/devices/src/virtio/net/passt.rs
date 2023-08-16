use nix::sys::socket::{
    connect, recv, send, socket, AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr,
};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::result;
use vm_memory::VolatileMemory;

// TODO: add the ability to start passt
// TODO: handle/report passt disconnect properly

/// Each frame from passt is prepended by a 4 byte "header".
/// It is interpreted as a big-endian u32 integer and is the length of the following ethernet frame.
const PASST_HEADER_LEN: usize = 4;

#[derive(Debug)]
pub enum Error {
    /// Failed to connect to passt socket
    FailedToConnect(nix::Error),
    /// The requested operation would block, try again later
    WouldBlock,
    /// The requested operation would block, try again later
    Internal(nix::Error),
}

pub type Result<T> = result::Result<T, Error>;

pub struct Passt {
    passt_sock: RawFd,
    // 0 when a frame length has not been read
    expecting_frame_length: u32,
}

impl Passt {
    /// Connect to a running passt instance, given a socket path
    pub fn connect_to_socket(socket_path: impl AsRef<Path>) -> Result<Self> {
        let sock = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_NONBLOCK,
            None,
        )
        .map_err(Error::FailedToConnect)?;

        let addr = UnixAddr::new(socket_path.as_ref()).map_err(Error::FailedToConnect)?;

        connect(sock, &addr).map_err(Error::FailedToConnect)?;

        Ok(Self {
            passt_sock: sock,
            expecting_frame_length: 0,
        })
    }

    /// Try to read a frame from passt. If no bytes are available reports PasstError::WouldBlock
    pub fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.expecting_frame_length == 0 {
            self.expecting_frame_length = {
                let mut frame_length_buf = [0u8; PASST_HEADER_LEN];
                recv_loop(self.passt_sock, &mut frame_length_buf)?;
                u32::from_be_bytes(frame_length_buf)
            };
        }

        let frame_length = self.expecting_frame_length as usize;
        recv_loop(self.passt_sock, &mut buf[..frame_length])?;
        self.expecting_frame_length = 0;
        log::trace!("Read eth frame from passt: {} bytes", frame_length);
        Ok(frame_length)
    }

    /// Try to write a frame to passt.
    /// (Will mutate and override parts of buf, with a passt header!)
    ///
    /// * `hdr_len` - specifies the size of any existing headers encapsulating the ethernet
    ///                     frame, must >= PASST_HEADER_LEN
    /// * `buf` - the buffer to write to passt, `buf[..hdr_len]` may be overwritten
    pub fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<()> {
        assert!(
            hdr_len >= PASST_HEADER_LEN,
            "Not enough space to write passt header"
        );
        assert!(buf.len() > hdr_len);
        let frame_length = buf.len() - hdr_len;

        buf[hdr_len - PASST_HEADER_LEN..hdr_len]
            .copy_from_slice(&(frame_length as u32).to_be_bytes());

        send_loop(self.passt_sock, &buf[hdr_len - PASST_HEADER_LEN..])?;
        log::trace!("Write eth frame to passt: {} bytes", frame_length);
        Ok(())
    }

    pub fn raw_socket_fd(&self) -> RawFd {
        self.passt_sock.as_raw_fd()
    }
}

/// Try to read until filling the whole slice.
/// May return WouldBlock only if the first read fails
fn recv_loop(fd: RawFd, buf: &mut [u8]) -> Result<()> {
    let mut bytes_read = 0;

    match recv(fd, buf, MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL) {
        Ok(size) => bytes_read += size,
        #[allow(unreachable_patterns)] // EAGAIN/EWOULDBLOCK may be a different value...
        Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => return Err(Error::WouldBlock),
        Err(e) => return Err(Error::Internal(e)),
    }

    while bytes_read < buf.len() {
        match recv(
            fd,
            &mut buf[bytes_read..],
            MsgFlags::MSG_WAITALL | MsgFlags::MSG_NOSIGNAL,
        ) {
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                log::trace!("Unexpected EAGAIN/EWOULDBLOCK when MSG_WAITALL was specified");
                continue;
            }
            Err(e) => return Err(Error::Internal(e)),
            Ok(size) => {
                bytes_read += size;
                log::trace!("recv {}/{}", bytes_read, buf.len());
            }
        }
    }

    Ok(())
}

fn send_loop(fd: RawFd, buf: &[u8]) -> Result<()> {
    let mut bytes_send = 0;

    // TODO: possibly drop full frames, if the socket blocks
    while bytes_send < buf.len() {
        bytes_send += send(fd, buf, MsgFlags::MSG_WAITALL | MsgFlags::MSG_NOSIGNAL)
            .map_err(Error::Internal)?;
        log::trace!("send {}/{}", bytes_send, buf.len());
    }

    Ok(())
}
