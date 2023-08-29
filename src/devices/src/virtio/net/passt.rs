use nix::sys::socket::{
    connect, recv, send, socket, AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr,
};
use std::num::NonZeroUsize;
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

#[derive(Debug)]
pub enum WriteError {
    /// Nothing was written, you can drop the frame or try to resend it later
    NothingWritten,
    /// Part of the buffer was written, the write has to be finished using try_finish_write
    PartialWrite,
    /// Another internal error occurred
    Internal(nix::Error),
}

pub type Result<T> = result::Result<T, Error>;

pub struct Passt {
    passt_sock: RawFd,
    // 0 when a frame length has not been read
    expecting_frame_length: u32,
    last_partial_write_length: Option<NonZeroUsize>,
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
            last_partial_write_length: None,
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
    ///
    /// If this function returns WriteError::PartialWrite, you have to finish the write using
    /// try_finish_write.
    pub fn write_frame(
        &mut self,
        hdr_len: usize,
        buf: &mut [u8],
    ) -> result::Result<(), WriteError> {
        if self.last_partial_write_length.is_some() {
            panic!("Cannot write a frame to passt, while a partial write is not resolved.");
        }
        assert!(
            hdr_len >= PASST_HEADER_LEN,
            "Not enough space to write passt header"
        );
        assert!(buf.len() > hdr_len);
        let frame_length = buf.len() - hdr_len;

        buf[hdr_len - PASST_HEADER_LEN..hdr_len]
            .copy_from_slice(&(frame_length as u32).to_be_bytes());

        self.send_loop(&buf[hdr_len - PASST_HEADER_LEN..])?;
        Ok(())
    }

    pub fn has_unfinished_write(&self) -> bool {
        self.last_partial_write_length.is_some()
    }

    /// Try to finish a partial write
    ///
    /// If not partial write is required will do nothing.
    ///
    /// * `hdr_len` - must be the same value as passed to write_frame, that caused the partial write
    /// * `buf` - must be same buffer that was given to write_frame, that caused the partial write
    pub fn try_finish_write(
        &mut self,
        hdr_len: usize,
        buf: &[u8],
    ) -> result::Result<(), WriteError> {
        log::trace!("Requested to finish partial write");
        if let Some(written_bytes) = self.last_partial_write_length {
            self.send_loop(&buf[hdr_len - PASST_HEADER_LEN + written_bytes.get()..])?;
            log::debug!(
                "Finished partial write ({}bytes written before)",
                written_bytes.get()
            )
        }

        Ok(())
    }

    fn send_loop(&mut self, buf: &[u8]) -> result::Result<(), WriteError> {
        let mut bytes_send = 0;

        while bytes_send < buf.len() {
            match send(
                self.passt_sock,
                buf,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            ) {
                Ok(size) => bytes_send += size,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    if bytes_send == 0 {
                        return Err(WriteError::NothingWritten);
                    } else {
                        log::trace!(
                            "Wrote {} bytes, but socket blocked, will need try_finish_write() to finish",
                            bytes_send
                        );
                        self.last_partial_write_length = Some(bytes_send.try_into().unwrap());
                        return Err(WriteError::PartialWrite);
                    }
                }
                Err(e) => return Err(WriteError::Internal(e)),
            }
        }
        self.last_partial_write_length = None;
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
