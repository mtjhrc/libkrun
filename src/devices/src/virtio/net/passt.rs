use std::io;
use std::io::{BufReader, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use vm_memory::VolatileMemory;

/// Each frame from passt is prepended by a 4 byte "header".
/// It is interpreted as a big-endian u32 integer and is the length of the following ethernet frame.
const PASST_HEADER_LEN: usize = 4;

pub struct Passt {
    socket_writer: UnixStream,
    socket_reader: BufReader<UnixStream>,
}

#[derive(Debug)]
pub enum Error {
    /// Failed to connect to passt socket
    FailedToConnect(io::Error),
    /// The requested operation would block, try again later
    WouldBlock,
    /// Any other IO error occurred while communicating with passt
    UnspecifiedIO(io::Error),
}

impl Error {
    /// Report a failed IO read or write operation
    fn from_failed_read_write(err: io::Error) -> Error {
        match err.kind() {
            io::ErrorKind::WouldBlock => Error::WouldBlock,
            _ => Error::UnspecifiedIO(err),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// TODO: add the ability to start passt

impl Passt {
    /// Connect to a running passt instance, given a socket path
    pub fn connect_to_socket(socket_path: impl AsRef<Path>) -> Result<Self> {
        let passt_sock = UnixStream::connect(socket_path)
            .map_err(Error::FailedToConnect)?;

        passt_sock.set_nonblocking(true).map_err(|e| {
            log::error!("Failed make passt socket non-blocking: {e:?}");
            Error::FailedToConnect(e)
        })?;

        let socket_reader = {
            let cloned_sock = passt_sock.try_clone().map_err(|e| {
                log::error!("Failed to clone passt socket: {e:?}");
                Error::FailedToConnect(e)
            })?;
            BufReader::new(cloned_sock)
        };

        Ok(Self {
            socket_writer: passt_sock,
            socket_reader,
        })
    }

    /// Try to read a frame from passt. If no bytes are available reports PasstError::WouldBlock
    pub fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize> {
        read_frame_impl(&mut self.socket_reader, buf)
    }

    /// Try to write a frame to passt.
    /// (Will mutate and override parts of buf, with a passt header!)
    ///
    /// * `hdr_len` - specifies the size of any existing headers encapsulating the ethernet
    ///                     frame, must >= PASST_HEADER_LEN
    /// * `buf` - the buffer to write to passt, `buf[..hdr_len]` may be overwritten
    pub fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<()> {
        write_frame_impl(&mut self.socket_writer, hdr_len, buf)
    }

    pub fn raw_socket_fd(&self) -> RawFd{
        self.socket_writer.as_raw_fd()
    }
}

// TODO: report error if the buffer is too small instead of panicking
fn read_frame_impl(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let frame_length: usize = {
        let mut frame_length_buf = [0u8; PASST_HEADER_LEN];
        reader
            .read_exact(&mut frame_length_buf)
            .map_err(Error::from_failed_read_write)?;
        u32::from_be_bytes(frame_length_buf) as usize
    };

    reader
        .read_exact(&mut buf[..frame_length])
        // This read shouldn't have failed, we were basically promised by passt, that frame_length
        // bytes of data would be available, so no WouldBlock should occur here
        .map_err(|e| {
            log::error!("Passt promised {frame_length} bytes of data, but read failed.");
            Error::UnspecifiedIO(e)
        })?;

    log::trace!("Rx eth frame from passt: {:x?}", &buf[..frame_length]);
    Ok(frame_length)
}

fn write_frame_impl(writer: &mut impl Write, hdr_len: usize, buf: &mut [u8]) -> Result<()> {
    assert!(hdr_len >= PASST_HEADER_LEN, "Not enough space to write passt header");
    assert!(buf.len() > hdr_len);
    let frame_length = buf.len() - hdr_len;

    buf[hdr_len - PASST_HEADER_LEN..hdr_len].copy_from_slice(&(frame_length as u32).to_be_bytes());
    // TODO: investigate handling EAGAIN / EWOULDBLOCK here
    writer.write_all(&buf[hdr_len - PASST_HEADER_LEN..])
        .map_err(Error::from_failed_read_write)?;
    log::trace!("Tx eth frame to passt: {:x?}", &buf[hdr_len..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use super::*;

    #[test]
    fn test_successful_small_write() -> Result<()> {
        let header = [0xffu8; 10];
        let body = b"Hello world!";
        // concat_bytes! is not stable yet...
        let mut msg: Vec<u8> = [&header[..], &body[..]].concat();

        let mut writer: Vec<u8> = Vec::new();
        write_frame_impl(&mut writer, header.len(), &mut msg[..])?;
        assert_eq!(&writer[..], b"\x00\x00\x00\x0cHello world!");
        Ok(())
    }

    #[test]
    fn test_successful_small_read() -> Result<()> {
        let msg =  b"\x00\x00\x00\x0cHello world!";
        let mut reader = VecDeque::from_iter(msg.iter().copied());

        let mut buf = [0; 12];
        read_frame_impl(&mut reader, &mut buf)?;
        assert_eq!(&buf[..], b"Hello world!");
        Ok(())
    }
}
