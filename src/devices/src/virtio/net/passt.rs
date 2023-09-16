use std::num::NonZeroUsize;
use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

#[cfg(not(test))]
use nix::sys::socket::recv;
use nix::sys::socket::{
    connect, send, setsockopt, socket, sockopt, AddressFamily, MsgFlags, SockFlag, SockType,
    UnixAddr,
};
use vm_memory::VolatileMemory;

use crate::virtio::MAX_BUFFER_SIZE;

/// Each frame from passt is prepended by a 4 byte "header".
/// It is interpreted as a big-endian u32 integer and is the length of the following ethernet frame.
const PASST_HEADER_LEN: usize = 4;

#[derive(Debug)]
pub enum ConnectError {
    /// Failed to connect to passt socket
    FailedToConnect(nix::Error),
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

#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// Nothing was written
    NotAvailibleYet,
    /// Another internal error occurred
    Internal(nix::Error),
}

trait RangeUtil<T> {
    fn contains_range(&self, r: &Range<T>) -> bool;
}

impl<T: PartialOrd> RangeUtil<T> for Range<T> {
    fn contains_range(&self, r: &Range<T>) -> bool {
        r.start >= self.start && r.end <= self.end
    }
}

pub struct Passt {
    passt_sock: RawFd,
    last_partial_write_length: Option<NonZeroUsize>,

    read_buf: [u8; 3 * MAX_BUFFER_SIZE],
    read_buf_return_range: Option<Range<usize>>, // range into current range
    read_current_range: Range<usize>,
}

//TODO: (re)move this
/*trait DefaultArray {
    fn default_array() -> Self;
}
impl<T: Default + Copy, const N:usize> DefaultArray for [T;N] {
    fn default_array() -> Self {
        [Default::default(); N]
    }
}*/

const VNET_HEADER_LEN: usize = 12;

fn default_array<T: Default + Copy, const N: usize>() -> [T; N] {
    [Default::default(); N]
}

impl Passt {
    /// Connect to a running passt instance, given a socket path
    pub fn connect_to_socket(socket_path: impl AsRef<Path>) -> Result<Self, ConnectError> {
        let sock = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .map_err(ConnectError::FailedToConnect)?;

        let addr = UnixAddr::new(socket_path.as_ref()).map_err(ConnectError::FailedToConnect)?;

        connect(sock, &addr).map_err(ConnectError::FailedToConnect)?;
        setsockopt(sock, sockopt::SndBuf, &(16 * 1024 * 1024)).unwrap();

        Ok(Self {
            passt_sock: sock,
            read_buf: default_array(),
            read_buf_return_range: None, // range into current range
            read_current_range: VNET_HEADER_LEN..VNET_HEADER_LEN,    // start of current range always points to the passt header
            last_partial_write_length: None,
        })
    }

    /// Try to read a frame from passt. If a frame is not available reports ReadError::WouldBlock
    pub fn read_frame(&mut self) -> Result<&mut [u8], ReadError> {
        log::trace!("read frame");
        match self.advance_read() {
            Ok(()) => (),
            Err(e) => {
                self.read_buf_return_range = None;
                log::trace!("advance_read: {e:?}");
                return Err(e);
            }
        }
        log::trace!("after advance");

        self.last_read_frame_mut().ok_or(ReadError::NotAvailibleYet)
    }

    pub fn last_read_frame_mut(&mut self) -> Option<&mut [u8]> {
        self.read_buf_return_range
            .clone()
            .map(|range| &mut self.read_buf[range])
    }

    /// Try to write a frame to passt.
    /// (Will mutate and override parts of buf, with a passt header!)
    ///
    /// * `hdr_len` - specifies the size of any existing headers encapsulating the ethernet frame,
    ///               (such as vnet header), that can be overwritten.
    ///               must be >= PASST_HEADER_LEN
    /// * `buf` - the buffer to write to passt, `buf[..hdr_len]` may be overwritten
    ///
    /// If this function returns WriteError::PartialWrite, you have to finish the write using
    /// try_finish_write.
    pub fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
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

        self.write_loop(&buf[hdr_len - PASST_HEADER_LEN..])?;
        Ok(())
    }

    pub fn has_unfinished_write(&self) -> bool {
        self.last_partial_write_length.is_some()
    }

    /// Try to finish a partial write
    ///
    /// If no partial write is required will do nothing and return Ok(())
    ///
    /// * `hdr_len` - must be the same value as passed to write_frame, that caused the partial write
    /// * `buf` - must be same buffer that was given to write_frame, that caused the partial write
    pub fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError> {
        //log::trace!("Requested to finish partial write");
        if let Some(written_bytes) = self.last_partial_write_length {
            self.write_loop(&buf[hdr_len - PASST_HEADER_LEN + written_bytes.get()..])?;
            log::debug!(
                "Finished partial write ({}bytes written before)",
                written_bytes.get()
            )
        }

        Ok(())
    }

    pub fn raw_socket_fd(&self) -> RawFd {
        self.passt_sock.as_raw_fd()
    }

    fn write_loop(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let mut bytes_send = 0;

        while bytes_send < buf.len() {
            match send(
                self.passt_sock,
                buf,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            ) {
                Ok(size) => {
                    bytes_send += size;
                    //log::trace!("passt send {}/{}", bytes_send, buf.len());
                }
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

    fn read_fill_buf(&mut self) -> Result<(), ReadError> {
        // first lets shift the current contents of the buffer to the left,
        // so we can read as much as possible
        self.read_buf
            .copy_within(self.read_current_range.clone(), VNET_HEADER_LEN);
        self.read_current_range = VNET_HEADER_LEN..VNET_HEADER_LEN+self.read_current_range.len();

        match recv(
            self.passt_sock,
            &mut self.read_buf[self.read_current_range.end..],
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
        ) {
            Ok(size) => {
                log::trace!("recv {}bytes (had {})", size, self.read_current_range.len());
                self.read_current_range.end += size;
                Ok(())
            }
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => Err(ReadError::NotAvailibleYet),
            Err(e) => Err(ReadError::Internal(e)),
        }
    }

    fn current_read_slice(&self) -> &[u8] {
        &self.read_buf[self.read_current_range.clone()]
    }

    fn get_len_header_at(&self, index: usize) -> Option<usize> {
        self
            .current_read_slice()
            .get(index..index + PASST_HEADER_LEN)
            .and_then(|buf| buf
                .try_into()
                .ok()
                .map(|array_of_4_bytes| u32::from_be_bytes(array_of_4_bytes) as usize))
    }

    fn try_return_frame_of_length(&mut self, frame_length: usize) -> bool {
        //TODO: rewrite this whole horrible function!

        //let new_range = VNET_HEADER_LEN+PASST_HEADER_LEN..VNET_HEADER_LEN+frame_length + PASST_HEADER_LEN;

        // if the frame is contained within the buffer
        if self.current_read_slice().len()-PASST_HEADER_LEN >= frame_length {
            /*let return_range = self.read_current_range.start - VNET_HEADER_LEN
                ..self.read_current_range.start + frame_length;
            */

            let return_range = self.read_current_range.start+PASST_HEADER_LEN-VNET_HEADER_LEN
                ..self.read_current_range.start + PASST_HEADER_LEN + frame_length;

            log::trace!(
                "current:{:?} frame_length:{:?} return range:{:?}",
                self.read_current_range,
                frame_length,
                return_range
            );
            self.read_buf_return_range = Some(return_range);
            self.read_current_range.start += PASST_HEADER_LEN + frame_length;
            true
        } else {
            log::trace!("cannot return frame of length: {frame_length}");
            false
        }
    }

    fn advance_read(&mut self) -> Result<(), ReadError> {
        let mut performed_read = false;
        if self.read_current_range.len() < PASST_HEADER_LEN {
            self.read_fill_buf()?;
            performed_read = true;
        }

        let frame_length = self
            .get_len_header_at(0)
            .ok_or(ReadError::NotAvailibleYet)?;

        assert_ne!(frame_length, 0);

        if self.try_return_frame_of_length(
            frame_length
        ) {
            Ok(())
        } else if !performed_read {
            // we had enough bytes buffered for the passt header, but not enough for the actual frame,
            // so let's try to read
            self.read_fill_buf()?;

            if self.try_return_frame_of_length(
                frame_length,
            ) {
                Ok(())
            } else {
                Err(ReadError::NotAvailibleYet)
            }
        } else {
            Err(ReadError::NotAvailibleYet)
        }
    }
}

#[cfg(test)]
fn recv(sockfd: RawFd, buf: &mut [u8], flags: MsgFlags) -> Result<usize, nix::Error> {
    unsafe { tests::recv_impl }.expect("You didn't set any mock implementation")(sockfd, buf, flags)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use super::*;

    pub static mut recv_impl: Option<
        fn(sockfd: RawFd, buf: &mut [u8], flags: MsgFlags) -> Result<usize, nix::Error>,
    > = None;

    //pub static
    //pub static mut TEST_MUTEX: Option<Mutex<()>> = None;

    macro_rules! mock_recv {
        (($fd:ident, $buf:ident, $flags:ident), $body:block) => {
            //fn mocked_recv() -> Result<usize, nix::Error>
            unsafe { recv_impl = Some(|$fd: RawFd, $buf: &mut [u8], $flags: MsgFlags| $body) };
        };
    }

    // based on implemetnation from:
    // https://www.reddit.com/r/rust/comments/zqwggh/how_to_concat_two_const_slices_in_a_const_way/
    // because std::concat_bytes! is nightly for now...
    macro_rules! concat_bytes {
        ($($s:expr),+) => {{
            const LEN: usize = $( $s.len() + )* 0;
            const ARR: [u8; LEN] = {
                let mut arr: [u8; LEN] = [0; LEN];
                let mut base: usize = 0;
                $({
                    let mut i = 0;
                    while i < $s.len() {
                        arr[base + i] = $s[i];
                        i += 1;
                    }
                    base += $s.len();
                })*
                if base != LEN { panic!("invalid length"); }
                arr
            };
            ARR
        }}
    }

    fn write_to_buf(dest: &mut [u8], src: impl AsRef<[u8]>) -> Result<usize, nix::Error>{
        let src = src.as_ref();

        dest[..src.len()].copy_from_slice(src);

        Ok(src.len())
    }

    #[test]
    fn recv_eagain_in_first_read() {
        let mut passt = Passt {
            passt_sock: 0,
            read_buf: default_array(),
            read_buf_return_range: None,
            read_current_range: 0..0,
            last_partial_write_length: None,
        };

        mock_recv!((fd, _buf, _flags), {
            assert_eq!(fd, 0);
            Err(nix::Error::EAGAIN)
        });

        assert_eq!(passt.read_frame(), Err(ReadError::NotAvailibleYet));
        assert_eq!(passt.read_buf_return_range, None);
        assert_eq!(passt.read_current_range, 0..0);
    }


    #[test]
    fn recv_eagain_after_first_read() {
        let mut passt = Passt {
            passt_sock: 0,
            read_buf: default_array(),
            read_buf_return_range: Some(4..14),
            read_current_range: 14..14,
            last_partial_write_length: None,
        };

        mock_recv!((fd, _buf, _flags), {
            assert_eq!(fd, 0);
            Err(nix::Error::EAGAIN)
        });

        assert_eq!(passt.read_frame(), Err(ReadError::NotAvailibleYet));
        assert_eq!(passt.read_buf_return_range, None);
        assert_eq!(passt.read_current_range, 0..0);
    }

    #[test]
    fn read_a_frame() {
        let mut passt = Passt {
            passt_sock: 0,
            read_buf: default_array(),
            read_buf_return_range: None,
            read_current_range: 0..0,
            last_partial_write_length: None,
        };

        const RESULT_LENGTH: usize = 10;
        const RESULT_ARRAY: [u8; RESULT_LENGTH] = [0xffu8; RESULT_LENGTH];
        mock_recv!((_fd, buf, _flags), {
            buf[..RESULT_LENGTH + PASST_HEADER_LEN].copy_from_slice(
                &concat_bytes!((RESULT_LENGTH as u32).to_be_bytes(), RESULT_ARRAY),
            );
            Ok(RESULT_LENGTH+PASST_HEADER_LEN)
        });

        assert_eq!(passt.read_frame(), Ok(&mut RESULT_ARRAY[..]));
        assert_eq!(passt.read_buf_return_range, Some(4..14));
        assert_eq!(passt.read_current_range, 14..14);
    }

    #[test]
    fn read_a_frame_with_empty_buf_shifting_left() {
        let mut passt = Passt {
            passt_sock: 0,
            last_partial_write_length: None,
            read_buf: default_array(),
            read_buf_return_range: Some(4..14),
            read_current_range: 14..14,
        };

        const RESULT_LENGTH: usize = 10;
        const RESULT_ARRAY: [u8; RESULT_LENGTH] = [0xffu8; RESULT_LENGTH];
        mock_recv!((_fd, buf, _flags), {
            write_to_buf(buf, concat_bytes!((RESULT_LENGTH as u32).to_be_bytes(), RESULT_ARRAY))
        });

        assert_eq!(passt.read_frame(), Ok(&mut RESULT_ARRAY[..]));
        assert_eq!(passt.read_buf_return_range, Some(4..14));
        assert_eq!(passt.read_current_range, 14..14);
    }

    #[test]
    fn read_frame_split_at_two_reads() {
        const RESULT_LENGTH: usize = 10;
        const RESULT_ARRAY_PART1: [u8;5] = [0xff; 5];
        const RESULT_ARRAY_PART2: [u8;5] = [0xaa; 5];
        const RESULT_COMBINED: [u8; 10] = concat_bytes!(RESULT_ARRAY_PART1, RESULT_ARRAY_PART2);

        let mut passt = Passt {
            passt_sock: 0,
            last_partial_write_length: None,
            read_buf: default_array(),
            read_buf_return_range: None,
            read_current_range: 0..0,
        };

        mock_recv!((_fd, buf, _flags), {
            write_to_buf(buf, concat_bytes!((RESULT_LENGTH as u32).to_be_bytes(), RESULT_ARRAY_PART1))
        });

        assert_eq!(passt.read_frame(), Err(ReadError::NotAvailibleYet));
        assert_eq!(passt.read_buf_return_range, None);
        assert_eq!(passt.read_current_range, 0..PASST_HEADER_LEN+5);

        mock_recv!((_fd, buf, _flags), {
             write_to_buf(buf, RESULT_ARRAY_PART2)
        });

        assert_eq!(passt.read_frame(), Ok(&mut RESULT_COMBINED[..]));
        assert_eq!(passt.read_buf_return_range, Some(4..14));
        assert_eq!(passt.read_current_range, 14..14);
    }
}
