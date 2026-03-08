//! Extension traits for slices and `Vec`s of [`AnyIoSlice`] types.
//!
//! Provides vectored I/O helpers (total length, advance, truncate, FFI pointer)
//! callable with method syntax on `&[T]` / `&mut [T]` and `Vec<T>`.

use libc::{c_void, iovec};
use smallvec::{Array, SmallVec};

use super::aliased_ioslice::AnyIoSlice;

/// Extension trait for slices of [`AnyIoSlice`] types.
///
/// Provides vectored I/O helpers (total length, advance, truncate, FFI pointer)
/// callable with method syntax on `&[T]` / `&mut [T]`.
pub trait SliceOfIoSlicesExt<T: AnyIoSlice> {
    /// Total length of all buffers in the slice.
    fn total_len(&self) -> usize;

    /// Returns a pointer to the base of the iovec array for FFI (e.g. writev/readv).
    ///
    /// # Safety
    /// The caller must ensure the slice remains valid while the pointer is in use.
    fn as_iovec_ptr(&self) -> *const iovec;

    /// Consumes `n` bytes from the front of the slice by shifting
    /// the base pointer and length of the descriptors in-place.
    fn advance(&mut self, n: usize) -> &mut [T];

    /// Truncates the slice descriptors to a total length of `n`.
    fn truncate(&mut self, n: usize) -> &mut [T];

    /// Scatter-write `data` across the iovec list, filling each buffer in order.
    /// Returns the total number of bytes written.
    fn write(&mut self, data: &[u8]) -> usize;
}

impl<T: AnyIoSlice> SliceOfIoSlicesExt<T> for [T] {
    fn total_len(&self) -> usize {
        self.iter().map(|s| s.len()).sum()
    }

    fn as_iovec_ptr(&self) -> *const iovec {
        self.as_ptr() as *const iovec
    }

    fn advance(&mut self, mut n: usize) -> &mut [T] {
        let mut skip = 0;
        for iov in self.iter_mut() {
            let len = iov.len();
            if n < len {
                // Safety: we have &mut self, so mutating the iovec is valid.
                let raw = unsafe { iov.as_iovec_mut() };
                raw.iov_base = unsafe { (raw.iov_base as *mut u8).add(n) as *mut c_void };
                raw.iov_len -= n;
                break;
            } else {
                n -= len;
                skip += 1;
            }
        }
        &mut self[skip..]
    }

    fn truncate(&mut self, mut n: usize) -> &mut [T] {
        let mut keep = 0;
        for iov in self.iter_mut() {
            let len = iov.len();
            if n <= len {
                // Safety: we have &mut self, so mutating the iovec is valid.
                unsafe { iov.as_iovec_mut() }.iov_len = n;
                keep += 1;
                break;
            } else {
                n -= len;
                keep += 1;
            }
        }
        &mut self[..keep]
    }

    fn write(&mut self, data: &[u8]) -> usize {
        let mut written = 0;
        for iov in self.iter_mut() {
            let remaining = data.len() - written;
            if remaining == 0 {
                break;
            }
            let take = remaining.min(iov.len());
            iov.write(&data[written..written + take]);
            written += take;
        }
        written
    }
}

/// Extension trait for `Vec<T: AnyIoSlice>`.
///
/// Wraps the slice-level [`SliceOfIoSlicesExt`] operations and also adjusts
/// the `Vec`'s length (draining consumed entries or truncating unused ones).
pub trait VecOfIoSlicesExt<T: AnyIoSlice> {
    /// Advance past `n` bytes, draining fully-consumed iovecs from the front.
    fn advance(&mut self, n: usize);

    /// Truncate to at most `n` total bytes, removing unused iovecs from the end.
    fn truncate_bytes(&mut self, n: usize);
}

impl<T: AnyIoSlice> VecOfIoSlicesExt<T> for Vec<T> {
    fn advance(&mut self, n: usize) {
        let orig_len = self.len();
        let remaining_len = self.as_mut_slice().advance(n).len();
        self.drain(..orig_len - remaining_len);
    }

    fn truncate_bytes(&mut self, n: usize) {
        let keep = self.as_mut_slice().truncate(n).len();
        self.truncate(keep);
    }
}

impl<A: Array> VecOfIoSlicesExt<A::Item> for SmallVec<A>
where
    A::Item: AnyIoSlice,
{
    fn advance(&mut self, n: usize) {
        let orig_len = self.len();
        let remaining_len = self.as_mut_slice().advance(n).len();
        self.drain(..orig_len - remaining_len);
    }

    fn truncate_bytes(&mut self, n: usize) {
        let keep = self.as_mut_slice().truncate(n).len();
        self.truncate(keep);
    }
}
