// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Utilities for working with iovec slices.

use std::io::IoSliceMut;

/// Calculate total length of iovec slices.
/// Works with both IoSlice and IoSliceMut.
pub fn iovecs_len<T: std::ops::Deref<Target = [u8]>>(slices: &[T]) -> usize {
    slices.iter().map(|s| s.len()).sum()
}

/// Write data to iovecs, spanning multiple buffers if needed.
pub fn write_to_iovecs(slices: &mut [IoSliceMut], data: &[u8]) -> usize {
    let mut written = 0;
    for iov in slices.iter_mut() {
        let remaining = data.len() - written;
        if remaining == 0 {
            break;
        }
        let take = remaining.min(iov.len());
        iov[..take].copy_from_slice(&data[written..written + take]);
        written += take;
    }
    written
}

/// Truncate iovecs in place to max_bytes total, returning the usable slice.
pub fn truncate_iovecs<'a, 'b>(
    slices: &'a mut [IoSliceMut<'b>],
    max_bytes: usize,
) -> &'a mut [IoSliceMut<'b>] {
    let mut total: usize = 0;
    for (i, slice) in slices.iter_mut().enumerate() {
        let new_total = total.saturating_add(slice.len());

        if new_total >= max_bytes {
            // total <= max_bytes here (otherwise we'd have returned in a previous iteration),
            // so this subtraction cannot underflow
            let take = max_bytes - total;
            // Last iovec is empty so we don't include it in the and
            if take == 0 {
                 return &mut slices[..i];
            }
            
            let ptr = slice.as_mut_ptr();
            // SAFETY: `take <= len` because we only enter this branch when
            // `total + len >= max_bytes`, which means `max_bytes - total <= len`.
            // The pointer `ptr` is valid for `len` bytes, so it's valid for `take` bytes.
            *slice = IoSliceMut::new(unsafe { std::slice::from_raw_parts_mut(ptr, take) });
            return &mut slices[..=i];
        }
        total = new_total;
    }
    slices
}
