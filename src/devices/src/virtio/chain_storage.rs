// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Generic chain storage trait for TX/RX queue operations.
//!
//! This trait abstracts over how iovecs are stored per descriptor chain,
//! allowing different backends to use optimized storage (e.g., mmsghdr for sendmmsg).

use libc::iovec;

/// Base storage trait for descriptor chain iovecs.
///
/// Construction is not part of the trait - each storage type provides its own
/// constructor.
pub trait ChainStorage: Sized + Send {
    /// User-defined metadata stored alongside each chain (e.g., Vec capacity).
    type Meta: Default;

    /// Number of slices in this chain.
    fn len(&self) -> usize;

    /// Check if empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes across all slices.
    fn total_bytes(&self) -> usize;

    /// Clear/reset and drop resources.
    fn clear(&mut self, meta: &mut Self::Meta);
}

/// Trait for storage types that support advancing (consuming bytes from front).
///
/// This is used by RX operations where the caller tracks byte counts manually
/// (e.g., via readv return values) rather than having the kernel fill them in.
pub trait AdvanceBytes {
    /// Advance slices by removing consumed bytes from the front.
    fn advance(&mut self, bytes: usize);
}

/// Trait for RX storage types that track completed byte counts.
///
/// Storage types like mmsghdr (Linux) or msghdr_x (macOS) have a field
/// that the kernel fills with the number of bytes received. This trait
/// provides access to that value for batch completion.
pub trait CompletedBytes {
    /// Get the number of bytes completed for this chain.
    fn completed_bytes(&self) -> usize;
}

// ChainStorage implemented for Vec<iovec> - the default storage type.
// Raw iovec has no lifetime, avoiding the need for fake 'static lifetimes.

impl ChainStorage for Vec<iovec> {
    type Meta = ();

    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn total_bytes(&self) -> usize {
        self.iter().map(|s| s.iov_len).sum()
    }

    fn clear(&mut self, _meta: &mut ()) {
        Vec::clear(self);
    }
}

impl AdvanceBytes for Vec<iovec> {
    fn advance(&mut self, bytes: usize) {
        let mut remaining = bytes;
        while remaining > 0 && !self.is_empty() {
            let first_len = self[0].iov_len;
            if first_len <= remaining {
                self.remove(0);
                remaining -= first_len;
            } else {
                let first = &mut self[0];
                first.iov_base = unsafe { (first.iov_base as *mut u8).add(remaining) as *mut _ };
                first.iov_len -= remaining;
                remaining = 0;
            }
        }
    }
}
