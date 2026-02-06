// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Generic chain storage traits for TX/RX queue operations.
//!
//! These traits abstract over how iovecs are stored per descriptor chain,
//! allowing different backends to use optimized storage (e.g., mmsghdr for sendmmsg).

use std::io::{IoSlice, IoSliceMut};

/// Storage for a single TX chain's iovecs.
///
/// Implementations store iovecs and provide access for I/O operations.
/// The default is `VecTxStorage` which simply wraps the Vec.
/// For sendmmsg, `MsgHdrTx` stores the pointer directly in mmsghdr.
pub trait TxChainStorage: Sized {
    /// User-defined metadata stored alongside each chain (e.g., Vec capacity).
    type Meta: Default;

    /// Create storage from a Vec of IoSlices (takes ownership).
    fn from_iovecs(iovecs: Vec<IoSlice<'static>>, meta: &mut Self::Meta) -> Self;

    /// Number of slices in this chain.
    fn len(&self) -> usize;

    /// Check if empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get slices for I/O (writev, etc.)
    fn as_slices(&self) -> &[IoSlice<'static>];

    /// Total bytes across all slices.
    fn total_bytes(&self) -> usize;

    /// Clear/reset and drop resources.
    fn clear(&mut self, meta: &mut Self::Meta);
}

/// Storage for a single RX chain's iovecs.
///
/// Similar to TxChainStorage but for writable buffers.
pub trait RxChainStorage: Sized {
    /// User-defined metadata stored alongside each chain.
    type Meta: Default;

    /// Create storage from a Vec of IoSliceMuts (takes ownership).
    fn from_iovecs(iovecs: Vec<IoSliceMut<'static>>, meta: &mut Self::Meta) -> Self;

    /// Number of slices in this chain.
    fn len(&self) -> usize;

    /// Check if empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get mutable slices for I/O (readv, etc.)
    fn as_slices_mut(&mut self) -> &mut [IoSliceMut<'static>];

    /// Total bytes across all slices.
    fn total_bytes(&self) -> usize;

    /// Advance slices by removing consumed bytes from the front.
    fn advance(&mut self, bytes: usize);

    /// Clear/reset and drop resources.
    fn clear(&mut self, meta: &mut Self::Meta);
}

/// Default TX chain storage - simply wraps a Vec<IoSlice>.
pub struct VecTxStorage(Vec<IoSlice<'static>>);

impl TxChainStorage for VecTxStorage {
    type Meta = ();

    fn from_iovecs(iovecs: Vec<IoSlice<'static>>, _meta: &mut ()) -> Self {
        Self(iovecs)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_slices(&self) -> &[IoSlice<'static>] {
        &self.0
    }

    fn total_bytes(&self) -> usize {
        self.0.iter().map(|s| s.len()).sum()
    }

    fn clear(&mut self, _meta: &mut ()) {
        self.0.clear();
    }
}

/// Default RX chain storage - simply wraps a Vec<IoSliceMut>.
pub struct VecRxStorage(Vec<IoSliceMut<'static>>);

impl RxChainStorage for VecRxStorage {
    type Meta = ();

    fn from_iovecs(iovecs: Vec<IoSliceMut<'static>>, _meta: &mut ()) -> Self {
        Self(iovecs)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_slices_mut(&mut self) -> &mut [IoSliceMut<'static>] {
        &mut self.0
    }

    fn total_bytes(&self) -> usize {
        self.0.iter().map(|s| s.len()).sum()
    }

    fn advance(&mut self, bytes: usize) {
        let mut remaining = bytes;
        while remaining > 0 && !self.0.is_empty() {
            let first_len = self.0[0].len();
            if first_len <= remaining {
                self.0.remove(0);
                remaining -= first_len;
            } else {
                // Advance within the first slice
                let first = &mut self.0[0];
                let ptr = first.as_mut_ptr();
                let new_len = first_len - remaining;
                // Safety: advancing pointer within same allocation
                let new_slice = unsafe { std::slice::from_raw_parts_mut(ptr.add(remaining), new_len) };
                self.0[0] = IoSliceMut::new(new_slice);
                remaining = 0;
            }
        }
    }

    fn clear(&mut self, _meta: &mut ()) {
        self.0.clear();
    }
}
