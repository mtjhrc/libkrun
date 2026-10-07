// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use devices::fdt::DeviceInfoForFDT;

/// Legacy Device Manager.
pub mod legacy;

/// Device Shared Memory Region Manager.
pub mod shm;

/// Memory Mapped I/O Manager.
#[cfg(target_os = "linux")]
pub mod kvm;
#[cfg(target_os = "linux")]
pub use self::kvm::mmio;
#[cfg(target_os = "macos")]
pub mod hvf;
#[cfg(target_os = "macos")]
pub use self::hvf::mmio;
#[cfg(target_os = "windows")]
pub mod whp;
#[cfg(target_os = "windows")]
pub use self::whp::mmio;

#[derive(Clone, Debug)]
pub struct MMIODeviceInfo {
    pub(crate) addr: u64,
    pub(crate) irq: u32,
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    pub(crate) len: u64,
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
impl DeviceInfoForFDT for MMIODeviceInfo {
    fn addr(&self) -> u64 {
        self.addr
    }

    fn irq(&self) -> u32 {
        self.irq
    }

    fn length(&self) -> u64 {
        self.len
    }
}
