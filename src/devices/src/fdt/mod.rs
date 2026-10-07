// Copyright 2025, Institute of Software, CAS. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "riscv64")]
pub use riscv64::*;

#[cfg(test)]
mod tests {
    use super::DeviceInfoForFDT;
    #[cfg(target_arch = "aarch64")]
    use super::aarch64::create_devices_node;
    #[cfg(target_arch = "riscv64")]
    use super::riscv64::create_devices_node;
    use crate::DeviceType;
    use vm_fdt::FdtWriter;

    #[derive(Clone, Debug)]
    struct DeviceInfo {
        addr: u64,
        irq: u32,
    }

    impl DeviceInfoForFDT for DeviceInfo {
        fn addr(&self) -> u64 {
            self.addr
        }

        fn irq(&self) -> u32 {
            self.irq
        }

        fn length(&self) -> u64 {
            0x1000
        }
    }

    #[test]
    fn repeated_virtio_type_preserves_nodes_in_address_order() {
        let devices = [
            (
                DeviceType::Virtio(18),
                DeviceInfo {
                    addr: 0xd000_1000,
                    irq: 33,
                },
            ),
            (
                DeviceType::Virtio(18),
                DeviceInfo {
                    addr: 0xd000_0000,
                    irq: 32,
                },
            ),
        ];
        let mut fdt = FdtWriter::new().unwrap();
        let root = fdt.begin_node("").unwrap();
        create_devices_node(&mut fdt, &devices).unwrap();
        fdt.end_node(root).unwrap();
        let bytes = fdt.finish().unwrap();
        let first = b"virtio_mmio@d0000000\0";
        let second = b"virtio_mmio@d0001000\0";
        let first_positions: Vec<_> = bytes
            .windows(first.len())
            .enumerate()
            .filter_map(|(i, bytes)| (bytes == first).then_some(i))
            .collect();
        let second_positions: Vec<_> = bytes
            .windows(second.len())
            .enumerate()
            .filter_map(|(i, bytes)| (bytes == second).then_some(i))
            .collect();
        assert_eq!(first_positions.len(), 1);
        assert_eq!(second_positions.len(), 1);
        assert!(first_positions[0] < second_positions[0]);
    }
}
