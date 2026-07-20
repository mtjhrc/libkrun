#![allow(dead_code)]

use std::os::fd::{BorrowedFd, RawFd};
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};

use devices::legacy::IrqChip;
use devices::virtio::{VirtioDevice, VirtioShmRegion, VmmExitObserver};
use polly::event_manager::{EventManager, Subscriber};
use vm_memory::{Address, GuestMemory, GuestMemoryMmap};
use vmm::Vmm;
use vmm::builder::{attach_mmio_device, setup_terminal_raw_mode};
use vmm::device_manager::mmio::Error as MmioError;
use vmm::device_manager::shm::ShmManager;

#[derive(Default)]
pub struct DeviceRequirements {
    pub shm_size: Option<usize>,
    #[cfg(feature = "gpu")]
    pub gpu_shm: Option<usize>,
    pub process_shareable_memory: bool,
}

pub struct ResolvedShmRegion {
    pub host_addr: u64,
    pub guest_addr: u64,
    pub size: usize,
}

impl From<ResolvedShmRegion> for VirtioShmRegion {
    fn from(region: ResolvedShmRegion) -> Self {
        Self {
            host_addr: region.host_addr,
            guest_addr: region.guest_addr,
            size: region.size,
        }
    }
}

pub(crate) struct AttachContext<'a> {
    vmm: &'a mut Vmm,
    event_manager: &'a mut EventManager,
    shm_manager: &'a ShmManager,
    intc: IrqChip,
    device_index: usize,
    #[cfg(target_os = "macos")]
    map_sender: Option<crossbeam_channel::Sender<utils::worker_message::WorkerMessage>>,
}

impl<'a> AttachContext<'a> {
    pub(crate) fn new_mmio(
        vmm: &'a mut Vmm,
        event_manager: &'a mut EventManager,
        shm_manager: &'a ShmManager,
        intc: IrqChip,
        device_index: usize,
        #[cfg(target_os = "macos")] map_sender: Option<
            crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
        >,
    ) -> Self {
        Self {
            vmm,
            event_manager,
            shm_manager,
            intc,
            device_index,
            #[cfg(target_os = "macos")]
            map_sender,
        }
    }

    pub(crate) fn register_mmio_device(
        &mut self,
        id: &str,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<(), MmioError> {
        attach_mmio_device(self.vmm, id.to_string(), self.intc.clone(), device)
    }

    pub(crate) fn subscribe_events(
        &mut self,
        subscriber: Arc<Mutex<dyn Subscriber>>,
    ) -> polly::event_manager::Result<()> {
        self.event_manager.add_subscriber(subscriber)
    }

    pub(crate) fn push_exit_observer(&mut self, observer: Arc<Mutex<dyn VmmExitObserver>>) {
        self.vmm.exit_observers.push(observer);
    }

    pub(crate) fn exit_code(&self) -> &Arc<AtomicI32> {
        &self.vmm.exit_code
    }

    pub(crate) fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.vmm.guest_memory
    }

    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    pub(crate) fn resolved_shm_region(&self) -> Option<ResolvedShmRegion> {
        self.shm_manager.fs_region(self.device_index).map(|region| {
            let host_addr = self
                .vmm
                .guest_memory
                .get_host_address(region.guest_addr)
                .expect("shm region host address");
            ResolvedShmRegion {
                host_addr: host_addr as u64,
                guest_addr: region.guest_addr.raw_value(),
                size: region.size,
            }
        })
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn resolved_gpu_shm_region(&self) -> Option<ResolvedShmRegion> {
        self.shm_manager.gpu_region().map(|region| {
            let host_addr = self
                .vmm
                .guest_memory
                .get_host_address(region.guest_addr)
                .expect("gpu shm region host address");
            ResolvedShmRegion {
                host_addr: host_addr as u64,
                guest_addr: region.guest_addr.raw_value(),
                size: region.size,
            }
        })
    }

    pub(crate) fn device_index(&self) -> usize {
        self.device_index
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn register_sigwinch(&mut self, fd: RawFd) -> utils::errno::Result<()> {
        vmm::signal_handler::register_sigwinch_handler(fd)
    }

    pub(crate) fn setup_terminal_raw_mode(&mut self, fd: BorrowedFd<'_>) {
        setup_terminal_raw_mode(self.vmm, Some(fd), false);
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn map_sender(
        &self,
    ) -> Option<crossbeam_channel::Sender<utils::worker_message::WorkerMessage>> {
        self.map_sender.clone()
    }

    pub(crate) fn append_kernel_cmdline(&mut self, cmdline: &str) {
        self.vmm
            .kernel_cmdline
            .insert_str(cmdline)
            .unwrap_or_else(|e| log::error!("failed to append '{cmdline}' to cmdline: {e}"));
    }
}
