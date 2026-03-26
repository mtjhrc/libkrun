use std::marker::PhantomData;
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};

use devices::legacy::{IrqChip, IrqChipDevice};
use devices::virtio::VirtioShmRegion;
use kernel::cmdline::Cmdline;
use polly::event_manager::EventManager;
use utils::eventfd::EventFd;
use vm_memory::Address;

use vmm::builder::{
    self, attach_mmio_device, choose_payload, create_guest_memory, load_cmdline,
    setup_terminal_raw_mode,
};
use vmm::device_manager::mmio::MMIODeviceManager;
use vmm::vmm_config::kernel_bundle::KernelBundle;
use vmm::vmm_config::kernel_cmdline::DEFAULT_KERNEL_CMDLINE;
use vmm::vstate::VcpuConfig;
use vmm::Vmm as InnerVmm;

use super::devices::{BalloonDevice, ConsoleDevice, FsDevice, RngDevice};
use super::error::{Error, ErrorCode};
use super::payload::LibkrunInit;

const INIT_PATH: &str = "/init.krun";

// ---------------------------------------------------------------------------
// KrunfwBindings — dynamically load libkrunfw
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", not(feature = "tee")))]
const KRUNFW_NAME: &str = "libkrunfw.so.5";
#[cfg(all(target_os = "linux", feature = "amd-sev"))]
const KRUNFW_NAME: &str = "libkrunfw-sev.so.5";
#[cfg(all(target_os = "linux", feature = "tdx"))]
const KRUNFW_NAME: &str = "libkrunfw-tdx.so.5";
#[cfg(target_os = "macos")]
const KRUNFW_NAME: &str = "libkrunfw.5.dylib";

struct KrunfwBindings {
    get_kernel: libloading::Symbol<
        'static,
        unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut libc::c_char,
    >,
}

static KRUNFW: std::sync::LazyLock<Option<libloading::Library>> =
    std::sync::LazyLock::new(|| unsafe { libloading::Library::new(KRUNFW_NAME).ok() });

fn load_krunfw_bindings() -> Result<KrunfwBindings, Error> {
    let lib = KRUNFW.as_ref().ok_or_else(|| {
        Error::new(
            ErrorCode::FileNotFound,
            format!("could not load {KRUNFW_NAME}"),
        )
    })?;
    let get_kernel = unsafe {
        lib.get(b"krunfw_get_kernel")
            .map_err(|e| Error::new(ErrorCode::Internal, format!("krunfw symbol: {e}")))?
    };
    Ok(KrunfwBindings { get_kernel })
}

fn load_krunfw_kernel(krunfw: &KrunfwBindings) -> Result<KernelBundle, Error> {
    let mut guest_addr: u64 = 0;
    let mut entry_addr: u64 = 0;
    let mut size: usize = 0;
    let host_addr = unsafe {
        (krunfw.get_kernel)(
            &mut guest_addr as *mut u64,
            &mut entry_addr as *mut u64,
            &mut size as *mut usize,
        )
    };
    if host_addr.is_null() {
        return Err(Error::new(
            ErrorCode::BootError,
            "krunfw_get_kernel returned null",
        ));
    }
    Ok(KernelBundle {
        host_addr: host_addr as u64,
        guest_addr,
        entry_addr,
        size,
    })
}

// ---------------------------------------------------------------------------
// VmmBuilder
// ---------------------------------------------------------------------------

pub struct VmmBuilder<'a> {
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    payload: Option<LibkrunInit>,
    fs_devices: Vec<FsDevice<'a>>,
    console_devices: Vec<ConsoleDevice<'a>>,
    balloon: Option<BalloonDevice>,
    rng: Option<RngDevice>,
}

#[ffier::exportable(prefix = "krun")]
impl<'a> VmmBuilder<'a> {
    pub fn new() -> Self {
        VmmBuilder {
            vcpus: None,
            ram_mib: None,
            payload: None,
            fs_devices: Vec::new(),
            console_devices: Vec::new(),
            balloon: None,
            rng: None,
        }
    }

    pub fn set_vcpus(&mut self, count: u8) -> Result<(), ErrorCode> {
        if count == 0 {
            return Err(ErrorCode::OutOfRange);
        }
        self.vcpus = Some(count);
        Ok(())
    }

    pub fn set_ram_mib(&mut self, mib: u32) -> Result<(), ErrorCode> {
        if mib == 0 {
            return Err(ErrorCode::OutOfRange);
        }
        self.ram_mib = Some(mib);
        Ok(())
    }

    pub fn set_payload(&mut self, payload: LibkrunInit) {
        self.payload = Some(payload);
    }

    pub fn add_fs_device(&mut self, device: FsDevice<'a>) {
        self.fs_devices.push(device);
    }

    pub fn add_console_device(&mut self, device: ConsoleDevice<'a>) {
        self.console_devices.push(device);
    }

    pub fn set_balloon(&mut self, device: BalloonDevice) {
        self.balloon = Some(device);
    }

    pub fn set_rng(&mut self, device: RngDevice) {
        self.rng = Some(device);
    }

    pub fn build(self) -> Result<KrunVmm<'a>, ErrorCode> {
        build_vm(self).map_err(|e| {
            log::error!("{e}");
            e.code
        })
    }
}

// ---------------------------------------------------------------------------
// KrunVmm — the running VM handle
// ---------------------------------------------------------------------------

pub struct KrunVmm<'a> {
    #[allow(dead_code)]
    inner: Arc<Mutex<InnerVmm>>,
    event_manager: EventManager,
    _lifetime: PhantomData<&'a ()>,
}

#[ffier::exportable(prefix = "krun")]
impl<'a> KrunVmm<'a> {
    pub fn run(&mut self) {
        loop {
            if let Err(e) = self.event_manager.run() {
                log::error!("fatal event loop error: {e:?}");
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The actual VM construction logic (extracted from build_microvm)
// ---------------------------------------------------------------------------

fn build_vm(builder_cfg: VmmBuilder<'_>) -> Result<KrunVmm<'_>, Error> {
    let vcpus_count = builder_cfg.vcpus.ok_or_else(|| {
        Error::new(ErrorCode::MissingConfig, "vcpus not set")
    })?;
    let ram_mib = builder_cfg.ram_mib.ok_or_else(|| {
        Error::new(ErrorCode::MissingConfig, "ram_mib not set")
    })?;
    let payload = builder_cfg.payload.ok_or_else(|| {
        Error::new(ErrorCode::MissingConfig, "payload not set")
    })?;
    if builder_cfg.fs_devices.is_empty() {
        return Err(Error::new(
            ErrorCode::MissingConfig,
            "at least one fs device is required",
        ));
    }

    // 1. Load krunfw kernel
    let krunfw = load_krunfw_bindings()?;
    let kernel_bundle = load_krunfw_kernel(&krunfw)?;

    // 2. Choose payload type
    let payload_type = choose_payload(
        Some(&kernel_bundle),
        #[cfg(feature = "tee")]
        None,
        #[cfg(feature = "tee")]
        None,
        None, // external_kernel
        None, // firmware_config
    )
    .map_err(|e| Error::new(ErrorCode::BootError, format!("{e:?}")))?;

    // 3. Collect fs shm sizes
    let fs_shm_sizes: Vec<Option<usize>> = builder_cfg
        .fs_devices
        .iter()
        .map(|fs| fs.shm_size)
        .collect();

    // 4. Create guest memory
    let (guest_memory, arch_memory_info, shm_manager, payload_config) = create_guest_memory(
        ram_mib as usize,
        Some(&kernel_bundle),
        #[cfg(feature = "tee")]
        None,
        #[cfg(feature = "tee")]
        None,
        None, // firmware_config
        &fs_shm_sizes,
        None, // gpu_virgl_flags
        None, // gpu_shm_size
        &payload_type,
    )
    .map_err(|e| Error::new(ErrorCode::BootError, format!("{e:?}")))?;

    // 5. Build kernel command line
    let mut kernel_cmdline = Cmdline::new(arch::CMDLINE_MAX_SIZE);

    if let Some(cmdline) = payload_config.kernel_cmdline {
        kernel_cmdline.insert_str(cmdline.as_str()).unwrap();
    } else {
        let cmdline_base = DEFAULT_KERNEL_CMDLINE.replace(" quiet", "");
        kernel_cmdline
            .insert_str(&format!("{cmdline_base} init={INIT_PATH}"))
            .unwrap();
    }

    // Append KRUN_INIT, KRUN_WORKDIR, KRUN_ENV
    let payload_args = payload.args.clone();
    kernel_cmdline.insert_str(&payload.env).unwrap();

    // NOTE: the "-- args" epilog is appended AFTER device attachment (step 15),
    // because attach_mmio_device appends virtio_mmio.device= params to the cmdline
    // and those must come BEFORE "--".

    log::info!("kernel cmdline: {}", kernel_cmdline.as_str());
    log::info!("kernel bundle: host=0x{:x} guest=0x{:x} entry=0x{:x} size={}",
        kernel_bundle.host_addr, kernel_bundle.guest_addr, kernel_bundle.entry_addr, kernel_bundle.size);
    log::info!("payload entry_addr: 0x{:x}", payload_config.entry_addr.0);
    log::info!("mem_info: ram_below_gap={} ram_above_gap={} ram_last_addr=0x{:x}",
        arch_memory_info.ram_below_gap, arch_memory_info.ram_above_gap, arch_memory_info.ram_last_addr);

    // 6. Set up VM
    #[cfg(not(feature = "tee"))]
    let vm = builder::setup_vm(&guest_memory, false)
        .map_err(|e| Error::new(ErrorCode::HypervisorError, format!("{e:?}")))?;

    let mut event_manager = EventManager::new()
        .map_err(|e| Error::new(ErrorCode::Internal, format!("EventManager: {e:?}")))?;

    // 7. Create legacy serial device on COM1 (no output — kernel console goes via hvc0)
    let serial_devices = vec![
        builder::setup_serial_device(&mut event_manager, None, None)
            .map_err(|e| Error::new(ErrorCode::Internal, format!("serial: {e:?}")))?,
    ];

    let exit_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK)
        .map_err(|e| Error::new(ErrorCode::Internal, format!("eventfd: {e}")))?;

    // 8. Create device managers
    #[cfg(target_arch = "x86_64")]
    let mut pio_device_manager = {
        use devices::legacy::Cmos;
        vmm::device_manager::legacy::PortIODeviceManager::new(
            Arc::new(Mutex::new(Cmos::new(
                arch_memory_info.ram_below_gap,
                arch_memory_info.ram_above_gap,
            ))),
            serial_devices,
            exit_evt
                .try_clone()
                .map_err(|e| Error::new(ErrorCode::Internal, format!("eventfd: {e}")))?,
        )
        .map_err(|e| Error::new(ErrorCode::Internal, format!("pio: {e:?}")))?
    };

    #[allow(unused_mut)]
    let mut mmio_device_manager = MMIODeviceManager::new(
        &mut (arch::MMIO_MEM_START.clone()),
        (arch::IRQ_BASE, arch::IRQ_MAX),
    );

    let vcpu_config = VcpuConfig {
        vcpu_count: vcpus_count,
        ht_enabled: false,
        cpu_template: None,
    };

    // 9. Create vCPUs + interrupt controller (arch-specific)
    let vcpus;
    let intc: IrqChip;

    #[cfg(target_arch = "x86_64")]
    {
        use devices::legacy::KvmIoapic;

        let ioapic = Box::new(
            KvmIoapic::new(vm.fd())
                .map_err(|e| Error::new(ErrorCode::HypervisorError, format!("{e:?}")))?,
        );
        intc = Arc::new(Mutex::new(IrqChipDevice::new(ioapic)));

        builder::attach_legacy_devices(
            &vm,
            false, // split_irqchip
            &mut pio_device_manager,
            &mut mmio_device_manager,
            Some(intc.clone()),
        )
        .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;

        vcpus = builder::create_vcpus_x86_64(
            &vm,
            &vcpu_config,
            &guest_memory,
            payload_config.entry_addr,
            &pio_device_manager.io_bus,
            &exit_evt,
            true, // kernel_boot
            #[cfg(feature = "tee")]
            crossbeam_channel::unbounded().0,
        )
        .map_err(|e| Error::new(ErrorCode::HypervisorError, format!("{e:?}")))?;
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        use devices::legacy::{KvmGicV2, KvmGicV3};

        vcpus = builder::create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &arch_memory_info,
            payload_config.entry_addr,
            &exit_evt,
        )
        .map_err(|e| Error::new(ErrorCode::HypervisorError, format!("{e:?}")))?;

        intc = {
            let gic = match KvmGicV3::new(vm.fd(), vcpus_count as u64) {
                Ok(gicv3) => IrqChipDevice::new(Box::new(gicv3)),
                Err(_) => IrqChipDevice::new(Box::new(KvmGicV2::new(vm.fd(), vcpus_count as u64))),
            };
            Arc::new(Mutex::new(gic))
        };

        builder::attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
        )
        .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        use devices::legacy::{GicV3, HvfGicV3, VcpuList};

        let vcpu_list = Arc::new(VcpuList::new(vcpus_count as u64));

        intc = {
            let gic = match HvfGicV3::new(vcpus_count as u64) {
                Ok(hvfgic) => IrqChipDevice::new(Box::new(hvfgic)),
                Err(_) => IrqChipDevice::new(Box::new(GicV3::new(vcpu_list.clone()))),
            };
            Arc::new(Mutex::new(gic))
        };

        vcpus = builder::create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &arch_memory_info,
            payload_config.entry_addr,
            &exit_evt,
            vcpu_list.clone(),
            false, // nested_enabled
        )
        .map_err(|e| Error::new(ErrorCode::HypervisorError, format!("{e:?}")))?;

        builder::attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
            &mut event_manager,
            None, // shutdown_efd
        )
        .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;
    }

    // 10. Construct Vmm struct
    let exit_code = Arc::new(AtomicI32::new(i32::MAX));

    let mut vmm = InnerVmm {
        guest_memory,
        arch_memory_info,
        kernel_cmdline,
        vcpus_handles: Vec::new(),
        exit_evt,
        exit_observers: Vec::new(),
        exit_code: exit_code.clone(),
        vm,
        mmio_device_manager,
        #[cfg(target_arch = "x86_64")]
        pio_device_manager,
    };

    // 11. Attach balloon
    if let Some(balloon) = builder_cfg.balloon {
        event_manager
            .add_subscriber(balloon.inner.clone())
            .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;
        attach_mmio_device(&mut vmm, "balloon".into(), intc.clone(), balloon.inner)
            .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;
    }

    // 12. Attach rng
    if let Some(rng) = builder_cfg.rng {
        event_manager
            .add_subscriber(rng.inner.clone())
            .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;
        attach_mmio_device(&mut vmm, "rng".into(), intc.clone(), rng.inner)
            .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;
    }

    // 13. Attach console devices
    for (i, console) in builder_cfg.console_devices.into_iter().enumerate() {
        let tty_fds = console.tty_fds.clone();

        let console_dev =
            Arc::new(Mutex::new(devices::virtio::Console::new(console.ports).map_err(
                |e| Error::new(ErrorCode::Internal, format!("console: {e:?}")),
            )?));

        vmm.exit_observers.push(console_dev.clone());

        event_manager
            .add_subscriber(console_dev.clone())
            .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;

        #[cfg(target_os = "linux")]
        vmm::signal_handler::register_sigwinch_handler(
            console_dev.lock().unwrap().get_sigwinch_fd(),
        )
        .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;

        attach_mmio_device(&mut vmm, format!("hvc{i}"), intc.clone(), console_dev)
            .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;

        // Set terminal raw mode for TTY ports (must happen after Vmm is constructed)
        for fd in &tty_fds {
            let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(*fd) };
            setup_terminal_raw_mode(&mut vmm, Some(borrowed), false);
        }
    }

    // 14. Attach fs devices
    for (i, fs_dev) in builder_cfg.fs_devices.into_iter().enumerate() {
        // Set up shm region if configured
        if let Some(shm_region) = shm_manager.fs_region(i) {
            use vm_memory::GuestMemory;
            fs_dev.inner.lock().unwrap().set_shm_region(VirtioShmRegion {
                host_addr: vmm
                    .guest_memory
                    .get_host_address(shm_region.guest_addr)
                    .map_err(|e| {
                        Error::new(ErrorCode::Internal, format!("shm host addr: {e:?}"))
                    })? as u64,
                guest_addr: shm_region.guest_addr.raw_value(),
                size: shm_region.size,
            });
        }

        let id = format!("virtiofs{i}");
        attach_mmio_device(&mut vmm, id, intc.clone(), fs_dev.inner)
            .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;
    }

    // 15. Append "-- args" epilog (must come after device attachment)
    if !payload_args.is_empty() {
        vmm.kernel_cmdline
            .insert_str(&format!(" -- {}", payload_args))
            .unwrap();
    }

    log::info!("final cmdline: {}", vmm.kernel_cmdline.as_str());

    // 16. Write kernel cmdline to guest memory (x86_64)
    #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
    load_cmdline(&vmm)
        .map_err(|e| Error::new(ErrorCode::BootError, format!("{e:?}")))?;

    // 16. Configure system
    vmm.configure_system(
        vcpus.as_slice(),
        &intc,
        &payload_config.initrd_config,
        &None, // smbios_oem_strings
    )
    .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;

    // 17. Start vCPUs
    vmm.start_vcpus(vcpus)
        .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;

    // 18. Register with EventManager
    #[allow(clippy::arc_with_non_send_sync)]
    let vmm = Arc::new(Mutex::new(vmm));
    event_manager
        .add_subscriber(vmm.clone())
        .map_err(|e| Error::new(ErrorCode::Internal, format!("{e:?}")))?;

    Ok(KrunVmm {
        inner: vmm,
        event_manager,
        _lifetime: PhantomData,
    })
}
