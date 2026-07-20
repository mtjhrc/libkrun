// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Old v1 boot path: builds and starts a microVM from `VmResources`.
//!
//! This lives in `libkrun` (not `vmm`) rather than in `vmm::builder`, so it
//! can eventually attach devices through the internal `AttachContext` in
//! `crate::attach` instead of hand-rolling `attach_mmio_device` calls per
//! device kind. This commit is a pure relocation: behavior is unchanged,
//! only the crate location and import paths differ from the previous
//! `vmm::builder::build_microvm()`.

use std::fs::File;
use std::io::{self, IsTerminal};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::fd::{BorrowedFd, FromRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle};
#[cfg(windows)]
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};

use crossbeam_channel::Sender;
#[cfg(target_arch = "x86_64")]
use devices::legacy::Cmos;
#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
use devices::legacy::KvmAia;
#[cfg(target_arch = "x86_64")]
use devices::legacy::KvmIoapic;
#[cfg(target_os = "macos")]
use devices::legacy::VcpuList;
#[cfg(target_os = "macos")]
use devices::legacy::{GicV3, HvfGicV3};
#[cfg(target_arch = "x86_64")]
use devices::legacy::{IoApic, IrqChipT};
use devices::legacy::{IrqChip, IrqChipDevice};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use devices::legacy::{KvmGicV2, KvmGicV3};
#[cfg(feature = "gpu")]
use devices::virtio::display::DisplayInfo;
#[cfg(feature = "gpu")]
use devices::virtio::display::NoopDisplayBackend;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::fs::ExportTable;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::passthrough::PermissionSemantics;
use devices::virtio::{PortDescription, Vsock, port_io};
#[cfg(feature = "gpu")]
use krun_display::DisplayBackend;
#[cfg(feature = "gpu")]
use krun_display::IntoDisplayBackend;
#[cfg(unix)]
use libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
#[cfg(unix)]
use nix::unistd::isatty;
use polly::event_manager::EventManager;
use utils::eventfd::EventFd;
#[cfg(windows)]
use utils::windows::SendHandle;
use utils::worker_message::WorkerMessage;
#[cfg(windows)]
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

use kernel::cmdline::Cmdline;
#[cfg(target_arch = "aarch64")]
use vmm::builder::create_vcpus_aarch64;
#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
use vmm::builder::create_vcpus_riscv64;
#[cfg(target_arch = "x86_64")]
use vmm::builder::create_vcpus_x86_64;
#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
use vmm::builder::load_cmdline;
#[cfg(not(feature = "tee"))]
use vmm::builder::setup_vm;
use vmm::builder::{
    StartMicrovmError, attach_legacy_devices, choose_payload, create_guest_memory,
    setup_serial_device, setup_terminal_raw_mode,
};
#[cfg(feature = "tee")]
use vmm::builder::{
    create_tee_vm, finalize_tee_vm, prepare_tee_vcpus, tee_boot_input_from_resources,
};
#[cfg(target_arch = "x86_64")]
use vmm::device_manager::legacy::PortIODeviceManager;
use vmm::device_manager::mmio::MMIODeviceManager;
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
use vmm::resources::VhostUserDeviceConfig;
use vmm::resources::{
    DefaultVirtioConsoleConfig, PortConfig, TsiFlags, VirtioConsoleConfigMode, VmResources,
};
#[cfg(target_os = "linux")]
use vmm::signal_handler::register_sigint_handler;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use vmm::vmm_config::fs::FsDeviceConfig;
use vmm::vmm_config::kernel_cmdline::DEFAULT_KERNEL_CMDLINE;
use vmm::{Error, Vmm};

use crate::attach::AttachContext;

/// Builds and starts a microVM based on the current `VmResources` configuration.
///
/// This is the v1 boot recipe used by `krun_start_enter()`.
pub fn build_microvm(
    vm_resources: &VmResources,
    event_manager: &mut EventManager,
    _shutdown_efd: Option<EventFd>,
    _sender: Sender<WorkerMessage>,
) -> std::result::Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    let payload = choose_payload(
        vm_resources.kernel_bundle.as_ref(),
        #[cfg(feature = "tee")]
        vm_resources.qboot_bundle.as_ref(),
        #[cfg(feature = "tee")]
        vm_resources.initrd_bundle.as_ref(),
        vm_resources.external_kernel(),
        vm_resources.firmware_config.as_ref(),
    )?;

    let fs_shm_sizes: Vec<Option<usize>> = vm_resources.fs.iter().map(|f| f.shm_size).collect();

    let (guest_memory, arch_memory_info, mut _shm_manager, payload_config) = create_guest_memory(
        vm_resources
            .vm_config()
            .mem_size_mib
            .ok_or(StartMicrovmError::MissingMemSizeConfig)?,
        vm_resources.kernel_bundle.as_ref(),
        #[cfg(feature = "tee")]
        vm_resources.qboot_bundle.as_ref(),
        #[cfg(feature = "tee")]
        vm_resources.initrd_bundle.as_ref(),
        vm_resources.firmware_config.as_ref(),
        &fs_shm_sizes,
        vm_resources
            .gpu_virgl_flags
            .map(|_| vm_resources.gpu_shm_size.unwrap_or(1 << 33)),
        {
            #[cfg(all(feature = "vhost-user", target_os = "linux"))]
            {
                !vm_resources.vhost_user_devices.is_empty()
            }
            #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
            {
                false
            }
        },
        &payload,
    )?;

    let vcpu_config = vm_resources.vcpu_config();

    // Clone the command-line so that a failed boot doesn't pollute the original.
    #[allow(unused_mut)]
    let mut kernel_cmdline = Cmdline::new(arch::CMDLINE_MAX_SIZE);
    if let Some(cmdline) = payload_config.kernel_cmdline {
        kernel_cmdline.insert_str(cmdline.as_str()).unwrap();
    } else if let Some(cmdline) = &vm_resources.kernel_cmdline.prolog {
        kernel_cmdline.insert_str(cmdline).unwrap();
    } else {
        kernel_cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).unwrap();
    }

    if let Some(cmdline) = &vm_resources.kernel_cmdline.krun_env {
        kernel_cmdline.insert_str(cmdline.as_str()).unwrap();
    }

    if let Some(kernel_console) = &vm_resources.kernel_console {
        let cmdline = kernel_cmdline.as_str();
        let console_start_idx = cmdline.find("console=").unwrap();
        let console_end_idx = cmdline
            .get(console_start_idx..)
            .and_then(|s| s.find(" ").map(|i| i + console_start_idx));

        let cmdline = cmdline.replace(
            &cmdline[console_start_idx..console_end_idx.unwrap()],
            format!("console={kernel_console}").as_str(),
        );
        kernel_cmdline = Cmdline::new(arch::CMDLINE_MAX_SIZE);
        kernel_cmdline.insert_str(cmdline).unwrap();
    }

    #[cfg(not(feature = "tee"))]
    #[allow(unused_mut)]
    let mut vm = setup_vm(&guest_memory, vm_resources.nested_enabled)?;

    #[cfg(feature = "tee")]
    let tee_boot = tee_boot_input_from_resources(vm_resources)?;

    #[cfg(feature = "tee")]
    let (vm, mut tee_state) = create_tee_vm(
        &guest_memory,
        &tee_boot,
        &payload_config,
        #[cfg(feature = "tdx")]
        _sender.clone(),
    )?;

    let mut serial_devices = Vec::new();

    // We can't call to `setup_terminal_raw_mode` until `Vmm` is created,
    // so let's keep track of FDs connected to legacy serial devices here
    // and set raw mode on them later.
    let mut serial_ttys = Vec::new();

    #[cfg(unix)]
    for s in &vm_resources.serial_consoles {
        let input: Option<Box<dyn devices::legacy::ReadableFd + Send>> = if s.input_fd >= 0 {
            let file = unsafe { File::from_raw_fd(s.input_fd) };
            if file.is_terminal() {
                serial_ttys.push(unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) });
            }
            Some(Box::new(file))
        } else {
            None
        };

        let output: Option<Box<dyn io::Write + Send>> = if s.output_fd >= 0 {
            Some(Box::new(unsafe { File::from_raw_fd(s.output_fd) }))
        } else {
            None
        };

        serial_devices.push(setup_serial_device(event_manager, input, output)?);
    }

    #[cfg(windows)]
    for s in &vm_resources.serial_consoles {
        let input: Option<Box<dyn devices::legacy::ReadableFd + Send>> =
            if is_valid_handle(s.input_handle.as_raw_handle()) {
                if unsafe {
                    BorrowedHandle::borrow_raw(s.input_handle.as_raw_handle()).is_terminal()
                } {
                    serial_ttys.push(s.input_handle);
                }
                Some(Box::new(unsafe {
                    File::from_raw_handle(s.input_handle.as_raw_handle())
                }))
            } else {
                None
            };

        let output: Option<Box<dyn io::Write + Send>> =
            if is_valid_handle(s.output_handle.as_raw_handle()) {
                Some(Box::new(unsafe {
                    File::from_raw_handle(s.output_handle.as_raw_handle())
                }))
            } else {
                None
            };

        serial_devices.push(setup_serial_device(event_manager, input, output)?);
    }

    let exit_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK)
        .map_err(Error::EventFd)
        .map_err(StartMicrovmError::Internal)?;

    #[cfg(target_arch = "x86_64")]
    // Safe to unwrap 'serial_device' as it's always 'Some' on x86_64.
    // x86_64 uses the i8042 reset event as the Vmm exit event.
    let mut pio_device_manager = PortIODeviceManager::new(
        Arc::new(Mutex::new(Cmos::new(
            arch_memory_info.ram_below_gap,
            arch_memory_info.ram_above_gap,
        ))),
        serial_devices,
        exit_evt
            .try_clone()
            .map_err(Error::EventFd)
            .map_err(StartMicrovmError::Internal)?,
    )
    .map_err(Error::CreateLegacyDevice)
    .map_err(StartMicrovmError::Internal)?;

    // Instantiate the MMIO device manager.
    // 'mmio_base' address has to be an address which is protected by the kernel
    // and is architectural specific.
    #[allow(unused_mut)]
    let mut mmio_device_manager = MMIODeviceManager::new(
        &mut (arch::MMIO_MEM_START.clone()),
        (arch::IRQ_BASE, arch::IRQ_MAX),
    );

    #[cfg(target_os = "macos")]
    let vcpu_list = {
        let cpu_count = vm_resources.vm_config().vcpu_count.unwrap();
        Arc::new(VcpuList::new(cpu_count as u64))
    };

    let vcpus;
    let intc: IrqChip;
    // For x86_64 we need to create the interrupt controller before calling `KVM_CREATE_VCPUS`
    // while on aarch64 we need to do it the other way around.
    #[cfg(target_arch = "x86_64")]
    {
        let ioapic: Box<dyn IrqChipT> = if vm_resources.split_irqchip {
            Box::new(
                IoApic::new(vm.fd(), _sender.clone())
                    .map_err(StartMicrovmError::CreateKvmIrqChip)?,
            )
        } else {
            Box::new(KvmIoapic::new(vm.fd()).map_err(StartMicrovmError::CreateKvmIrqChip)?)
        };
        intc = Arc::new(Mutex::new(IrqChipDevice::new(ioapic)));

        attach_legacy_devices(
            &vm,
            vm_resources.split_irqchip,
            &mut pio_device_manager,
            &mut mmio_device_manager,
            Some(intc.clone()),
        )?;

        let kernel_boot = vm_resources.firmware_config.is_none() && !cfg!(feature = "tee");

        vcpus = create_vcpus_x86_64(
            &vm,
            &vcpu_config,
            &guest_memory,
            payload_config.entry_addr,
            &pio_device_manager.io_bus,
            &exit_evt,
            kernel_boot,
            payload_config.pvh,
            #[cfg(feature = "tee")]
            _sender,
        )
        .map_err(StartMicrovmError::Internal)?;
    }

    #[cfg(feature = "tee")]
    prepare_tee_vcpus(&vm, &mut tee_state, &vcpus)?;

    // On aarch64, the vCPUs need to be created (i.e call KVM_CREATE_VCPU) and configured before
    // setting up the IRQ chip because the `KVM_CREATE_VCPU` ioctl will return error if the IRQCHIP
    // was already initialized.
    // Search for `kvm_arch_vcpu_create` in arch/arm/kvm/arm.c.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        vcpus = create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &arch_memory_info,
            payload_config.entry_addr,
            &exit_evt,
        )
        .map_err(StartMicrovmError::Internal)?;

        intc = {
            // The SoC in some popular boards (namely, the RPi family) doesn't support an
            // architected vGIC, which is required for requesting KVM the instantiation of a
            // GICv3. To relieve the users from having to configure the gic version manually,
            // try first to instantiate a GICv3, and fall back to a GICv2 if it fails.
            let vcpu_count = vm_resources.vm_config().vcpu_count.unwrap() as u64;
            let gic = match KvmGicV3::new(vm.fd(), vcpu_count) {
                Ok(gicv3) => IrqChipDevice::new(Box::new(gicv3)),
                Err(_) => {
                    warn!("KVM GICv3 creation failed, falling back to KVM GICv2");
                    IrqChipDevice::new(Box::new(KvmGicV2::new(vm.fd(), vcpu_count)))
                }
            };
            Arc::new(Mutex::new(gic))
        };

        attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
        )?;
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        intc = {
            // If the system supports the in-kernel GIC, use it. Otherwise, fall back to the
            // userspace implementation.
            let gic = match HvfGicV3::new(vm_resources.vm_config().vcpu_count.unwrap() as u64) {
                Ok(hvfgic) => IrqChipDevice::new(Box::new(hvfgic)),
                Err(_) => IrqChipDevice::new(Box::new(GicV3::new(vcpu_list.clone()))),
            };
            Arc::new(Mutex::new(gic))
        };

        vcpus = create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &arch_memory_info,
            payload_config.entry_addr,
            &exit_evt,
            vcpu_list.clone(),
            vm_resources.nested_enabled,
        )
        .map_err(StartMicrovmError::Internal)?;

        attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
            event_manager,
            _shutdown_efd,
        )?;
    }

    #[cfg(all(target_arch = "riscv64", target_os = "linux"))]
    {
        vcpus = create_vcpus_riscv64(
            &vm,
            &vcpu_config,
            &guest_memory,
            payload_config.entry_addr,
            &exit_evt,
        )
        .map_err(StartMicrovmError::Internal)?;

        intc = Arc::new(Mutex::new(IrqChipDevice::new(Box::new(
            KvmAia::new(vm.fd(), vm_resources.vm_config().vcpu_count.unwrap() as u32).unwrap(),
        ))));

        attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
        )?;
    }

    // We use this atomic to record the exit code set by init/init.c in the VM.
    let exit_code = Arc::new(AtomicI32::new(i32::MAX));

    let mut vmm = Vmm {
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

    // Set raw mode for FDs that are connected to legacy serial devices.
    for serial_tty in serial_ttys {
        setup_terminal_raw_mode(&mut vmm, Some(serial_tty), false);
    }

    let devices = collect_devices(vm_resources, exit_code);
    for device in devices {
        let device_index = device.device_index();
        let mut ctx = AttachContext::new_mmio(
            &mut vmm,
            event_manager,
            &_shm_manager,
            intc.clone(),
            device_index,
            #[cfg(target_os = "macos")]
            Some(_sender.clone()),
        );
        device.attach(&mut ctx)?;
    }

    // Kept outside VsockAttach/NetAttach rather than routed through
    // AttachContext::append_kernel_cmdline, which only logs on failure: a
    // full kernel cmdline buffer must still fail the boot here, matching
    // the original attach_unixsock_vsock_device/attach_net_devices behavior.
    if vm_resources.vsock.get().is_some() {
        let tsi_flags = vm_resources.vsock.tsi_flags();
        if tsi_flags.contains(TsiFlags::HIJACK_INET) {
            vmm.kernel_cmdline.insert_str("tsi_hijack")?;
        }
        if tsi_flags.contains(TsiFlags::HIJACK_UNIX) {
            vmm.kernel_cmdline.insert_str("tsi_hijack_unix")?;
        }
    }

    #[cfg(feature = "net")]
    if vm_resources.dhcp_client {
        vmm.kernel_cmdline.insert_str("KRUN_DHCP=1")?;
    }

    if let Some(s) = &vm_resources.kernel_cmdline.epilog {
        vmm.kernel_cmdline.insert_str(s).unwrap();
    };

    // Write the kernel command line to guest memory. This is x86_64 specific, since on
    // aarch64 the command line will be specified through the FDT.
    #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
    load_cmdline(&vmm)?;

    vmm.configure_system(
        vcpus.as_slice(),
        &intc,
        &payload_config.initrd_config,
        &vm_resources.smbios_oem_strings,
        payload_config.pvh,
    )
    .map_err(StartMicrovmError::Internal)?;

    #[cfg(feature = "tee")]
    finalize_tee_vm(&mut vmm, tee_state)?;

    vmm.start_vcpus(vcpus)
        .map_err(StartMicrovmError::Internal)?;

    // Clippy thinks we don't need Arc<Mutex<...
    // but we don't want to change the event_manager interface
    #[allow(clippy::arc_with_non_send_sync)]
    let vmm = Arc::new(Mutex::new(vmm));
    event_manager
        .add_subscriber(vmm.clone())
        .map_err(StartMicrovmError::RegisterEvent)?;

    Ok(vmm)
}

// ---------------------------------------------------------------------------
// AttachDevice — converges every v1 device kind onto the same AttachContext
// abstraction the typed API already uses, instead of hand-rolling
// attach_mmio_device calls per device kind.
// ---------------------------------------------------------------------------

trait AttachDevice {
    /// Index passed to `AttachContext::new_mmio`. Only meaningful for fs
    /// devices, whose SHM region is keyed by their position within the fs
    /// list specifically (see `ShmManager::fs_region`), not by a global
    /// position across all attached devices.
    fn device_index(&self) -> usize {
        0
    }

    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), StartMicrovmError>;
}

/// Builds every device the old v1 boot path attaches, in the same order
/// `build_microvm` always has: balloon, then rng (unless a vhost-user rng
/// device covers it), then consoles, gpu, input, fs, block, vsock, net.
fn collect_devices(
    vm_resources: &VmResources,
    #[cfg_attr(any(feature = "tee", feature = "aws-nitro"), allow(unused_variables))]
    exit_code: Arc<AtomicI32>,
) -> Vec<Box<dyn AttachDevice>> {
    let mut devices: Vec<Box<dyn AttachDevice>> = Vec::new();

    #[cfg(not(feature = "tee"))]
    devices.push(Box::new(BalloonAttach));

    #[cfg(not(feature = "tee"))]
    {
        #[cfg(all(feature = "vhost-user", target_os = "linux"))]
        {
            const VIRTIO_ID_RNG: u32 = 4;
            for config in &vm_resources.vhost_user_devices {
                devices.push(Box::new(VhostUserAttach {
                    config: config.clone(),
                }));
            }

            let has_vhost_user_rng = vm_resources
                .vhost_user_devices
                .iter()
                .any(|dev| dev.device_type == VIRTIO_ID_RNG);

            if !has_vhost_user_rng {
                devices.push(Box::new(RngAttach));
            }
        }

        #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
        devices.push(Box::new(RngAttach));
    }

    for (id_number, cfg) in vm_resources.virtio_consoles.iter().enumerate() {
        devices.push(Box::new(ConsoleAttach {
            cfg: Some(cfg.clone()),
            id_number: id_number as u32,
            #[cfg(target_os = "windows")]
            console_output: vm_resources.console_output.clone(),
            #[cfg(target_os = "windows")]
            disable_implicit_console: vm_resources.disable_implicit_console,
        }));
    }

    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    let export_table: Option<ExportTable> = if cfg!(feature = "gpu") {
        Some(Default::default())
    } else {
        None
    };

    #[cfg(feature = "gpu")]
    if let Some(virgl_flags) = vm_resources.gpu_virgl_flags {
        let display_backend = vm_resources
            .display_backend
            .unwrap_or_else(|| NoopDisplayBackend::into_display_backend(None));

        devices.push(Box::new(GpuAttach {
            #[cfg(not(feature = "tee"))]
            export_table: export_table.clone(),
            virgl_flags,
            displays: Box::from(&vm_resources.displays[..]),
            display_backend,
        }));
    }

    #[cfg(feature = "input")]
    for (index, (config_backend, events_backend)) in vm_resources.input_backends.iter().enumerate()
    {
        devices.push(Box::new(InputAttach {
            index,
            config_backend: *config_backend,
            events_backend: *events_backend,
        }));
    }

    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    for (index, config) in vm_resources.fs.iter().enumerate() {
        devices.push(Box::new(FsAttach {
            index,
            config: config.clone(),
            export_table: export_table.clone(),
            exit_code: exit_code.clone(),
        }));
    }

    #[cfg(feature = "blk")]
    for block in vm_resources.block.list.iter() {
        devices.push(Box::new(BlockAttach {
            device: block.clone(),
        }));
    }

    if let Some(vsock) = vm_resources.vsock.get() {
        devices.push(Box::new(VsockAttach {
            device: vsock.clone(),
        }));
    }

    #[cfg(feature = "net")]
    for net_device in vm_resources.net.list.iter() {
        devices.push(Box::new(NetAttach {
            device: net_device.clone(),
        }));
    }

    devices
}

#[cfg(not(feature = "tee"))]
struct BalloonAttach;

#[cfg(not(feature = "tee"))]
impl AttachDevice for BalloonAttach {
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        let balloon = Arc::new(Mutex::new(devices::virtio::Balloon::new().unwrap()));
        ctx.subscribe_events(balloon.clone())
            .map_err(RegisterEvent)?;
        let id = String::from(balloon.lock().unwrap().id());
        ctx.register_mmio_device(&id, balloon)
            .map_err(RegisterBalloonDevice)?;
        Ok(())
    }
}

#[cfg(not(feature = "tee"))]
struct RngAttach;

#[cfg(not(feature = "tee"))]
impl AttachDevice for RngAttach {
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        let rng = Arc::new(Mutex::new(devices::virtio::Rng::new().unwrap()));
        ctx.subscribe_events(rng.clone()).map_err(RegisterEvent)?;
        let id = String::from(rng.lock().unwrap().id());
        ctx.register_mmio_device(&id, rng)
            .map_err(RegisterRngDevice)?;
        Ok(())
    }
}

#[cfg(all(feature = "vhost-user", target_os = "linux"))]
struct VhostUserAttach {
    config: VhostUserDeviceConfig,
}

#[cfg(all(feature = "vhost-user", target_os = "linux"))]
impl AttachDevice for VhostUserAttach {
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        let device_config = self.config;
        let device_name = device_config
            .name
            .clone()
            .unwrap_or_else(|| format!("vhost-user-{}", device_config.device_type));

        let device = Arc::new(Mutex::new(
            devices::virtio::VhostUserDevice::new(
                &device_config.socket_path,
                device_config.device_type,
                device_name.clone(),
                device_config.num_queues,
                &device_config.queue_sizes,
            )
            .map_err(|e| {
                RegisterVhostUserDevice(vmm::device_manager::mmio::Error::VhostUserDevice(e))
            })?,
        ));

        ctx.subscribe_events(device.clone())
            .map_err(RegisterEvent)?;
        ctx.register_mmio_device(&device_name, device)
            .map_err(RegisterVhostUserDevice)?;
        Ok(())
    }
}

struct ConsoleAttach {
    cfg: Option<VirtioConsoleConfigMode>,
    id_number: u32,
    #[cfg(target_os = "windows")]
    console_output: Option<PathBuf>,
    #[cfg(target_os = "windows")]
    disable_implicit_console: bool,
}

impl AttachDevice for ConsoleAttach {
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        let ports = match &self.cfg {
            None => autoconfigure_console_ports(ctx, &self, None)?,
            Some(VirtioConsoleConfigMode::Autoconfigure(autocfg)) => {
                autoconfigure_console_ports(ctx, &self, Some(autocfg))?
            }
            Some(VirtioConsoleConfigMode::Explicit(ports)) => create_explicit_ports(ctx, ports)?,
        };

        let console = Arc::new(Mutex::new(devices::virtio::Console::new(ports).unwrap()));

        ctx.push_exit_observer(console.clone());
        ctx.subscribe_events(console.clone())
            .map_err(RegisterEvent)?;

        #[cfg(target_os = "linux")]
        ctx.register_sigwinch(console.lock().unwrap().get_sigwinch_fd())
            .map_err(RegisterFsSigwinch)?;

        ctx.register_mmio_device(&format!("hvc{}", self.id_number), console)
            .map_err(RegisterConsoleDevice)?;

        Ok(())
    }
}

#[cfg(unix)]
fn autoconfigure_console_ports(
    ctx: &mut AttachContext,
    _console: &ConsoleAttach,
    cfg: Option<&DefaultVirtioConsoleConfig>,
) -> std::result::Result<Vec<PortDescription>, StartMicrovmError> {
    let (input_fd, output_fd, err_fd) = match cfg {
        Some(c) => (c.input_fd, c.output_fd, c.err_fd),
        None => (STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO),
    };
    {
        let input_is_terminal =
            input_fd >= 0 && isatty(unsafe { BorrowedFd::borrow_raw(input_fd) }).unwrap_or(false);
        let output_is_terminal =
            output_fd >= 0 && isatty(unsafe { BorrowedFd::borrow_raw(output_fd) }).unwrap_or(false);
        let error_is_terminal =
            err_fd >= 0 && isatty(unsafe { BorrowedFd::borrow_raw(err_fd) }).unwrap_or(false);

        let term_fd = if input_is_terminal {
            Some(unsafe { BorrowedFd::borrow_raw(input_fd) })
        } else if output_is_terminal {
            Some(unsafe { BorrowedFd::borrow_raw(output_fd) })
        } else if error_is_terminal {
            Some(unsafe { BorrowedFd::borrow_raw(err_fd) })
        } else {
            None
        };

        let forwarding_sigint;
        let console_input = if input_is_terminal && input_fd >= 0 {
            forwarding_sigint = false;
            Some(port_io::input_to_raw_fd_dup(input_fd).unwrap())
        } else {
            #[cfg(target_os = "linux")]
            {
                forwarding_sigint = true;
                let sigint_input = port_io::PortInputSigInt::new();
                let sigint_input_fd = sigint_input.sigint_evt().as_raw_fd();
                register_sigint_handler(sigint_input_fd)
                    .map_err(StartMicrovmError::RegisterFsSigwinch)?;
                Some(Box::new(sigint_input) as _)
            }
            #[cfg(not(target_os = "linux"))]
            {
                forwarding_sigint = false;
                Some(port_io::input_empty().unwrap())
            }
        };

        let console_output = if output_is_terminal && output_fd >= 0 {
            Some(port_io::output_to_raw_fd_dup(output_fd).unwrap())
        } else {
            Some(port_io::output_to_log_as_err())
        };

        let terminal_properties = term_fd
            .map(|fd| port_io::term_fd(fd.as_raw_fd()).unwrap())
            .unwrap_or_else(|| port_io::term_fixed_size(0, 0));

        if let Some(term_fd) = term_fd {
            ctx.setup_terminal_raw_mode(term_fd, forwarding_sigint);
        }

        let mut ports = vec![PortDescription::console(
            console_input,
            console_output,
            terminal_properties,
        )];

        if input_fd >= 0 && !input_is_terminal {
            ports.push(PortDescription::input_pipe(
                "krun-stdin",
                port_io::input_to_raw_fd_dup(input_fd).unwrap(),
            ));
        }

        if output_fd >= 0 && !output_is_terminal {
            ports.push(PortDescription::output_pipe(
                "krun-stdout",
                port_io::output_to_raw_fd_dup(output_fd).unwrap(),
            ));
        };

        if err_fd >= 0 && !error_is_terminal {
            ports.push(PortDescription::output_pipe(
                "krun-stderr",
                port_io::output_to_raw_fd_dup(err_fd).unwrap(),
            ));
        }

        Ok(ports)
    }
}

#[cfg(windows)]
fn is_valid_handle(h: *mut core::ffi::c_void) -> bool {
    !h.is_null() && h != INVALID_HANDLE_VALUE
}

#[cfg(target_os = "windows")]
fn autoconfigure_console_ports(
    ctx: &mut AttachContext,
    console: &ConsoleAttach,
    cfg: Option<&DefaultVirtioConsoleConfig>,
) -> std::result::Result<Vec<PortDescription>, StartMicrovmError> {
    use StartMicrovmError::*;

    // The first console (id 0) is the implicit default console.
    let creating_implicit_console = console.id_number == 0;

    let mut console_output_path: Option<PathBuf> = None;
    if let Some(path) = console.console_output.clone() {
        if !console.disable_implicit_console && creating_implicit_console {
            console_output_path = Some(path)
        }
    }

    if let Some(console_output_path) = console_output_path {
        let file = File::create(console_output_path).map_err(OpenConsoleFile)?;
        // Manually emulate our Legacy behavior: In the case of output_path we have always used the
        // stdin to determine the console size
        let stdin_h = unsafe { BorrowedHandle::borrow_raw(GetStdHandle(STD_INPUT_HANDLE)) };
        let term_h = if stdin_h.is_terminal() {
            port_io::term_handle(stdin_h.as_raw_handle()).unwrap()
        } else {
            port_io::term_fixed_size(0, 0)
        };
        Ok(vec![PortDescription::console(
            Some(port_io::input_empty().unwrap()),
            Some(port_io::output_file(file).unwrap()),
            term_h,
        )])
    } else {
        let (input_h, output_h, err_h) = match cfg {
            Some(c) => (
                c.input_handle.as_raw_handle(),
                c.output_handle.as_raw_handle(),
                c.err_handle.as_raw_handle(),
            ),
            None => unsafe {
                (
                    GetStdHandle(STD_INPUT_HANDLE),
                    GetStdHandle(STD_OUTPUT_HANDLE),
                    GetStdHandle(STD_ERROR_HANDLE),
                )
            },
        };
        let input_is_terminal = (unsafe { BorrowedHandle::borrow_raw(input_h) }).is_terminal();
        let output_is_terminal = (unsafe { BorrowedHandle::borrow_raw(output_h) }).is_terminal();
        let error_is_terminal = (unsafe { BorrowedHandle::borrow_raw(err_h) }).is_terminal();

        let term_h = if input_is_terminal {
            Some(SendHandle::new(input_h))
        } else if output_is_terminal {
            Some(SendHandle::new(output_h))
        } else if error_is_terminal {
            Some(SendHandle::new(err_h))
        } else {
            None
        };

        let forwarding_sigint = false;
        let console_input = if input_is_terminal {
            Some(port_io::input_to_handle_dup(input_h).unwrap())
        } else {
            Some(port_io::input_empty().unwrap())
        };

        let console_output = if output_is_terminal {
            Some(port_io::output_to_handle_dup(output_h).unwrap())
        } else {
            Some(port_io::output_to_log_as_err())
        };

        let terminal_properties = term_h
            .map(|h| port_io::term_handle(h.as_raw_handle()).unwrap())
            .unwrap_or_else(|| port_io::term_fixed_size(0, 0));

        if let Some(term_h) = term_h {
            ctx.setup_terminal_raw_mode(term_h, forwarding_sigint);
        }

        let mut ports = vec![PortDescription::console(
            console_input,
            console_output,
            terminal_properties,
        )];

        if is_valid_handle(input_h) && !input_is_terminal {
            ports.push(PortDescription::input_pipe(
                "krun-stdin",
                port_io::input_to_handle_dup(input_h).unwrap(),
            ));
        }

        if is_valid_handle(output_h) && !output_is_terminal {
            ports.push(PortDescription::output_pipe(
                "krun-stdout",
                port_io::output_to_handle_dup(output_h).unwrap(),
            ));
        };

        if is_valid_handle(err_h) && !error_is_terminal {
            ports.push(PortDescription::output_pipe(
                "krun-stderr",
                port_io::output_to_handle_dup(err_h).unwrap(),
            ));
        }

        Ok(ports)
    }
}

#[cfg(unix)]
fn create_explicit_ports(
    ctx: &mut AttachContext,
    port_configs: &[PortConfig],
) -> std::result::Result<Vec<PortDescription>, StartMicrovmError> {
    let mut ports = Vec::with_capacity(port_configs.len());

    for port_cfg in port_configs {
        let port_desc = match port_cfg {
            PortConfig::Tty { name, tty_fd } => {
                assert!(*tty_fd > 0, "PortConfig::Tty must have a valid tty_fd");
                let term_fd = unsafe { BorrowedFd::borrow_raw(*tty_fd) };
                ctx.setup_terminal_raw_mode(term_fd, false);

                PortDescription {
                    name: name.clone().into(),
                    input: Some(port_io::input_to_raw_fd_dup(*tty_fd).unwrap()),
                    output: Some(port_io::output_to_raw_fd_dup(*tty_fd).unwrap()),
                    terminal: Some(port_io::term_fd(*tty_fd).unwrap()),
                }
            }
            PortConfig::InOut {
                name,
                input_fd,
                output_fd,
            } => PortDescription {
                name: name.clone().into(),
                input: if *input_fd < 0 {
                    None
                } else {
                    Some(port_io::input_to_raw_fd_dup(*input_fd).unwrap())
                },
                output: if *output_fd < 0 {
                    None
                } else {
                    Some(port_io::output_to_raw_fd_dup(*output_fd).unwrap())
                },
                terminal: None,
            },
        };

        ports.push(port_desc);
    }

    Ok(ports)
}

#[cfg(target_os = "windows")]
fn create_explicit_ports(
    ctx: &mut AttachContext,
    port_configs: &[PortConfig],
) -> std::result::Result<Vec<PortDescription>, StartMicrovmError> {
    let mut ports = Vec::with_capacity(port_configs.len());

    for port_cfg in port_configs {
        let port_desc = match port_cfg {
            PortConfig::Tty { name, tty_handle } => {
                assert!(
                    is_valid_handle(tty_handle.as_raw_handle()),
                    "PortConfig::Tty must have a valid tty_handle"
                );
                let term_h = SendHandle::new(tty_handle.as_raw_handle());
                ctx.setup_terminal_raw_mode(term_h, false);

                PortDescription {
                    name: name.clone().into(),
                    input: Some(port_io::input_to_handle_dup(tty_handle.as_raw_handle()).unwrap()),
                    output: Some(
                        port_io::output_to_handle_dup(tty_handle.as_raw_handle()).unwrap(),
                    ),
                    terminal: Some(port_io::term_handle(tty_handle.as_raw_handle()).unwrap()),
                }
            }
            PortConfig::InOut {
                name,
                input_handle,
                output_handle,
            } => PortDescription {
                name: name.clone().into(),
                input: if !is_valid_handle(input_handle.as_raw_handle()) {
                    None
                } else {
                    Some(port_io::input_to_handle_dup(input_handle.as_raw_handle()).unwrap())
                },
                output: if !is_valid_handle(output_handle.as_raw_handle()) {
                    None
                } else {
                    Some(port_io::output_to_handle_dup(output_handle.as_raw_handle()).unwrap())
                },
                terminal: None,
            },
        };

        ports.push(port_desc);
    }

    Ok(ports)
}

#[cfg(feature = "gpu")]
struct GpuAttach {
    #[cfg(not(feature = "tee"))]
    export_table: Option<ExportTable>,
    virgl_flags: u32,
    displays: Box<[DisplayInfo]>,
    display_backend: DisplayBackend<'static>,
}

#[cfg(feature = "gpu")]
impl AttachDevice for GpuAttach {
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        let gpu = Arc::new(Mutex::new(
            devices::virtio::Gpu::new(
                self.virgl_flags,
                self.displays,
                self.display_backend,
                #[cfg(target_os = "macos")]
                ctx.map_sender().expect("gpu device requires a map sender"),
            )
            .unwrap(),
        ));

        let id = String::from(gpu.lock().unwrap().id());

        if let Some(region) = ctx.resolved_gpu_shm_region() {
            gpu.lock().unwrap().set_shm_region(region.into());
        }

        #[cfg(not(feature = "tee"))]
        if let Some(export_table) = self.export_table {
            gpu.lock().unwrap().set_export_table(export_table);
        }

        ctx.register_mmio_device(&id, gpu)
            .map_err(RegisterGpuDevice)?;

        Ok(())
    }
}

#[cfg(feature = "input")]
struct InputAttach {
    index: usize,
    config_backend: krun_input::InputConfigBackend<'static>,
    events_backend: krun_input::InputEventProviderBackend<'static>,
}

#[cfg(feature = "input")]
impl AttachDevice for InputAttach {
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), StartMicrovmError> {
        let input_device = Arc::new(Mutex::new(
            devices::virtio::input::Input::new(self.config_backend, self.events_backend).unwrap(),
        ));
        let id = format!("input{}", self.index);
        ctx.register_mmio_device(&id, input_device)
            .map_err(StartMicrovmError::RegisterInputDevice)?;
        Ok(())
    }
}

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
struct FsAttach {
    index: usize,
    config: FsDeviceConfig,
    export_table: Option<ExportTable>,
    exit_code: Arc<AtomicI32>,
}

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
impl AttachDevice for FsAttach {
    fn device_index(&self) -> usize {
        self.index
    }

    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        let fs = Arc::new(Mutex::new(
            devices::virtio::Fs::new(
                self.config.fs_id.clone(),
                PermissionSemantics::LinuxComplete,
                self.config.shared_dir.clone(),
                self.exit_code,
                self.config.read_only,
                self.config.virtual_entries.clone(),
            )
            .unwrap(),
        ));

        let id = format!("{}{}", String::from(fs.lock().unwrap().id()), self.index);

        if let Some(region) = ctx.resolved_shm_region() {
            fs.lock().unwrap().set_shm_region(region.into());
        }

        if let Some(export_table) = self.export_table {
            fs.lock().unwrap().set_export_table(export_table);
        }

        #[cfg(target_os = "macos")]
        fs.lock()
            .unwrap()
            .set_map_sender(ctx.map_sender().expect("fs device requires a map sender"));

        ctx.register_mmio_device(&id, fs)
            .map_err(RegisterFsDevice)?;

        Ok(())
    }
}

#[cfg(feature = "blk")]
struct BlockAttach {
    device: Arc<Mutex<devices::virtio::Block>>,
}

#[cfg(feature = "blk")]
impl AttachDevice for BlockAttach {
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), StartMicrovmError> {
        let id = String::from(self.device.lock().unwrap().id());
        ctx.register_mmio_device(&id, self.device)
            .map_err(StartMicrovmError::RegisterBlockDevice)?;
        Ok(())
    }
}

struct VsockAttach {
    device: Arc<Mutex<Vsock>>,
}

impl AttachDevice for VsockAttach {
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        ctx.subscribe_events(self.device.clone())
            .map_err(RegisterEvent)?;
        let id = String::from(self.device.lock().unwrap().id());
        ctx.register_mmio_device(&id, self.device)
            .map_err(RegisterVsockDevice)?;
        Ok(())
    }
}

#[cfg(feature = "net")]
struct NetAttach {
    device: Arc<Mutex<devices::virtio::Net>>,
}

#[cfg(feature = "net")]
impl AttachDevice for NetAttach {
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), StartMicrovmError> {
        let id = String::from(self.device.lock().unwrap().id());
        ctx.register_mmio_device(&id, self.device)
            .map_err(StartMicrovmError::RegisterNetDevice)?;
        Ok(())
    }
}
