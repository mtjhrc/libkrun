use std::marker::PhantomData;
#[cfg(unix)]
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

use crossbeam_channel::unbounded;
use polly::event_manager::EventManager;
use vmm::Vmm as InnerVmm;
use vmm::resources::VmResources;
use vmm::vmm_config::machine_config::VmConfig;

use super::device_builders::{DeviceManager, MmioDeviceManager};
use super::error::{DetailedError, Error};
use super::payload::Payload;

pub struct VmmBuilder<'a> {
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    payload: Option<Payload>,
    device_manager: Option<Box<dyn DeviceManager<'a> + 'a>>,
    #[cfg(unix)]
    serial_input_fd: Option<RawFd>,
    kernel_console: Option<String>,
    nested_virt: bool,
    split_irqchip: bool,
    smbios_oem_strings: Vec<String>,
}

impl Default for VmmBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> VmmBuilder<'a> {
    pub fn new() -> Self {
        VmmBuilder {
            vcpus: None,
            ram_mib: None,
            payload: None,
            device_manager: None,
            #[cfg(unix)]
            serial_input_fd: None,
            kernel_console: None,
            nested_virt: false,
            split_irqchip: false,
            smbios_oem_strings: Vec::new(),
        }
    }

    pub fn vcpus(mut self, count: u8) -> Result<Self, Error> {
        if count == 0 {
            return Err(Error::OutOfRange());
        }
        self.vcpus = Some(count);
        Ok(self)
    }

    pub fn ram_mib(mut self, mib: u32) -> Result<Self, Error> {
        if mib == 0 {
            return Err(Error::OutOfRange());
        }
        self.ram_mib = Some(mib);
        Ok(self)
    }

    pub fn payload(mut self, payload: Payload) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn devices(mut self, devices: MmioDeviceManager<'a>) -> Self {
        self.device_manager = Some(Box::new(devices));
        self
    }

    pub fn set_kernel_console(mut self, console: &str) -> Self {
        self.kernel_console = Some(console.to_string());
        self
    }

    /// Set the fd used as input for the legacy serial console (e.g. a pipe read end).
    ///
    /// When set, a serial console device is created with this fd as input and the
    /// corresponding output duplicated to stdout. This is required for FreeBSD guests
    /// which use the legacy serial console instead of the virtio console.
    #[cfg(unix)]
    pub fn serial_input_fd(mut self, fd: i32) -> Self {
        self.serial_input_fd = Some(fd);
        self
    }

    pub fn nested_virt(mut self, enabled: bool) -> Self {
        self.nested_virt = enabled;
        self
    }

    pub fn split_irqchip(mut self, enabled: bool) -> Result<Self, Error> {
        if enabled && !cfg!(target_arch = "x86_64") {
            return Err(Error::InvalidParam());
        }
        self.split_irqchip = enabled;
        Ok(self)
    }

    pub fn add_smbios_oem_string(mut self, s: &str) -> Self {
        self.smbios_oem_strings.push(s.to_string());
        self
    }

    pub fn build(self) -> Result<Vmm<'a>, Error> {
        build_vm(self).map_err(|e| {
            log::error!("{e}");
            e.code
        })
    }
}

enum VmmInner {
    Vmm {
        #[allow(dead_code)]
        vmm: Arc<Mutex<InnerVmm>>,
        event_manager: EventManager,
        #[allow(dead_code)]
        _worker_sender: crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
    },
    #[cfg(feature = "aws-nitro")]
    Nitro(aws_nitro::enclave::NitroEnclave),
}

pub struct Vmm<'a> {
    inner: VmmInner,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> Vmm<'a> {
    pub fn run(self) {
        match self.inner {
            VmmInner::Vmm { mut event_manager, .. } => loop {
                if let Err(e) = event_manager.run() {
                    log::error!("fatal event loop error: {e:?}");
                    return;
                }
            },
            #[cfg(feature = "aws-nitro")]
            VmmInner::Nitro(enclave) => {
                let exit_code = enclave.run().unwrap_or_else(|e| {
                    log::error!("Error running nitro enclave: {e}");
                    -libc::EINVAL
                });
                unsafe { libc::_exit(exit_code) }
            }
        }
    }
}

fn build_vm(builder_cfg: VmmBuilder<'_>) -> Result<Vmm<'_>, DetailedError> {
    use super::payload::PayloadKind;

    let vcpus_count = builder_cfg
        .vcpus
        .ok_or_else(|| DetailedError::new(Error::MissingConfig(), "vcpus not set"))?;
    let ram_mib = builder_cfg
        .ram_mib
        .ok_or_else(|| DetailedError::new(Error::MissingConfig(), "ram_mib not set"))?;
    let payload = builder_cfg
        .payload
        .ok_or_else(|| DetailedError::new(Error::MissingConfig(), "payload not set"))?;

    #[cfg(feature = "aws-nitro")]
    if let PayloadKind::Nitro(nitro_config) = payload.kind {
        let enclave = nitro_config
            .into_enclave(vcpus_count, ram_mib as usize)
            .map_err(|e| DetailedError::new(Error::MissingConfig(), e))?;
        return Ok(Vmm {
            inner: VmmInner::Nitro(enclave),
            _lifetime: PhantomData,
        });
    }

    let device_manager = builder_cfg.device_manager.ok_or_else(|| {
        DetailedError::new(
            Error::MissingConfig(),
            "no device manager set (call .devices())",
        )
    })?;

    let mut vm_resources = VmResources::default();
    vm_resources
        .set_vm_config(&VmConfig {
            vcpu_count: Some(vcpus_count),
            mem_size_mib: Some(ram_mib as usize),
            ht_enabled: Some(false),
            cpu_template: None,
        })
        .map_err(|e| DetailedError::new(Error::InvalidParam(), format!("{e:?}")))?;

    match payload.kind {
        PayloadKind::Kernel { bundle } => {
            vm_resources.kernel_bundle = Some(bundle);
        }
        PayloadKind::External { kernel } => {
            vm_resources.external_kernel = Some(kernel);
        }
        PayloadKind::Firmware { path } => {
            vm_resources.set_firmware_config(vmm::vmm_config::firmware::FirmwareConfig { path });
        }
        #[cfg(feature = "tee")]
        PayloadKind::Tee {
            bundle,
            qboot_bundle,
            initrd_bundle,
            tee_config_path,
        } => {
            vm_resources.kernel_bundle = Some(bundle);
            vm_resources
                .set_qboot_bundle(qboot_bundle)
                .map_err(|e| DetailedError::new(Error::InvalidParam(), format!("{e}")))?;
            vm_resources
                .set_initrd_bundle(initrd_bundle)
                .map_err(|e| DetailedError::new(Error::InvalidParam(), format!("{e}")))?;
            vm_resources
                .set_tee_config(tee_config_path)
                .map_err(|e| DetailedError::new(Error::InvalidParam(), format!("{e:?}")))?;
        }
        #[cfg(feature = "aws-nitro")]
        PayloadKind::Nitro(_) => unreachable!("handled above"),
    }

    vm_resources.kernel_cmdline.prolog = Some(payload.cmdline);

    vm_resources.nested_enabled = builder_cfg.nested_virt;
    vm_resources.split_irqchip = builder_cfg.split_irqchip;
    if !builder_cfg.smbios_oem_strings.is_empty() {
        vm_resources.smbios_oem_strings = Some(builder_cfg.smbios_oem_strings);
    }

    if let Some(console) = builder_cfg.kernel_console {
        vm_resources.kernel_console = Some(console);
    }

    #[cfg(unix)]
    if let Some(serial_fd) = builder_cfg.serial_input_fd {
        use vmm::resources::SerialConsoleConfig;
        vm_resources.serial_consoles.push(SerialConsoleConfig {
            input_fd: serial_fd,
            output_fd: unsafe { libc::dup(serial_fd) },
        });
    }

    let mut event_manager = EventManager::new()
        .map_err(|e| DetailedError::new(Error::Internal(), format!("{e:?}")))?;

    let (sender, _receiver) = unbounded();

    let inner = crate::builder::build_microvm(
        &vm_resources,
        &mut event_manager,
        None,
        sender.clone(),
        device_manager,
    )
    .map_err(|e| DetailedError::new(Error::BootError(), format!("{e:?}")))?;

    Ok(Vmm {
        inner: VmmInner::Vmm {
            vmm: inner,
            event_manager,
            _worker_sender: sender,
        },
        _lifetime: PhantomData,
    })
}
