#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use std::ffi::CString;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use std::marker::PhantomData;
use std::os::fd::{BorrowedFd, RawFd};
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};

use devices::legacy::IrqChip;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::fs::virtual_entry::{VirtualDirEntry, VirtualEntry, VirtualEntryContent};
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::passthrough::PermissionSemantics;
use devices::virtio::{VirtioDevice, VirtioShmRegion, VmmExitObserver};
use polly::event_manager::{EventManager, Subscriber};
use vm_memory::GuestMemoryMmap;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use vm_memory::{Address, GuestMemory};
use vmm::Vmm;
use vmm::builder::{attach_mmio_device, setup_terminal_raw_mode};
use vmm::device_manager::shm::ShmManager;

use super::error::Error;

/// Requirements a device declares before the VM's memory layout is fixed.
/// `#[non_exhaustive]` allows adding new fields in minor releases.
#[derive(Default)]
#[non_exhaustive]
pub struct DeviceRequirements {
    /// Size of shared memory (DAX) window needed, if any.
    pub shm_size: Option<usize>,
    // TODO: unify fs and gpu shm into a single SHM abstraction
    /// GPU shared memory size, if this is a GPU device.
    #[cfg(feature = "gpu")]
    pub gpu_shm: Option<usize>,
    /// Whether this device needs process-shareable memory (vhost-user).
    pub process_shareable_memory: bool,
}

/// Context provided to devices during attachment.
///
/// This struct wraps internal VMM state and exposes a stable set of capability
/// methods. Adding new methods is a non-breaking (semver-minor) change.
/// Devices call these methods in their [`AttachDevice::attach`] implementation
/// instead of interacting with VMM internals directly.
#[allow(clippy::type_complexity)]
pub struct AttachContext<'a> {
    vmm: &'a mut Vmm,
    event_manager: &'a mut EventManager,
    #[allow(dead_code)]
    shm_manager: &'a ShmManager,
    intc: IrqChip,
    device_index: usize,
    register_fn: Box<
        dyn Fn(&mut Vmm, String, IrqChip, Arc<Mutex<dyn VirtioDevice>>) -> Result<(), Error> + 'a,
    >,
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
            register_fn: Box::new(|vmm, id, intc, device| {
                attach_mmio_device(vmm, id, intc, device)
                    .map_err(|e| Error::Internal(format!("{e:?}")))?;
                Ok(())
            }),
            #[cfg(target_os = "macos")]
            map_sender,
        }
    }

    /// Register a virtio device on the transport bus.
    ///
    /// The actual transport (MMIO, future PCIe) is determined by which
    /// [`DeviceManager`] the device was added to.
    pub fn register(
        &mut self,
        id: &str,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<(), Error> {
        (self.register_fn)(self.vmm, id.to_string(), self.intc.clone(), device)
    }

    /// Subscribe a device to the event loop for epoll-based I/O.
    pub fn subscribe_events(
        &mut self,
        subscriber: Arc<Mutex<dyn Subscriber>>,
    ) -> Result<(), Error> {
        self.event_manager
            .add_subscriber(subscriber)
            .map_err(|e| Error::Internal(format!("{e:?}")))
    }

    /// Register a cleanup callback invoked on VM shutdown.
    pub fn push_exit_observer(&mut self, observer: Arc<Mutex<dyn VmmExitObserver>>) {
        self.vmm.exit_observers.push(observer);
    }

    /// The VM's exit code. Devices (e.g. virtiofs) can write to this
    /// to communicate an exit code to the host.
    pub fn exit_code(&self) -> &Arc<AtomicI32> {
        &self.vmm.exit_code
    }

    /// The VM's guest memory map.
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.vmm.guest_memory
    }

    /// The resolved SHM region for the current device index, if one was
    /// allocated based on [`DeviceRequirements::shm_size`].
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    pub fn resolved_shm_region(&self) -> Option<ResolvedShmRegion> {
        self.shm_manager.fs_region(self.device_index).map(|r| {
            let host_addr = self
                .vmm
                .guest_memory
                .get_host_address(r.guest_addr)
                .expect("shm region host address");
            ResolvedShmRegion {
                host_addr: host_addr as u64,
                guest_addr: r.guest_addr.raw_value(),
                size: r.size,
            }
        })
    }

    /// The resolved GPU SHM region, if GPU is enabled and a region was allocated.
    #[cfg(feature = "gpu")]
    pub fn resolved_gpu_shm_region(&self) -> Option<ResolvedShmRegion> {
        self.shm_manager.gpu_region().map(|r| {
            let host_addr = self
                .vmm
                .guest_memory
                .get_host_address(r.guest_addr)
                .expect("gpu shm region host address");
            ResolvedShmRegion {
                host_addr: host_addr as u64,
                guest_addr: r.guest_addr.raw_value(),
                size: r.size,
            }
        })
    }

    /// The index of the current device within its device manager.
    pub fn device_index(&self) -> usize {
        self.device_index
    }

    /// Register a SIGWINCH signal handler that writes to the given fd.
    /// Typically used by the console device.
    #[cfg(target_os = "linux")]
    pub fn register_sigwinch(&mut self, fd: RawFd) -> Result<(), Error> {
        vmm::signal_handler::register_sigwinch_handler(fd)
            .map_err(|e| Error::Internal(format!("{e:?}")))
    }

    /// Set up terminal raw mode for the given fd, registering a cleanup
    /// observer to restore the terminal on VM shutdown.
    pub fn setup_terminal_raw_mode(&mut self, fd: BorrowedFd<'_>) {
        setup_terminal_raw_mode(self.vmm, Some(fd), false);
    }

    /// Get the macOS memory mapping channel sender, if available.
    /// Used by GPU and Fs devices for DAX memory mapping on macOS.
    #[cfg(target_os = "macos")]
    pub fn map_sender(
        &self,
    ) -> Option<crossbeam_channel::Sender<utils::worker_message::WorkerMessage>> {
        self.map_sender.clone()
    }

    /// Append a string to the kernel command line.
    /// Used by devices that need to pass parameters to the guest kernel
    /// (e.g., vsock TSI flags).
    pub fn append_kernel_cmdline(&mut self, s: &str) {
        self.vmm
            .kernel_cmdline
            .insert_str(s)
            .unwrap_or_else(|e| log::error!("failed to append '{s}' to cmdline: {e}"));
    }
}

/// A resolved shared memory region with both host and guest addresses.
///
/// Returned by [`AttachContext::resolved_shm_region`] after guest memory has been
/// created and the SHM region mapped.
pub struct ResolvedShmRegion {
    /// Host virtual address of the start of the SHM region.
    pub host_addr: u64,
    /// Guest physical address of the start of the SHM region.
    pub guest_addr: u64,
    /// Size of the SHM region in bytes.
    pub size: usize,
}

impl From<ResolvedShmRegion> for VirtioShmRegion {
    fn from(r: ResolvedShmRegion) -> Self {
        VirtioShmRegion {
            host_addr: r.host_addr,
            guest_addr: r.guest_addr,
            size: r.size,
        }
    }
}

/// Trait implemented by devices that can be attached to a VM.
///
/// Built-in devices (`FsDevice`, `ConsoleDevice`, etc.) implement this.
/// Future users can implement this for custom virtio devices.
///
/// The [`attach`](AttachDevice::attach) method receives an [`AttachContext`]
/// with all VMM capabilities. Adding new methods to `AttachContext` is a
/// non-breaking change, so the trait signature never needs to change.
pub trait AttachDevice<'a>: Send + 'a {
    /// Declare requirements before guest memory is created.
    fn requirements(&self) -> DeviceRequirements {
        DeviceRequirements::default()
    }

    /// Attach this device to the VM.
    ///
    /// The device should:
    /// 1. Perform any device-specific setup using `ctx` methods
    /// 2. Call [`ctx.register()`](AttachContext::register) to register on the transport bus
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error>;
}

mod sealed {
    pub trait Sealed {}
}

/// A device manager that owns a set of devices and knows how to attach them
/// to a VM using a specific transport (e.g. MMIO, future PCIe).
///
/// This trait is sealed — only libkrun-provided managers can implement it.
/// The seal may be lifted in a future major version.
pub trait DeviceManager<'a>: sealed::Sealed + Send + 'a {
    /// Collect requirements from all devices (called before guest memory creation).
    #[doc(hidden)]
    fn requirements(&self) -> Vec<DeviceRequirements>;

    /// Attach all devices using the given VMM context.
    #[doc(hidden)]
    fn attach_all(
        self: Box<Self>,
        vmm: &mut Vmm,
        event_manager: &mut EventManager,
        shm_manager: &ShmManager,
        intc: IrqChip,
        #[cfg(target_os = "macos")] map_sender: Option<
            crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
        >,
    ) -> Result<(), Error>;
}

/// Device manager using the virtio-mmio transport.
///
/// Devices added to this manager will be registered on the MMIO bus
/// during VM construction.
#[derive(Default)]
pub struct MmioDeviceManager<'a> {
    devices: Vec<Box<dyn AttachDevice<'a> + 'a>>,
}

impl<'a> MmioDeviceManager<'a> {
    /// Create an empty device manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a device to this manager.
    ///
    /// Devices are attached in the order they are added. The device must
    /// implement [`AttachDevice`] — all built-in device types
    /// (`FsDevice`, `ConsoleDevice`, etc.) implement this trait.
    pub fn add(&mut self, device: impl AttachDevice<'a>) -> &mut Self {
        self.devices.push(Box::new(device));
        self
    }
}

impl sealed::Sealed for MmioDeviceManager<'_> {}

impl<'a> DeviceManager<'a> for MmioDeviceManager<'a> {
    fn requirements(&self) -> Vec<DeviceRequirements> {
        self.devices.iter().map(|d| d.requirements()).collect()
    }

    fn attach_all(
        self: Box<Self>,
        vmm: &mut Vmm,
        event_manager: &mut EventManager,
        shm_manager: &ShmManager,
        intc: IrqChip,
        #[cfg(target_os = "macos")] map_sender: Option<
            crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
        >,
    ) -> Result<(), Error> {
        for (i, device) in self.devices.into_iter().enumerate() {
            let mut ctx = AttachContext::new_mmio(
                vmm,
                event_manager,
                shm_manager,
                intc.clone(),
                i,
                #[cfg(target_os = "macos")]
                map_sender.clone(),
            );
            device.attach(&mut ctx)?;
        }
        Ok(())
    }
}

/// A set of virtual filesystem entries to overlay on a virtiofs device.
///
/// Entries are synthetic files/directories that exist only in memory,
/// overlaid on top of the real (or null) host filesystem. They are
/// visible to the guest but do not exist on the host.
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
#[derive(Default)]
pub struct FsOverlay<'a> {
    entries: Vec<VirtualDirEntry<'a>>,
}

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
impl<'a> FsOverlay<'a> {
    /// Create a new empty overlay.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a virtual directory entry.
    ///
    /// `path` may contain `/` separators for nested entries (e.g. `"etc/nested"`).
    /// Intermediate directories must already exist in the overlay.
    pub fn add_dir(&mut self, path: &str, mode: u32) -> Result<(), Error> {
        let entry = VirtualEntry {
            mode,
            one_shot: false,
            content: VirtualEntryContent::Dir {
                children: Vec::new(),
            },
        };
        self.add_at_path(path, entry)
    }

    /// Add a virtual file entry.
    ///
    /// `path` may contain `/` separators for nested entries (e.g. `"etc/nested/file.txt"`).
    /// Intermediate directories must already exist in the overlay.
    pub fn add_file(
        &mut self,
        path: &str,
        data: &'a [u8],
        mode: u32,
        one_shot: bool,
    ) -> Result<(), Error> {
        let entry = VirtualEntry {
            mode,
            one_shot,
            content: VirtualEntryContent::File { data },
        };
        self.add_at_path(path, entry)
    }
}

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
impl<'a> FsOverlay<'a> {
    /// Consume the overlay and return the raw virtual directory entries.
    pub fn into_entries(self) -> Vec<VirtualDirEntry<'a>> {
        self.entries
    }

    fn add_at_path(&mut self, path: &str, entry: VirtualEntry<'a>) -> Result<(), Error> {
        let path = path.strip_prefix('/').unwrap_or(path);
        let components: Vec<&str> = path.split('/').collect();
        let (leaf, parents) = components
            .split_last()
            .ok_or_else(Error::InvalidParam)?;

        if leaf.is_empty() {
            return Err(Error::InvalidParam());
        }
        let leaf_name = CString::new(*leaf).map_err(|_| Error::InvalidParam())?;

        let target = resolve_parent_dirs(&mut self.entries, parents)?;
        target.push(VirtualDirEntry {
            name: leaf_name,
            entry,
        });
        Ok(())
    }
}

/// A virtio-fs (virtiofs) shared filesystem device.
///
/// Exposes a host directory to the guest as a shared filesystem.
/// The `tag` is used by the guest to mount the filesystem
/// (e.g. `mount -t virtiofs /dev/root /mnt`).
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub struct FsDevice<'a> {
    pub(crate) inner: Arc<Mutex<devices::virtio::Fs>>,
    #[allow(dead_code)]
    pub(crate) tag: String,
    pub(crate) shm_size: Option<usize>,
    pub(crate) overlay: Option<FsOverlay<'a>>,
    _lifetime: PhantomData<&'a ()>,
}

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
impl<'a> FsDevice<'a> {
    /// Create a new virtiofs device sharing a host directory.
    ///
    /// # Arguments
    ///
    /// - `tag`: the filesystem tag visible to the guest (e.g. `"/dev/root"`).
    /// - `host_path`: the host directory to share.
    pub fn new(tag: &str, host_path: &str) -> Result<Self, Error> {
        Self::new_inner(tag, Some(host_path.to_string()), false)
    }

    /// Create a read-only virtiofs device sharing a host directory.
    pub fn new_read_only(tag: &str, host_path: &str) -> Result<Self, Error> {
        Self::new_inner(tag, Some(host_path.to_string()), true)
    }

    /// Create a virtiofs device with no host directory (NullFs).
    ///
    /// The guest sees an empty filesystem. Use [`FsOverlay`] to build
    /// virtual entries and [`set_overlay`](Self::set_overlay) to attach
    /// them.
    pub fn new_null(tag: &str) -> Result<Self, Error> {
        Self::new_inner(tag, None, false)
    }

    /// Set a pre-built [`FsOverlay`] on this device.
    ///
    /// The overlay entries are resolved (applied to the underlying
    /// virtiofs device) during [`attach`](AttachDevice::attach).
    pub fn set_overlay(&mut self, overlay: FsOverlay<'a>) {
        self.overlay = Some(overlay);
    }

    /// Set the size of the DAX (direct access) shared memory window.
    ///
    /// When set, the guest can memory-map files from the shared filesystem
    /// directly into its address space, avoiding data copies. If not set,
    /// no DAX window is allocated.
    pub fn set_dax_window_size(&mut self, bytes: u64) {
        self.shm_size = Some(bytes as usize);
    }
}

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
impl<'a> FsDevice<'a> {
    fn new_inner(tag: &str, host_path: Option<String>, read_only: bool) -> Result<Self, Error> {
        let exit_code = Arc::new(AtomicI32::new(i32::MAX));
        let fs = devices::virtio::Fs::new(
            tag.to_string(),
            PermissionSemantics::LinuxComplete,
            host_path,
            exit_code.clone(),
            read_only,
            Vec::new(),
        )
        .map_err(|e| Error::Internal(format!("fs device: {e:?}")))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(fs)),
            tag: tag.to_string(),
            shm_size: None,
            overlay: None,
            _lifetime: PhantomData,
        })
    }
}

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
impl<'a> AttachDevice<'a> for FsDevice<'a> {
    fn requirements(&self) -> DeviceRequirements {
        DeviceRequirements {
            shm_size: self.shm_size,
            ..Default::default()
        }
    }

    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error> {
        {
            let mut fs = self.inner.lock().unwrap();
            // Wire exit code from VMM into the fs device
            fs.set_exit_code(ctx.exit_code().clone());
            // Resolve overlay entries
            if let Some(overlay) = self.overlay {
                // FIXME: The VMM terminates the process on VM exit, so the
                // borrowed overlay data remains valid for the worker lifetime.
                let entries: Vec<VirtualDirEntry<'static>> =
                    unsafe { std::mem::transmute(overlay.into_entries()) };
                for entry in entries {
                    fs.add_virtual_entry(entry);
                }
            }
            // Set up SHM region if allocated
            #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
            if let Some(region) = ctx.resolved_shm_region() {
                fs.set_shm_region(region.into());
            }
        }

        ctx.register(&format!("virtiofs{}", ctx.device_index()), self.inner)
    }
}

/// Walk parent directory components in a virtual entry tree, returning the
/// children vec of the deepest parent.
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
fn resolve_parent_dirs<'a, 'b>(
    entries: &'b mut Vec<VirtualDirEntry<'a>>,
    parents: &[&str],
) -> Result<&'b mut Vec<VirtualDirEntry<'a>>, Error> {
    let mut current = entries;
    for component in parents {
        if component.is_empty() {
            return Err(Error::InvalidParam());
        }
        let dir = current
            .iter_mut()
            .find(|e| e.name.as_c_str().to_bytes() == component.as_bytes())
            .ok_or_else(Error::InvalidParam)?;
        match &mut dir.entry.content {
            VirtualEntryContent::Dir { children } => current = children,
            _ => return Err(Error::InvalidParam()),
        }
    }
    Ok(current)
}
