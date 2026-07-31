pub mod device_builders;
pub mod error;
pub mod logging;
pub mod payload;
pub mod vmm_builder;

#[allow(unused_macros)]
macro_rules! export_bitflags {
    ($(#[cfg($($cfg:tt)*)])? bitflags::bitflags! { $($body:tt)* }) => {
        $(#[cfg($($cfg)*)])?
        bitflags::bitflags! { $($body)* }
    };
}
pub(crate) use export_bitflags;

#[cfg(feature = "aws-nitro")]
pub use crate::NitroConfig;
#[cfg(not(feature = "tee"))]
pub use device_builders::BalloonDevice;
#[cfg(feature = "blk")]
pub use device_builders::BlockDevice;
#[cfg(feature = "blk")]
pub use devices::virtio::block::{DiskFormat, SyncMode};
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use device_builders::FsDevice;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use device_builders::FsOverlay;
#[cfg(feature = "input")]
pub use device_builders::InputDevice;
#[cfg(feature = "net")]
pub use device_builders::NetDevice;
#[cfg(feature = "net")]
pub use device_builders::NetFlags;
#[cfg(not(feature = "tee"))]
pub use device_builders::RngDevice;
pub use device_builders::{
    AttachContext, AttachDevice, ConsoleBuilder, ConsoleDevice, DeviceManager, DeviceRequirements,
    MmioDeviceManager, ResolvedShmRegion, TsiFlags, VsockDevice,
};
#[cfg(any(feature = "gpu", feature = "vhost-user"))]
pub use device_builders::{DisplayBackend, DisplayInfoBuilder};
#[cfg(feature = "gpu")]
pub use device_builders::{GpuDevice, VirglRendererFlags};
pub use error::VmmError;
pub use logging::{LogLevel, LogOptions, LogStyle, init_log};
pub use payload::{KernelFormat, Payload};
pub use vmm_builder::{Vmm, VmmBuilder, check_nested_virt};

#[cfg(feature = "net")]
pub use devices::virtio::net::device::VirtioNetBackend;
pub use devices::virtio::port_io;
