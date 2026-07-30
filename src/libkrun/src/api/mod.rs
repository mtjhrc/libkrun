pub mod device_builders;
pub mod error;
pub mod logging;
pub mod payload;
pub mod vmm_builder;

#[cfg(feature = "aws-nitro")]
pub use crate::NitroConfig;
#[cfg(not(feature = "tee"))]
pub use device_builders::BalloonDevice;
#[cfg(feature = "blk")]
pub use device_builders::BlockDevice;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use device_builders::FsDevice;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use device_builders::FsOverlay;
#[cfg(feature = "input")]
pub use device_builders::InputDevice;
#[cfg(feature = "net")]
pub use device_builders::NetDevice;
#[cfg(not(feature = "tee"))]
pub use device_builders::RngDevice;
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
pub use device_builders::VhostUserDevice;
pub use device_builders::{
    AttachContext, AttachDevice, ConsoleBuilder, ConsoleDevice, DeviceManager, DeviceRequirements,
    MmioDeviceManager, ResolvedShmRegion, VsockDevice,
};
#[cfg(feature = "gpu")]
pub use device_builders::{DisplayBackend, DisplayInfoBuilder, GpuDevice, VirglRendererFlags};
pub use error::Error;
pub use logging::{LogLevel, LogOptions, LogStyle, init_log};
pub use payload::{KernelFormat, Payload};
pub use vmm_builder::{Vmm, VmmBuilder};

pub use devices::virtio::TsiFlags;
#[cfg(feature = "net")]
pub use devices::virtio::net::device::VirtioNetBackend;
pub use devices::virtio::port_io;
