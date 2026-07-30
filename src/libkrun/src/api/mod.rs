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
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use device_builders::FsDevice;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use device_builders::FsOverlay;
#[cfg(not(feature = "tee"))]
pub use device_builders::RngDevice;
pub use device_builders::{
    AttachContext, AttachDevice, ConsoleBuilder, ConsoleDevice, DeviceManager, DeviceRequirements,
    MmioDeviceManager, ResolvedShmRegion, TsiFlags, VsockDevice,
};
pub use error::VmmError;
pub use logging::{LogLevel, LogOptions, LogStyle, init_log};
pub use payload::{KernelFormat, Payload};
pub use vmm_builder::{Vmm, VmmBuilder, check_nested_virt};

#[cfg(feature = "net")]
pub use devices::virtio::net::device::VirtioNetBackend;
pub use devices::virtio::port_io;
