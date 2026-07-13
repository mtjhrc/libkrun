pub mod devices;
pub mod error;
pub mod logging;
pub mod payload;
pub mod vmm_builder;

#[cfg(feature = "blk")]
pub use devices::BlockDevice;
pub use devices::{
    AttachContext, AttachDevice, BalloonDevice, ConsoleBuilder, ConsoleDevice, DeviceManager,
    DeviceRequirements, FsDevice, FsOverlay, MmioDeviceManager, ResolvedShmRegion, RngDevice,
    VsockDevice,
};
pub use error::{DetailedError, Error};
pub use logging::{LogLevel, LogStyle, LogTarget, init_log};
pub use payload::{KernelFormat, Payload};
pub use vmm_builder::{Vmm, VmmBuilder};

// Re-export from the external `devices` (krun-devices) crate.
// Can't use `devices::` here because `pub mod devices` above shadows it.
pub use crate::reexports::TsiFlags;
#[cfg(feature = "net")]
pub use crate::reexports::VirtioNetBackend;
pub use crate::reexports::port_io;

ffier::library_definition!("krun", library_tag = 1,
    primitives_prefix = "krun",
    crate::api::error::Error = 1,
    crate::api::devices::MmioDeviceManager<'_> = 2,
    crate::api::devices::FsDevice<'_> = 3,
    crate::api::devices::ConsoleDevice<'_> = 4,
    crate::api::devices::ConsoleBuilder<'_> = 5,
    crate::api::devices::FsOverlay = 6,
    crate::api::payload::Payload = 8,
    crate::api::vmm_builder::VmmBuilder<'_> = 10,
    crate::api::vmm_builder::Vmm<'_> = 11,
    crate::api::devices::BalloonDevice = 14,
    crate::api::devices::AttachDevice for crate::api::devices::FsDevice,
    crate::api::devices::AttachDevice for crate::api::devices::ConsoleDevice,
    crate::api::devices::RngDevice = 15,
    crate::api::devices::VsockDevice = 16,
    #[cfg(feature = "blk")]
    crate::api::devices::BlockDevice = 17,
    #[cfg(feature = "blk")]
    crate::api::devices::AttachDevice for crate::api::devices::BlockDevice,
    crate::api::devices::AttachDevice for crate::api::devices::BalloonDevice,
    crate::api::devices::AttachDevice for crate::api::devices::RngDevice,
    crate::api::devices::AttachDevice for crate::api::devices::VsockDevice,
    trait ffier::builtins::PushStr = 12,
    trait ffier::builtins::Error = 13,
    Error for crate::api::error::Error,
    enum crate::api::payload::KernelFormat,
    enum crate::api::logging::LogLevel,
    enum crate::api::logging::LogStyle,
    enum crate::api::logging::LogTarget,
    fn crate::api::logging::init_log,
);
