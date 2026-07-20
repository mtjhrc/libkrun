pub mod devices;
pub mod error;
pub mod logging;
pub mod payload;
pub mod vmm_builder;

pub use devices::{
    AttachContext, AttachDevice, BalloonDevice, ConsoleBuilder, ConsoleDevice, DeviceManager,
    DeviceRequirements, FsDevice, FsOverlay, MmioDeviceManager, ResolvedShmRegion, RngDevice,
};
pub use error::{DetailedError, Error};
pub use logging::{LOG_OPTION_NO_ENV, LogLevel, LogStyle, init_log};
pub use payload::{KernelFormat, Payload};
pub use vmm_builder::{Vmm, VmmBuilder};

ffier::library_definition!("krun", library_tag = 1,
    primitives_prefix = "krun",
    crate::api::error::Error = 1,
    crate::api::devices::MmioDeviceManager<'_> = 2,
    crate::api::devices::FsDevice<'_> = 3,
    crate::api::devices::ConsoleDevice<'_> = 4,
    crate::api::devices::ConsoleBuilder<'_> = 5,
    crate::api::payload::Payload = 8,
    crate::api::vmm_builder::VmmBuilder<'_> = 10,
    crate::api::vmm_builder::Vmm<'_> = 11,
    crate::api::devices::FsOverlay = 14,
    crate::api::devices::BalloonDevice = 15,
    crate::api::devices::AttachDevice for crate::api::devices::FsDevice,
    crate::api::devices::AttachDevice for crate::api::devices::ConsoleDevice,
    crate::api::devices::RngDevice = 16,
    crate::api::devices::AttachDevice for crate::api::devices::BalloonDevice,
    crate::api::devices::AttachDevice for crate::api::devices::RngDevice,
    trait ffier_builtins::PushStr = 12,
    trait ffier_builtins::Error = 13,
    Error for crate::api::error::Error,
    enum crate::api::payload::KernelFormat,
    enum crate::api::logging::LogLevel,
    enum crate::api::logging::LogStyle,
    fn crate::api::logging::init_log,
);
