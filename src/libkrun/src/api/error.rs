#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid parameter")]
    InvalidParam(),

    #[error("duplicate device")]
    DuplicateDevice(),

    #[error("device limit exceeded")]
    DeviceLimitExceeded(),

    #[error("missing required configuration: {0}")]
    MissingConfig(String),

    #[error("conflicting configuration")]
    ConflictingConfig(),

    #[error("value out of range")]
    OutOfRange(),

    #[error("file not found")]
    FileNotFound(),

    #[error("permission denied")]
    PermissionDenied(),

    #[error("resource allocation failed")]
    ResourceAlloc(),

    #[error("bad file descriptor")]
    BadFd(),

    #[error("backend unavailable")]
    BackendUnavailable(),

    #[error("feature not enabled in this build")]
    FeatureDisabled(),

    #[error("disk format error")]
    DiskFormatError(),

    #[error("VM already started")]
    AlreadyStarted(),

    #[error("validation failed")]
    ValidationFailed(),

    #[error("hypervisor error")]
    HypervisorError(),

    #[error("boot error: {0}")]
    BootError(String),

    #[error("internal error: {0}")]
    Internal(String),
}
