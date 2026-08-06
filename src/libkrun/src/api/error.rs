#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "ffi", derive(ffier::FfiError))]
#[non_exhaustive]
pub enum Error {
    #[error("invalid parameter")]
    #[cfg_attr(feature = "ffi", ffier(code = 1))]
    InvalidParam(),

    #[error("duplicate device")]
    #[cfg_attr(feature = "ffi", ffier(code = 2))]
    DuplicateDevice(),

    #[error("device limit exceeded")]
    #[cfg_attr(feature = "ffi", ffier(code = 3))]
    DeviceLimitExceeded(),

    #[error("missing required configuration: {0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 4, opaque))]
    MissingConfig(String),

    #[error("conflicting configuration")]
    #[cfg_attr(feature = "ffi", ffier(code = 5))]
    ConflictingConfig(),

    #[error("value out of range")]
    #[cfg_attr(feature = "ffi", ffier(code = 6))]
    OutOfRange(),

    #[error("file not found")]
    #[cfg_attr(feature = "ffi", ffier(code = 7))]
    FileNotFound(),

    #[error("permission denied")]
    #[cfg_attr(feature = "ffi", ffier(code = 8))]
    PermissionDenied(),

    #[error("resource allocation failed")]
    #[cfg_attr(feature = "ffi", ffier(code = 9))]
    ResourceAlloc(),

    #[error("bad file descriptor")]
    #[cfg_attr(feature = "ffi", ffier(code = 10))]
    BadFd(),

    #[error("backend unavailable")]
    #[cfg_attr(feature = "ffi", ffier(code = 11))]
    BackendUnavailable(),

    #[error("feature not enabled in this build")]
    #[cfg_attr(feature = "ffi", ffier(code = 12))]
    FeatureDisabled(),

    #[error("disk format error")]
    #[cfg_attr(feature = "ffi", ffier(code = 13))]
    DiskFormatError(),

    #[error("VM already started")]
    #[cfg_attr(feature = "ffi", ffier(code = 14))]
    AlreadyStarted(),

    #[error("validation failed")]
    #[cfg_attr(feature = "ffi", ffier(code = 15))]
    ValidationFailed(),

    #[error("hypervisor error")]
    #[cfg_attr(feature = "ffi", ffier(code = 16))]
    HypervisorError(),

    #[error("boot error: {0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 17, opaque))]
    BootError(String),

    #[error("internal error: {0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 18, opaque))]
    Internal(String),
}
