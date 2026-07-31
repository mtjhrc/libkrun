#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid parameter")]
    InvalidParam(),

    #[error("missing required configuration: {0}")]
    MissingConfig(String),

    #[error("value out of range")]
    OutOfRange(),

    #[error("file not found")]
    FileNotFound(),

    #[error("resource allocation failed")]
    ResourceAlloc(),

    #[error("bad file descriptor")]
    BadFd(),

    #[error("feature not enabled in this build")]
    FeatureDisabled(),

    #[error("boot error: {0}")]
    BootError(String),

    #[error("internal error: {0}")]
    Internal(String),
}
