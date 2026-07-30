use std::fmt;

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Error {
    // Configuration (100-199)
    InvalidParam(),
    DuplicateDevice(),
    DeviceLimitExceeded(),
    MissingConfig(),
    ConflictingConfig(),
    OutOfRange(),

    // Resources (200-299)
    FileNotFound(),
    PermissionDenied(),
    ResourceAlloc(),
    BadFd(),

    // Devices (300-399)
    BackendUnavailable(),
    FeatureDisabled(),
    DiskFormatError(),

    // Runtime (400-499)
    AlreadyStarted(),
    ValidationFailed(),
    HypervisorError(),
    BootError(),

    // Internal (900-999)
    Internal(),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
pub struct DetailedError {
    pub code: Error,
    pub context: Option<String>,
}

impl DetailedError {
    pub fn new(code: Error, context: impl Into<String>) -> Self {
        Self {
            code,
            context: Some(context.into()),
        }
    }
}

impl fmt::Display for DetailedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.code)?;
        if let Some(ctx) = &self.context {
            write!(f, ": {ctx}")?;
        }
        Ok(())
    }
}

impl std::error::Error for DetailedError {}

impl From<Error> for DetailedError {
    fn from(code: Error) -> Self {
        Self {
            code,
            context: None,
        }
    }
}
