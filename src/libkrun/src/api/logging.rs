#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::fd::FromRawFd;

use env_logger::{Env, Target};

use super::error::Error;

#[ffier::export]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Off = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

#[ffier::export]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStyle {
    Auto = 0,
    Always = 1,
    Never = 2,
}

/// Bit flag for [`init_log`]'s `options` parameter: disable env-var
/// (`RUST_LOG`) override of the requested `level`/`style`.
pub const LOG_OPTION_NO_ENV: u32 = 1;

const LOG_OPTIONS_ALL: u32 = LOG_OPTION_NO_ENV;

/// Initialize logging.
///
/// # Arguments
///
/// - `target_fd`: where log output is written. `-1` selects the default
///   target (stderr), `1` selects stdout, `2` selects stderr, and any other
///   non-negative value is treated as an arbitrary file descriptor the
///   caller owns and is transferring to the logger.
/// - `level`: the maximum log level to emit.
/// - `style`: whether to colorize output.
/// - `options`: a bitmask of `LOG_OPTION_*` flags (0 for defaults).
#[ffier::export]
pub fn init_log(
    target_fd: i32,
    level: LogLevel,
    style: LogStyle,
    options: u32,
) -> Result<(), Error> {
    if options & !LOG_OPTIONS_ALL != 0 {
        return Err(Error::InvalidParam());
    }

    let target = match target_fd {
        ..-1 => return Err(Error::InvalidParam()),
        -1 => Target::default(),
        0 => return Err(Error::InvalidParam()),
        1 => Target::Stdout,
        2 => Target::Stderr,
        #[cfg(unix)]
        fd => Target::Pipe(Box::new(unsafe { File::from_raw_fd(fd) })),
        #[cfg(not(unix))]
        _ => return Err(Error::InvalidParam()),
    };

    let filter = match level {
        LogLevel::Off => "off",
        LogLevel::Error => "error",
        LogLevel::Warn => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    };

    let write_style = match style {
        LogStyle::Auto => "auto",
        LogStyle::Always => "always",
        LogStyle::Never => "never",
    };

    let use_env = options & LOG_OPTION_NO_ENV == 0;

    let mut builder = if use_env {
        env_logger::Builder::from_env(
            Env::new()
                .default_filter_or(filter)
                .default_write_style_or(write_style),
        )
    } else {
        let mut builder = env_logger::Builder::new();
        builder.parse_filters(filter).parse_write_style(write_style);
        builder
    };
    builder.format_timestamp_micros().target(target).init();

    Ok(())
}
