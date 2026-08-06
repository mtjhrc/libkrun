use std::io::{self, Write};
use std::os::fd::BorrowedFd;

use env_logger::Env;

use super::error::Error;

#[cfg_attr(feature = "ffi", ffier::export)]
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

#[cfg_attr(feature = "ffi", ffier::export)]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStyle {
    Auto = 0,
    Always = 1,
    Never = 2,
}

#[cfg(feature = "ffi")]
ffier::export_bitflags! {
    bitflags::bitflags! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct LogOptions: u32 {
            const NO_ENV = 1;
        }
    }
}

#[cfg(not(feature = "ffi"))]
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LogOptions: u32 {
        const NO_ENV = 1;
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
pub fn init_log(
    target: Option<BorrowedFd<'static>>,
    level: LogLevel,
    style: LogStyle,
    options: LogOptions,
) -> Result<(), Error> {
    struct FdWriter(BorrowedFd<'static>);

    impl Write for FdWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            nix::unistd::write(self.0, buf).map_err(io::Error::from)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let target = match target {
        None => env_logger::Target::default(),
        Some(fd) => env_logger::Target::Pipe(Box::new(FdWriter(fd))),
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

    let mut builder = if options.contains(LogOptions::NO_ENV) {
        let mut builder = env_logger::Builder::new();
        builder.parse_filters(filter).parse_write_style(write_style);
        builder
    } else {
        env_logger::Builder::from_env(
            Env::new()
                .default_filter_or(filter)
                .default_write_style_or(write_style),
        )
    };
    builder.format_timestamp_micros().target(target).init();

    Ok(())
}
