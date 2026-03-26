use std::io::IsTerminal;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};

use devices::virtio::{port_io, PortDescription};

use super::error::ErrorCode;

// ---------------------------------------------------------------------------
// FsDevice
// ---------------------------------------------------------------------------

pub struct FsDevice<'a> {
    pub(crate) inner: Arc<Mutex<devices::virtio::Fs>>,
    #[allow(dead_code)]
    pub(crate) tag: String,
    pub(crate) shm_size: Option<usize>,
    _lifetime: PhantomData<&'a ()>,
}

#[ffier::exportable(prefix = "krun")]
impl<'a> FsDevice<'a> {
    pub fn new(tag: &str, host_path: &str) -> Result<Self, ErrorCode> {
        let exit_code = Arc::new(AtomicI32::new(i32::MAX));
        let fs = devices::virtio::Fs::new(
            tag.to_string(),
            host_path.to_string(),
            exit_code.clone(),
            false,
        )
        .map_err(|e| {
            log::error!("fs device: {e:?}");
            ErrorCode::Internal
        })?;

        Ok(Self {
            inner: Arc::new(Mutex::new(fs)),
            tag: tag.to_string(),
            shm_size: None,
            _lifetime: PhantomData,
        })
    }

    pub fn set_dax_window_size(&mut self, bytes: u64) {
        self.shm_size = Some(bytes as usize);
    }
}

// ---------------------------------------------------------------------------
// ConsoleDevice + Builder
// ---------------------------------------------------------------------------

pub struct ConsoleDevice<'a> {
    pub(crate) ports: Vec<PortDescription>,
    #[allow(dead_code)]
    pub(crate) kernel_console_port: Option<u32>,
    /// Raw fds of TTY ports that need raw mode set after Vmm is constructed.
    pub(crate) tty_fds: Vec<i32>,
    _lifetime: PhantomData<&'a ()>,
}

pub struct ConsoleDeviceBuilder<'a> {
    ports: Vec<PortDescription>,
    kernel_console_port: Option<u32>,
    tty_fds: Vec<i32>,
    _lifetime: PhantomData<&'a ()>,
}

#[ffier::exportable(prefix = "krun")]
impl<'a> ConsoleDevice<'a> {
    pub fn builder() -> ConsoleDeviceBuilder<'a> {
        ConsoleDeviceBuilder {
            ports: Vec::new(),
            kernel_console_port: None,
            tty_fds: Vec::new(),
            _lifetime: PhantomData,
        }
    }
}

#[ffier::exportable(prefix = "krun")]
impl<'a> ConsoleDeviceBuilder<'a> {
    pub fn add_tty_port(
        &mut self,
        name: &str,
        tty_fd: BorrowedFd<'a>,
    ) -> Result<u32, ErrorCode> {
        let index = self.ports.len() as u32;
        self.add_tty_port_inner(name, tty_fd)?;
        Ok(index)
    }

    pub fn set_kernel_console(&mut self, port_index: u32) -> Result<(), ErrorCode> {
        if port_index as usize >= self.ports.len() {
            return Err(ErrorCode::OutOfRange);
        }
        self.kernel_console_port = Some(port_index);
        Ok(())
    }

    pub fn build(self) -> Result<ConsoleDevice<'a>, ErrorCode> {
        if self.ports.is_empty() {
            return Err(ErrorCode::MissingConfig);
        }
        Ok(ConsoleDevice {
            ports: self.ports,
            kernel_console_port: self.kernel_console_port,
            tty_fds: self.tty_fds,
            _lifetime: PhantomData,
        })
    }
}

impl ConsoleDeviceBuilder<'_> {
    /// Add an output-only port (no input, no terminal).
    pub(crate) fn add_output_port(
        &mut self,
        name: &str,
        output: Box<dyn devices::virtio::port_io::PortOutput + Send>,
    ) -> u32 {
        let index = self.ports.len() as u32;
        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input: None,
            output: Some(output),
            terminal: None,
        });
        index
    }

    /// Add an output-only console port with fake terminal properties.
    /// The kernel can use this as `console=hvcN` (mark_console_port is triggered
    /// by the presence of terminal properties).
    pub(crate) fn add_console_port(
        &mut self,
        name: &str,
        output: Box<dyn devices::virtio::port_io::PortOutput + Send>,
    ) -> u32 {
        let index = self.ports.len() as u32;
        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input: None,
            output: Some(output),
            terminal: Some(port_io::term_fixed_size(80, 24)),
        });
        index
    }

    /// Add a port with separate input and output fds (no terminal properties).
    /// Used for krun-stdin/krun-stdout/krun-stderr redirect ports.
    pub(crate) fn add_io_port(
        &mut self,
        name: &str,
        input_fd: Option<i32>,
        output_fd: Option<i32>,
    ) -> Result<u32, ErrorCode> {
        let index = self.ports.len() as u32;
        let input = match input_fd {
            Some(fd) if fd >= 0 => Some(port_io::input_to_raw_fd_dup(fd).map_err(|e| {
                log::error!("dup input fd: {e}");
                ErrorCode::BadFd
            })?),
            _ => None,
        };
        let output = match output_fd {
            Some(fd) if fd >= 0 => Some(port_io::output_to_raw_fd_dup(fd).map_err(|e| {
                log::error!("dup output fd: {e}");
                ErrorCode::BadFd
            })?),
            _ => None,
        };
        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input,
            output,
            terminal: None,
        });
        Ok(index)
    }

    fn add_tty_port_inner(&mut self, name: &str, tty_fd: BorrowedFd<'_>) -> Result<(), ErrorCode> {
        let raw_fd = tty_fd.as_raw_fd();

        let input = Some(
            port_io::input_to_raw_fd_dup(raw_fd).map_err(|e| {
                log::error!("dup input fd: {e}");
                ErrorCode::BadFd
            })?,
        );
        let output = Some(
            port_io::output_to_raw_fd_dup(raw_fd).map_err(|e| {
                log::error!("dup output fd: {e}");
                ErrorCode::BadFd
            })?,
        );

        // If it's a real terminal, attach terminal properties for winsize queries.
        // If not a terminal (e.g. a pipe), terminal is None.
        let file_check = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        let is_term = file_check.is_terminal();
        std::mem::forget(file_check); // don't close — we don't own this fd
        let terminal: Option<Box<dyn devices::virtio::port_io::PortTerminalProperties>> =
            if is_term {
                Some(port_io::term_fd(raw_fd).map_err(|e| {
                    log::error!("term fd: {e}");
                    ErrorCode::BadFd
                })?)
            } else {
                None
            };

        if is_term {
            self.tty_fds.push(raw_fd);
        }

        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input,
            output,
            terminal,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BalloonDevice
// ---------------------------------------------------------------------------

pub struct BalloonDevice {
    pub(crate) inner: Arc<Mutex<devices::virtio::Balloon>>,
}

#[ffier::exportable(prefix = "krun")]
impl BalloonDevice {
    pub fn new() -> Result<Self, ErrorCode> {
        let balloon = devices::virtio::Balloon::new().map_err(|e| {
            log::error!("balloon: {e:?}");
            ErrorCode::Internal
        })?;
        Ok(Self {
            inner: Arc::new(Mutex::new(balloon)),
        })
    }
}

// ---------------------------------------------------------------------------
// RngDevice
// ---------------------------------------------------------------------------

pub struct RngDevice {
    pub(crate) inner: Arc<Mutex<devices::virtio::Rng>>,
}

#[ffier::exportable(prefix = "krun")]
impl RngDevice {
    pub fn new() -> Result<Self, ErrorCode> {
        let rng = devices::virtio::Rng::new().map_err(|e| {
            log::error!("rng: {e:?}");
            ErrorCode::Internal
        })?;
        Ok(Self {
            inner: Arc::new(Mutex::new(rng)),
        })
    }
}
