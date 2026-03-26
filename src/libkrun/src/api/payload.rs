use std::io::IsTerminal;
use std::os::fd::{BorrowedFd, FromRawFd};

use devices::virtio::port_io;
use libc::{STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};

use super::devices::{ConsoleDeviceBuilder, FsDevice};
use super::error::ErrorCode;

pub struct LibkrunInit {
    pub(crate) args: String,
    pub(crate) env: String,
}

pub struct LibkrunInitBuilder<'a, 'b> {
    console: &'b mut ConsoleDeviceBuilder<'a>,
    exec_path: Option<String>,
    args: Option<String>,
    env: Option<String>,
    workdir: Option<String>,
    payload_console_configured: bool,
}

#[ffier::exportable(prefix = "krun")]
impl LibkrunInit {
    pub fn builder<'a, 'b>(
        _rootfs: &FsDevice<'_>,
        console: &'b mut ConsoleDeviceBuilder<'a>,
    ) -> LibkrunInitBuilder<'a, 'b> {
        // Port 0 is always the kernel/init console (output-only).
        // Kernel cmdline has console=hvc0, so boot messages go here.
        // init.krun's stdio starts on hvc0 too; setup_redirects() in init.krun
        // moves payload stdio to a named port (krun-tty or krun-stdin/stdout/stderr).
        console.add_console_port("krun-init-console", port_io::output_to_log(log::Level::Info));

        LibkrunInitBuilder {
            console,
            exec_path: None,
            args: None,
            env: None,
            workdir: None,
            payload_console_configured: false,
        }
    }
}

#[ffier::exportable(prefix = "krun")]
impl<'a, 'b> LibkrunInitBuilder<'a, 'b> {
    /// Auto-detect console setup based on stdin/stdout/stderr properties.
    ///
    /// If stdin is a TTY: creates a single TTY port for payload I/O (like v1 default).
    /// Otherwise: creates separate krun-stdin/krun-stdout/krun-stderr redirect ports.
    pub fn set_console_auto(&mut self) -> Result<(), ErrorCode> {
        let stdin_is_tty = unsafe {
            let f = std::fs::File::from_raw_fd(STDIN_FILENO);
            let is = f.is_terminal();
            std::mem::forget(f);
            is
        };

        if stdin_is_tty {
            self.set_console_tty(unsafe { BorrowedFd::borrow_raw(STDIN_FILENO) })
        } else {
            self.set_console_redirects(STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO)
        }
    }

    /// Set up a single TTY port for payload I/O.
    /// The fd is used for both input and output; terminal properties are attached
    /// if the fd is a real terminal.
    pub fn set_console_tty(&mut self, tty_fd: BorrowedFd<'a>) -> Result<(), ErrorCode> {
        self.console
            .add_tty_port("krun-payload-tty", tty_fd)?;
        self.payload_console_configured = true;
        Ok(())
    }

    /// Set up separate redirect ports for payload stdin/stdout/stderr.
    /// Pass -1 for any fd to leave that stream disconnected.
    pub fn set_console_redirects(
        &mut self,
        stdin_fd: i32,
        stdout_fd: i32,
        stderr_fd: i32,
    ) -> Result<(), ErrorCode> {
        if stdin_fd >= 0 {
            self.console
                .add_io_port("krun-payload-stdin", Some(stdin_fd), None)?;
        }
        if stdout_fd >= 0 {
            self.console
                .add_io_port("krun-payload-stdout", None, Some(stdout_fd))?;
        }
        if stderr_fd >= 0 {
            self.console
                .add_io_port("krun-payload-stderr", None, Some(stderr_fd))?;
        }
        self.payload_console_configured = true;
        Ok(())
    }

    pub fn set_exec(&mut self, exec_path: &str, args: &[&str]) -> Result<(), ErrorCode> {
        if exec_path.is_empty() {
            return Err(ErrorCode::InvalidParam);
        }
        self.exec_path = Some(exec_path.to_string());
        let encoded: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
        self.args = Some(encoded.join(" "));
        Ok(())
    }

    pub fn set_env(&mut self, env: &[&str]) -> Result<(), ErrorCode> {
        let encoded: Vec<String> = env.iter().map(|e| format!("\"{e}\"")).collect();
        self.env = Some(encoded.join(" "));
        Ok(())
    }

    pub fn set_workdir(&mut self, path: &str) -> Result<(), ErrorCode> {
        if path.is_empty() {
            return Err(ErrorCode::InvalidParam);
        }
        self.workdir = Some(path.to_string());
        Ok(())
    }

    pub fn build(mut self) -> Result<LibkrunInit, ErrorCode> {
        // If the caller didn't explicitly set up console ports, auto-detect.
        if !self.payload_console_configured {
            self.set_console_auto()?;
        }

        let exec_path = self.exec_path.ok_or(ErrorCode::MissingConfig)?;
        let krun_init = format!("KRUN_INIT={exec_path}");
        let krun_workdir = self
            .workdir
            .as_ref()
            .map(|w| format!("KRUN_WORKDIR={w}"))
            .unwrap_or_default();
        let krun_env = self.env.clone().unwrap_or_default();
        let args = self.args.unwrap_or_default();

        let env_str = format!(" {krun_init} {krun_workdir} {krun_env}");

        Ok(LibkrunInit { args, env: env_str })
    }
}
