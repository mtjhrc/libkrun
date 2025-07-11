use crate::display_backend::GtkDisplayBackend;
use crate::event::DisplayEvent;
use crate::glib::program_name;
use crate::scanout_window::ScanoutWindow;
use ::utils::pollable_channel::{PollableChannelReciever, PollableChannelSender, pollable_channel};
use anyhow::Context;
use clap::{Arg, ArgGroup, Parser};
use clap_derive::Parser;
use gtk4::builders::AlertDialogBuilder;
use gtk4::glib::ffi::{G_SPAWN_FILE_AND_ARGV_ZERO, g_source_add_poll};
use gtk4::glib::{
    GStr, MainLoop, Priority, idle_add_local, unix_fd_add_local, unix_fd_add_local_full,
};
use gtk4::graphene::EulerOrder::Rxyx;
use gtk4::{
    Application, ApplicationWindow, Label,
    gio::ApplicationFlags,
    glib,
    glib::prelude::*,
    glib::{ControlFlow, IOCondition, source},
};
use krun_display::{DisplayBackend, IntoDisplayBackend};
use krun_sys::{
    KRUN_MAX_DISPLAYS, VIRGLRENDERER_THREAD_SYNC, VIRGLRENDERER_USE_ASYNC_FENCE_CB,
    VIRGLRENDERER_USE_EGL, krun_create_ctx, krun_set_display, krun_set_display_backend,
    krun_set_exec, krun_set_gpu_options, krun_set_log_level, krun_set_root, krun_start_enter,
};
use libc::{_exit, c_char, fd_set, select};
use log::{LevelFilter, debug, error, info, trace, warn};
use std::cell::{OnceCell, RefCell};
use std::ffi::{CString, c_void};
use std::os::fd::{AsRawFd, RawFd};
use std::process::exit;
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::time::Duration;
use std::{io, mem, thread};
use gtk4::prelude::{ApplicationExt, ApplicationExtManual};

mod display_backend;
mod event;
mod scanout_paintable;
mod scanout_window;
mod utils;

#[derive(Debug, Clone, Copy)]
struct DisplayArg {
    id: u32,
    width: u32,
    height: u32,
}

fn parse_display(s: &str) -> Result<DisplayArg, String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 3 {
        return Err("Expected format: id,width,height".to_string());
    }
    let id = parts[0].parse().map_err(|_| "Invalid id")?;
    let width = parts[1].parse().map_err(|_| "Invalid width")?;
    let height = parts[2].parse().map_err(|_| "Invalid height")?;
    Ok(DisplayArg { id, width, height })
}

#[derive(Parser, Debug)]
struct Args {
    #[cfg(not(feature = "efi"))]
    #[arg(long)]
    root_dir: Option<CString>,

    #[cfg(not(feature = "efi"))]
    executable: Option<CString>,

    #[cfg(not(feature = "efi"))]
    argv: Vec<CString>,

    #[cfg(feature = "efi")]
    #[arg(long)]
    root_disk: Option<CString>,

    #[clap(long, value_parser = parse_display)]
    display: Vec<DisplayArg>,
}

fn krun_thread(args: &Args, tx: &PollableChannelSender<DisplayEvent>) -> anyhow::Result<()> {
    unsafe {
        krun_call!(krun_set_log_level(3))?;
        let ctx = krun_call_u32!(krun_create_ctx())?;

        krun_call!(krun_set_gpu_options(
            ctx,
            VIRGLRENDERER_USE_EGL
                | VIRGLRENDERER_USE_EGL
                | VIRGLRENDERER_THREAD_SYNC
                | VIRGLRENDERER_USE_ASYNC_FENCE_CB
        ))?;

        #[cfg(feature = "efi")]
        if let Some(root_disk) = &args.root_disk {
            krun_call!(krun_set_root_disk(ctx, root_disk.as_ptr()))?;
        }

        #[cfg(not(feature = "efi"))]
        if let Some(root_dir) = &args.root_dir {
            krun_call!(krun_set_root(ctx, root_dir.as_ptr()))?;
            // Executable variable should be set if we have root_dir, this is verified by clap
            let executable = args.executable.as_ref().unwrap().as_ptr();
            let argv: Vec<_> = args.argv.iter().map(|a| a.as_ptr()).collect();
            let argv_ptr = if argv.is_empty() {
                null()
            } else {
                argv.as_ptr()
            };
            let envp = [null()];
            krun_call!(krun_set_exec(ctx, executable, argv_ptr, envp.as_ptr()))?;
        }

        for display in &args.display {
            krun_call!(krun_set_display(
                ctx,
                display.id,
                display.width,
                display.height
            ))?;
        }

        let display_backend = GtkDisplayBackend::into_display_backend(Some(tx));

        krun_call!(krun_set_display_backend(
            ctx,
            1,
            &raw const display_backend as *const c_void,
            size_of::<DisplayBackend>()
        ))?;
        krun_call!(krun_start_enter(ctx))?;
    };
    Ok(())
}

struct DisplayEventHandler {
    app_name: String,
    rx: PollableChannelReciever<DisplayEvent>,
    scanouts: RefCell<[Option<ScanoutWindow>; KRUN_MAX_DISPLAYS as usize]>,
}

impl DisplayEventHandler {
    fn new(rx: PollableChannelReciever<DisplayEvent>) -> Self {
        let program_name = {
            let args = std::env::args();
            args.into_iter()
                .next()
                .map(|name| format!("{name} (libkrun)"))
                .unwrap_or_else(|| "libkrun".to_string())
        };

        Self {
            rx,
            app_name: program_name,
            scanouts: Default::default(),
        }
    }

    fn handle_event(&self) {
        let Some(msg) = self.rx.try_recv().unwrap() else {
            return;
        };
        let mut scanouts = self.scanouts.borrow_mut();

        match msg {
            DisplayEvent::ConfigureScanout {
                scanout_id,
                display_width,
                display_height,
                width,
                height,
                format,
            } => {
                if let Some(ref mut scanout) = scanouts[scanout_id as usize] {
                    trace!(
                        "Update params of scanout {scanout_id}: width={width} height={height} format={format:?}"
                    );
                    scanout.reconfigure(width as i32, height as i32, format);
                } else {
                    debug!(
                        "Enable scanout {scanout_id} width={width} height={height} format={format:?}"
                    );
                    scanouts[scanout_id as usize] = Some(ScanoutWindow::new(
                        format!(
                            "{name} - display {scanout_id} ({width}x{height})",
                            name = self.app_name
                        ),
                        display_width as i32,
                        display_height as i32,
                        width as i32,
                        height as i32,
                        format,
                    ));
                }
            }
            DisplayEvent::DisableScanout { scanout_id } => {
                debug!("Disable scanout {scanout_id}");
                scanouts[scanout_id as usize] = None;
            }
            DisplayEvent::UpdateScanout { scanout_id, data } => {
                if let Some(scanout) = &mut scanouts[scanout_id as usize] {
                    trace!("Update scanout {scanout_id}");
                    scanout.update(data);
                } else {
                    warn!("Attempted to update non-existent scanout: {scanout_id}");
                }
            }
        };
    }
}

pub fn display_thread(rx: PollableChannelReciever<DisplayEvent>) -> anyhow::Result<()> {
    let app = Application::builder().build();

    // Hold the application so it doesn't close when we don't have any windows open. We hold the
    // app forever, because currently libkrun just exits the process on VM shutdown so there is no
    // way for us to do anything better here for now.
    let _app_hold = app.hold();

    let rx_fd = rx.as_raw_fd();
    let handler = Rc::new(DisplayEventHandler::new(rx));

    app.connect_activate(move |app| {
        let handler = Rc::clone(&handler);
        unix_fd_add_local(rx_fd, IOCondition::IN, move |_, _| {
            handler.handle_event();
            ControlFlow::Continue
        });
    });
    app.run_with_args::<&str>(&[]);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(LevelFilter::Trace)
        .init();
    let args = Args::parse();
    let (tx, rx) = pollable_channel().context("Failed to create channel")?;

    thread::scope(|s| {
        s.spawn(|| {
            if let Err(e) = krun_thread(&args, &tx) {
                eprintln!("{e}");
                exit(1);
            }
        });
        display_thread(rx).context("Display thread failed")
    })?;
    unreachable!("Expected libkrun to exit the process");
}
