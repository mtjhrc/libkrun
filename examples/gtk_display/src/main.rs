use crate::display_backend::GtkDisplayBackend;
use crate::display_loop::display_loop;
use crate::event::DisplayEvent;
use ::utils::pollable_channel::{PollableChannelSender, pollable_channel};
use clap::Parser;
use clap_derive::Parser;
use krun_display::{DisplayBackend, IntoDisplayBackend};
use krun_sys::{KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER, KRUN_LOG_LEVEL_TRACE, KRUN_LOG_STYLE_ALWAYS, VIRGLRENDERER_NO_VIRGL, VIRGLRENDERER_THREAD_SYNC, VIRGLRENDERER_USE_ASYNC_FENCE_CB, VIRGLRENDERER_USE_EGL, VIRGLRENDERER_VENUS, krun_create_ctx, krun_init_log, krun_set_display, krun_set_display_backend, krun_set_exec, krun_set_gpu_options, krun_set_gpu_options2, krun_set_gvproxy_path, krun_set_log_level, krun_set_root, krun_set_root_disk, krun_set_vm_config, krun_start_enter, VIRGLRENDERER_RENDER_SERVER, VIRGLRENDERER_USE_SURFACELESS, VIRGLRENDERER_USE_GLES};
use std::ffi::{CString, c_char, c_void};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, IntoRawFd};
use std::process::exit;
use std::ptr::null;
use std::thread;
use anyhow::Context;

mod display_backend;
mod display_loop;
mod event;
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
    #[arg(long)]
    root_disk: CString,
    #[clap(long, value_parser = parse_display)]
    display: Vec<DisplayArg>,
    //argv: Vec<CString>,
}

fn krun_thread(args: &Args, tx: &PollableChannelSender<DisplayEvent>) -> anyhow::Result<()> {
    unsafe {
        krun_call!(krun_init_log(
            OpenOptions::new()
                .write(true)
                .open("/tmp/mylog").context("Can't open log pipe/file")?
                .into_raw_fd(),
            KRUN_LOG_LEVEL_TRACE,
            KRUN_LOG_STYLE_ALWAYS,
            0
        ))?;
        let ctx = krun_call_u32!(krun_create_ctx())?;

        krun_call!(krun_set_vm_config(ctx, 2, 1024))?;

        
        krun_call!(krun_set_gpu_options2(
            ctx,
            VIRGLRENDERER_VENUS | VIRGLRENDERER_NO_VIRGL,
            4 * 1024 * 1024,
        ))?;

        // FIXME: the C function has the wrong signature needs fix in libkrun!
        krun_call!(krun_set_gvproxy_path(ctx, c"/tmp/mynet".as_ptr() as *mut _))?;

        krun_call!(krun_set_root_disk(ctx, args.root_disk.as_ptr()))?;
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

fn main() -> anyhow::Result<()> {
    // Note that we have a different instance of env_logger than libkrun
    // env_logger::init();

    thread::scope(|s| {
        let args = Args::parse();
        let (tx, rx) = pollable_channel().unwrap();
        s.spawn(move || {
            if let Err(e) = krun_thread(&args, &tx) {
                eprintln!("{e}");
                exit(1);
            }
        });
        display_loop(rx);
    });
    unreachable!()
}
