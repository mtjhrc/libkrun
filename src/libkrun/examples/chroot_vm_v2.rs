//! v2 API example: chroot-like functionality with libkrun.
//!
//! Usage: chroot_vm_v2 NEWROOT COMMAND [ARGS...]
//!
//! Executes COMMAND inside a lightweight VM with NEWROOT as the rootfs.
//! Kernel/init log goes to /tmp/krun_kernel.log.
//! Payload I/O goes to the terminal (auto-detected).

use std::env;
use std::process;

use krun::{
    BalloonDevice, ConsoleDevice, FsDevice, LibkrunInit, RngDevice, VmmBuilder,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} NEWROOT COMMAND [ARGS...]", args[0]);
        process::exit(1);
    }

    let new_root = &args[1];
    let guest_cmd = &args[2];
    let guest_args: Vec<&str> = args[3..].iter().map(|s| s.as_str()).collect();

    // Initialize libkrun logging to file
    let log_file = std::fs::File::create("/tmp/krun_v2.log").expect("log file");
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Trace)
        .target(env_logger::Target::Pipe(Box::new(std::io::BufWriter::new(log_file))))
        .format_timestamp_micros()
        .init();

    // Create rootfs
    let rootfs = FsDevice::new("/dev/root", new_root).expect("fs device");

    // Create console + payload together (payload adds ports to the console)
    let mut console_builder = ConsoleDevice::builder();
    let payload = {
        let mut b = LibkrunInit::builder(&rootfs, &mut console_builder);
        b.set_exec(guest_cmd, &guest_args).expect("set exec");
        b.set_workdir("/").expect("set workdir");
        b.set_env(&["HOME=/root", "TERM=xterm-256color"])
            .expect("set env");
        // Auto-detects TTY vs pipe for payload I/O
        b.build().expect("build payload")
    };
    let console = console_builder.build().expect("build console");

    // Create balloon and rng
    let balloon = BalloonDevice::new().expect("balloon");
    let rng = RngDevice::new().expect("rng");

    // Build and run the VM
    let mut builder = VmmBuilder::new();
    builder.set_vcpus(2).expect("set vcpus");
    builder.set_ram_mib(512).expect("set ram");
    builder.set_payload(payload);
    builder.add_fs_device(rootfs);
    builder.add_console_device(console);
    builder.set_balloon(balloon);
    builder.set_rng(rng);

    let mut vmm = builder.build().expect("build vmm");
    vmm.run();
}
