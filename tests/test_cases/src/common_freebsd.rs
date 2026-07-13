//! Host-side utilities for FreeBSD guest tests.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;

use krun_via_cdylib_weak as krun;

use crate::TestSetup;
use crate::test_net::COMPAT_NET_FEATURES;
use crate::test_net::gvproxy::{Gvproxy, wait_for_socket};

pub struct FreeBsdAssets {
    pub kernel_path: PathBuf,
    pub iso_path: PathBuf,
}

pub fn freebsd_assets() -> Option<FreeBsdAssets> {
    let kernel_path = PathBuf::from(std::env::var_os("KRUN_TEST_FREEBSD_KERNEL_PATH")?);
    let iso_path = PathBuf::from(std::env::var_os("KRUN_TEST_FREEBSD_ISO_PATH")?);
    if !kernel_path.exists() || !iso_path.exists() {
        return None;
    }
    Some(FreeBsdAssets {
        kernel_path,
        iso_path,
    })
}

fn create_config_iso(test_case: &str, tmp_dir: &Path) -> anyhow::Result<PathBuf> {
    let staging = tmp_dir.join("krun_config");
    std::fs::create_dir(&staging).context("create krun_config staging dir")?;

    let json = format!(r#"{{"Cmd":["/guest-agent","{test_case}"]}}"#);
    std::fs::write(staging.join("krun_config.json"), json).context("write krun_config.json")?;

    let iso_path = tmp_dir.join("krun_config.iso");
    let status = Command::new("bsdtar")
        .args([
            "cf",
            iso_path.to_str().context("config iso path is not UTF-8")?,
            "--format=iso9660",
            "--options",
            "volume-id=KRUN_CONFIG",
            "-C",
            staging
                .to_str()
                .context("config staging dir is not UTF-8")?,
            "krun_config.json",
        ])
        .status()
        .context(
            "Failed to run bsdtar — on Linux install libarchive-tools; on macOS bsdtar is built-in",
        )?;

    if !status.success() {
        anyhow::bail!("bsdtar exited with {status}");
    }
    Ok(iso_path)
}

pub fn normalize_serial_output(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n")
}

fn random_mac_address() -> [u8; 6] {
    let mut hasher = RandomState::new().build_hasher();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    hasher.write_u32(nanos);
    let hash = hasher.finish();

    [
        0x52, // Xen OUI
        0x54,
        0x00,
        ((hash >> 16) & 0xFF) as u8,
        ((hash >> 8) & 0xFF) as u8,
        (hash & 0xFF) as u8,
    ]
}

pub fn setup_gvproxy_backend(test_setup: &TestSetup) -> anyhow::Result<(krun::NetDevice, String)> {
    let tmp_dir = test_setup
        .tmp_dir
        .canonicalize()
        .unwrap_or_else(|_| test_setup.tmp_dir.clone());
    let net_sock = tmp_dir.join("gvproxy-net.sock");
    let vfkit_sock = tmp_dir.join("gvproxy-vfkit.sock");
    let gvproxy_log = tmp_dir.join("gvproxy.log");

    let net_sock_str = net_sock
        .to_str()
        .context("gvproxy net-sock path is not valid UTF-8")?
        .to_string();
    let vfkit_sock_str = vfkit_sock
        .to_str()
        .context("gvproxy vfkit-sock path is not valid UTF-8")?;

    let child = Gvproxy::new(vfkit_sock_str, &gvproxy_log)
        .net_sock(&net_sock_str)
        .ssh_port(-1)
        .start()?;
    test_setup.register_cleanup_pid(child.id());

    anyhow::ensure!(
        wait_for_socket(&vfkit_sock, 5000),
        "gvproxy failed to create vfkit socket"
    );

    let mac = random_mac_address();
    let net =
        krun::NetDevice::new_unixgram_path("net0", vfkit_sock_str, &mac, COMPAT_NET_FEATURES, true)
            .map_err(|e| anyhow::anyhow!("NetDevice: {e:?}"))?;

    Ok((net, net_sock_str))
}

pub fn setup_kernel_and_enter(
    test_setup: TestSetup,
    assets: FreeBsdAssets,
    extra_devices: Vec<
        Box<dyn FnOnce(&mut krun::MmioDeviceManager<'static>) -> anyhow::Result<()>>,
    >,
) -> anyhow::Result<()> {
    let config_iso = create_config_iso(&test_setup.test_case, &test_setup.tmp_dir)?;

    // Serial console: pipe to avoid kqueue busy-spin on macOS
    let mut pipe_fds: [libc::c_int; 2] = [-1, -1];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        anyhow::bail!(
            "Failed to create serial input pipe: {}",
            io::Error::last_os_error()
        );
    }
    let serial_read_fd = pipe_fds[0];

    #[cfg(target_arch = "x86_64")]
    let (kernel_format, cmdline_prefix, flags) = (krun::KernelFormat::Elf, "", "boot_mute=YES");
    #[cfg(not(target_arch = "x86_64"))]
    let (kernel_format, cmdline_prefix, flags) = (krun::KernelFormat::Raw, "FreeBSD:", "-mq");

    let cmdline = format!(
        "{cmdline_prefix}vfs.root.mountfrom=cd9660:/dev/vtbd0 {flags} init_path=/init-freebsd"
    );

    let payload = krun::Payload::load_external(
        assets.kernel_path.to_str().unwrap(),
        kernel_format,
        &cmdline,
    )
    .map_err(|e| anyhow::anyhow!("load_external: {e:?}"))?;

    let rootfs_disk = krun::BlockDevice::new("vtbd0", assets.iso_path.to_str().unwrap(), true)
        .map_err(|e| anyhow::anyhow!("BlockDevice rootfs: {e:?}"))?;

    let config_disk = krun::BlockDevice::new("vtbd1", config_iso.to_str().unwrap(), true)
        .map_err(|e| anyhow::anyhow!("BlockDevice config: {e:?}"))?;

    let mut console_builder = krun::ConsoleDevice::builder();
    console_builder
        .add_default_console(-1, io::stdout().as_raw_fd(), -1)
        .map_err(|e| anyhow::anyhow!("add_default_console: {e:?}"))?;
    let console = console_builder
        .build()
        .map_err(|e| anyhow::anyhow!("ConsoleDevice::build: {e:?}"))?;

    let mut devices = krun::MmioDeviceManager::new();
    devices.add(rootfs_disk);
    devices.add(config_disk);
    devices.add(console);
    devices.add(krun::BalloonDevice::new().map_err(|e| anyhow::anyhow!("BalloonDevice: {e:?}"))?);
    devices.add(krun::RngDevice::new().map_err(|e| anyhow::anyhow!("RngDevice: {e:?}"))?);

    for add_device in extra_devices {
        add_device(&mut devices)?;
    }

    let mut vmm = krun::VmmBuilder::new()
        .vcpus(1)
        .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
        .ram_mib(512)
        .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
        .payload(payload)
        .serial_input_fd(serial_read_fd)
        .devices(devices)
        .build()
        .map_err(|e| anyhow::anyhow!("build: {e:?}"))?;

    vmm.run();
    unreachable!()
}
