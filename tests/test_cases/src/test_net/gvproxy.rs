//! Gvproxy backend for virtio-net test (macOS only)

use crate::{ShouldRun, TestSetup};
use krun_sys::{COMPAT_NET_FEATURES, NET_FLAG_VFKIT};
use nix::libc;
use std::ffi::CString;

type KrunAddNetUnixgramFn = unsafe extern "C" fn(
    ctx_id: u32,
    c_path: *const std::ffi::c_char,
    fd: i32,
    c_mac: *mut u8,
    features: u32,
    flags: u32,
) -> i32;

fn get_krun_add_net_unixgram() -> Option<KrunAddNetUnixgramFn> {
    let symbol = CString::new("krun_add_net_unixgram").unwrap();
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute(ptr) })
    }
}

fn gvproxy_path() -> Option<String> {
    let paths = [
        "/opt/homebrew/Cellar/podman/5.5.1/libexec/podman/gvproxy",
        "/opt/homebrew/opt/podman/libexec/podman/gvproxy",
        "/usr/libexec/podman/gvproxy",
        "/usr/local/libexec/podman/gvproxy",
    ];
    for path in paths {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    std::process::Command::new("which")
        .arg("gvproxy")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}

fn start_gvproxy(
    socket_path: &str,
    log_path: &std::path::Path,
) -> std::io::Result<std::process::Child> {
    use std::process::{Command, Stdio};

    let _ = Command::new("pkill").arg("-9").arg("gvproxy").status();

    let gvproxy = gvproxy_path()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "gvproxy not found"))?;

    let log_file = std::fs::File::create(log_path)?;

    Command::new(&gvproxy)
        .arg("--listen-vfkit")
        .arg(format!("unixgram:{}", socket_path))
        .arg("-debug")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log_file)
        .spawn()
}

/// Expose a port via gvproxy control socket API.
/// Tells gvproxy to forward guest connections to gateway:port → host localhost:port.
fn expose_port(control_socket_path: &std::path::Path, port: u16) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(control_socket_path)?;
    let body = format!(r#"{{"local":":{port}","remote":"127.0.0.1:{port}"}}"#);
    let request = format!(
        "POST /services/forwarder/expose HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    anyhow::ensure!(
        response.contains("200"),
        "gvproxy expose_port failed: {}",
        response
    );
    eprintln!("gvproxy: exposed port {port}");
    Ok(())
}

fn wait_for_socket(path: &std::path::Path, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < timeout_ms as u128 {
        if path.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

pub fn should_run() -> ShouldRun {
    #[cfg(not(target_os = "macos"))]
    return ShouldRun::No("gvproxy unixgram only supported on macOS");

    #[cfg(target_os = "macos")]
    {
        if get_krun_add_net_unixgram().is_none() {
            return ShouldRun::No("libkrun compiled without NET");
        }
        if gvproxy_path().is_none() {
            return ShouldRun::No("gvproxy not installed");
        }
        ShouldRun::Yes
    }
}

pub fn setup_backend(ctx: u32, test_setup: &TestSetup) -> anyhow::Result<()> {
    let tmp_dir = test_setup
        .tmp_dir
        .canonicalize()
        .unwrap_or_else(|_| test_setup.tmp_dir.clone());
    let socket_path = tmp_dir.join("gvproxy.sock");
    let gvproxy_log = tmp_dir.join("gvproxy.log");

    let _gvproxy_child = start_gvproxy(
        socket_path.to_str().unwrap(),
        &gvproxy_log,
    )?;

    anyhow::ensure!(
        wait_for_socket(&socket_path, 5000),
        "gvproxy failed to create socket"
    );

    // Wait for control socket and expose port so gvproxy forwards guest TCP to host
    anyhow::ensure!(
        wait_for_socket(&control_socket_path, 5000),
        "gvproxy failed to create control socket"
    );
    expose_port(&control_socket_path, 8002)?;

    let mut mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
    let c_socket_path = CString::new(socket_path.to_str().unwrap()).unwrap();

    let net_result = unsafe {
        get_krun_add_net_unixgram().unwrap()(
            ctx,
            c_socket_path.as_ptr(),
            -1,
            mac.as_mut_ptr(),
            COMPAT_NET_FEATURES,
            NET_FLAG_VFKIT,
        )
    };
    anyhow::ensure!(net_result >= 0, "krun_add_net_unixgram failed: {}", net_result);
    Ok(())
}
