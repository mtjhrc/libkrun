//! virtio-net integration test with passt
//!
//! This test verifies the virtio-net device by:
//! 1. Host: Starting passt as userspace network proxy, configuring virtio-net
//! 2. Guest: Configuring the network interface (eth0) using ioctl syscalls
//! 3. Testing TCP connectivity between guest and host using TcpTester

use crate::tcp_tester::TcpTester;
use macros::{guest, host};

const PORT: u16 = 8000;

pub struct TestNetPasst {
    #[allow(dead_code)] // Used by host module
    tcp_tester: TcpTester,
}

impl TestNetPasst {
    pub fn new() -> Self {
        Self {
            tcp_tester: TcpTester::new(PORT),
        }
    }
}

#[host]
mod host {
    use super::*;
    use nix::libc;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32, Test, TestSetup};
    use krun_sys::*;
    use std::ffi::{c_char, c_int, CString};
    use std::os::unix::io::RawFd;
    use std::thread;

    // Type alias for krun_add_net_unixstream function
    type KrunAddNetUnixstreamFn = unsafe extern "C" fn(
        ctx_id: u32,
        c_path: *const c_char,
        fd: c_int,
        c_mac: *mut u8,
        features: u32,
        flags: u32,
    ) -> i32;

    /// Try to get krun_add_net_unixstream function pointer via dlsym
    /// Returns None if the function doesn't exist (libkrun compiled without NET)
    fn get_krun_add_net_unixstream() -> Option<KrunAddNetUnixstreamFn> {
        let symbol = CString::new("krun_add_net_unixstream").unwrap();
        let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute(ptr) })
        }
    }

    /// Check if passt is available
    fn passt_available() -> bool {
        std::process::Command::new("which")
            .arg("passt")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Start passt and return the socket fd for communication
    fn start_passt() -> std::io::Result<RawFd> {
        // Create a socketpair for communication with passt
        let mut fds = [0 as libc::c_int; 2];
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let parent_fd = fds[0];
        let child_fd = fds[1];

        let child_fd_str = child_fd.to_string();

        // Fork and exec passt
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error());
        }

        if pid == 0 {
            // Child process
            unsafe { libc::close(parent_fd) };

            let passt = CString::new("passt").unwrap();
            let arg_f = CString::new("-f").unwrap();
            let arg_fd = CString::new("--fd").unwrap();
            let arg_fd_val = CString::new(child_fd_str).unwrap();

            unsafe {
                libc::execlp(
                    passt.as_ptr(),
                    passt.as_ptr(),
                    arg_f.as_ptr(),
                    arg_fd.as_ptr(),
                    arg_fd_val.as_ptr(),
                    std::ptr::null::<libc::c_char>(),
                );
            }
            // If exec fails, exit
            std::process::exit(1);
        }

        // Parent process
        unsafe { libc::close(child_fd) };

        Ok(parent_fd)
    }

    impl Test for TestNetPasst {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // Check if krun_add_net_unixstream is available (libkrun compiled with NET)
            let krun_add_net_unixstream = match get_krun_add_net_unixstream() {
                Some(f) => f,
                None => {
                    println!("SKIP");
                    return Ok(());
                }
            };

            // Check if passt is available
            if !passt_available() {
                println!("SKIP");
                return Ok(());
            }

            // Start passt
            let passt_fd = match start_passt() {
                Ok(fd) => fd,
                Err(_) => {
                    println!("SKIP");
                    return Ok(());
                }
            };

            // Start TCP server
            let listener = self.tcp_tester.create_server_socket();
            let tcp_tester = self.tcp_tester;
            thread::spawn(move || tcp_tester.run_server(listener));

            // MAC address for the virtio-net interface
            let mut mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;

                // Add virtio-net with passt backend
                // If net feature is not enabled, this will fail - skip the test
                let net_result = krun_add_net_unixstream(
                    ctx,
                    std::ptr::null(),  // No path, use fd
                    passt_fd,
                    mac.as_mut_ptr(),
                    COMPAT_NET_FEATURES,
                    0
                );
                if net_result < 0 {
                    // ENOTSUP (-95) or ENOSYS (-38) means feature not available
                    println!("SKIP");
                    return Ok(());
                }

                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
    use std::io::{Read, Write};
    use std::net::{IpAddr, SocketAddr, TcpStream};
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    // Network interface configuration constants
    const IFNAMSIZ: usize = 16;

    // Guest IP configuration (passt local mode - used when no external network)
    // passt NATs 169.254.2.2 to host's 127.0.0.1
    const GUEST_IP: &str = "169.254.2.1";
    const NETMASK: &str = "255.255.0.0";
    const HOST_IP: &str = "169.254.2.2";

    const IFF_UP: nix::libc::c_short = 0x1;
    const IFF_RUNNING: nix::libc::c_short = 0x40;

    #[repr(C)]
    #[derive(Default)]
    struct Ifreq {
        ifr_name: [u8; IFNAMSIZ],
        ifr_ifru: IfreqIfru,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    union IfreqIfru {
        ifru_addr: nix::libc::sockaddr,
        ifru_flags: nix::libc::c_short,
        _pad: [u8; 24],
    }

    impl Default for IfreqIfru {
        fn default() -> Self {
            Self { _pad: [0u8; 24] }
        }
    }

    // Define ioctl wrappers using nix macros
    nix::ioctl_readwrite_bad!(ioctl_siocsifaddr, 0x8916, Ifreq);
    nix::ioctl_readwrite_bad!(ioctl_siocsifnetmask, 0x891c, Ifreq);
    nix::ioctl_readwrite_bad!(ioctl_siocgifflags, 0x8913, Ifreq);
    nix::ioctl_readwrite_bad!(ioctl_siocsifflags, 0x8914, Ifreq);

    fn set_interface_name(ifr: &mut Ifreq, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(IFNAMSIZ - 1);
        ifr.ifr_name[..len].copy_from_slice(&bytes[..len]);
        ifr.ifr_name[len] = 0;
    }

    fn make_sockaddr_in(ip: &str) -> nix::libc::sockaddr {
        let mut addr: nix::libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = nix::libc::AF_INET as nix::libc::sa_family_t;

        // Parse IP address
        let octets: Vec<u8> = ip.split('.').map(|s| s.parse().unwrap()).collect();
        addr.sin_addr.s_addr = u32::from_ne_bytes([octets[0], octets[1], octets[2], octets[3]]);

        unsafe { std::mem::transmute(addr) }
    }

    fn configure_interface(name: &str, ip: &str, netmask: &str) -> nix::Result<()> {
        // Create a socket for ioctl operations
        let sock = socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), None)?;
        let fd = sock.as_raw_fd();

        // Set IP address
        let mut ifr = Ifreq::default();
        set_interface_name(&mut ifr, name);
        ifr.ifr_ifru.ifru_addr = make_sockaddr_in(ip);
        unsafe { ioctl_siocsifaddr(fd, &mut ifr)? };

        // Set netmask
        let mut ifr = Ifreq::default();
        set_interface_name(&mut ifr, name);
        ifr.ifr_ifru.ifru_addr = make_sockaddr_in(netmask);
        unsafe { ioctl_siocsifnetmask(fd, &mut ifr)? };

        // Get current flags
        let mut ifr = Ifreq::default();
        set_interface_name(&mut ifr, name);
        unsafe { ioctl_siocgifflags(fd, &mut ifr)? };

        // Set UP and RUNNING flags
        unsafe {
            ifr.ifr_ifru.ifru_flags |= IFF_UP | IFF_RUNNING;
        }
        unsafe { ioctl_siocsifflags(fd, &mut ifr)? };

        Ok(())
    }

    fn expect_msg(stream: &mut TcpStream, expected: &[u8]) {
        let mut buf = vec![0; expected.len()];
        stream.read_exact(&mut buf[..]).unwrap();
        assert_eq!(&buf[..], expected);
    }

    fn set_timeouts(stream: &mut TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_millis(500)))
            .unwrap();
    }

    impl Test for TestNetPasst {
        fn in_guest(self: Box<Self>) {
            // Configure the eth0 interface
            configure_interface("eth0", GUEST_IP, NETMASK)
                .expect("Failed to configure eth0");

            // Connect to the host TCP server
            let addr = SocketAddr::new(IpAddr::V4(HOST_IP.parse().unwrap()), PORT);

            // Retry connection a few times since network may take time to come up
            let mut stream = None;
            for _ in 0..10 {
                match TcpStream::connect(addr) {
                    Ok(s) => {
                        stream = Some(s);
                        break;
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            }
            let mut stream = stream.expect("Failed to connect to host");
            set_timeouts(&mut stream);

            // Run the TCP test protocol (same as TcpTester::run_client)
            expect_msg(&mut stream, b"ping!");
            stream.write_all(b"pong!").unwrap();
            expect_msg(&mut stream, b"bye!");

            println!("OK");
        }
    }
}
