//! virtio-net integration test with TAP backend
//!
//! This test verifies the virtio-net device using a TAP interface by:
//! 1. Host: Checking that tap0 exists and configuring virtio-net to use it
//! 2. Guest: Configuring the network interface (eth0) using ioctl syscalls
//! 3. Testing TCP connectivity between guest and host using TcpTester

use macros::{guest, host};

const PORT: u16 = 8001;

pub struct TestNetTap;

impl TestNetTap {
    pub fn new() -> Self {
        Self
    }
}

#[host]
mod host {
    use super::*;
    use crate::tcp_tester::TcpTester;
    use nix::libc;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32, Test, TestSetup};
    use krun_sys::*;
    use std::ffi::{c_char, CString};
    use std::thread;

    // Type alias for krun_add_net_tap function
    type KrunAddNetTapFn = unsafe extern "C" fn(
        ctx_id: u32,
        c_tap_name: *const c_char,
        c_mac: *mut u8,
        features: u32,
        flags: u32,
    ) -> i32;

    /// Try to get krun_add_net_tap function pointer via dlsym
    /// Returns None if the function doesn't exist (libkrun compiled without NET)
    fn get_krun_add_net_tap() -> Option<KrunAddNetTapFn> {
        let symbol = CString::new("krun_add_net_tap").unwrap();
        let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute(ptr) })
        }
    }

    /// Check if tap0 interface exists
    fn tap_exists(name: &str) -> bool {
        std::path::Path::new(&format!("/sys/class/net/{}", name)).exists()
    }

    impl Test for TestNetTap {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // Get tap name from environment variable, skip if not set
            let tap_name_str = match std::env::var("LIBKRUN_TAP_NAME") {
                Ok(name) => name,
                Err(_) => {
                    println!("SKIP");
                    return Ok(());
                }
            };

            // Check if krun_add_net_tap is available (libkrun compiled with NET)
            let krun_add_net_tap = match get_krun_add_net_tap() {
                Some(f) => f,
                None => {
                    println!("SKIP");
                    return Ok(());
                }
            };

            // Check if tap exists
            if !tap_exists(&tap_name_str) {
                println!("SKIP");
                return Ok(());
            }

            // Start TCP server
            let tcp_tester = TcpTester::new(PORT);
            let listener = tcp_tester.create_server_socket();
            thread::spawn(move || tcp_tester.run_server(listener));

            // MAC address for the virtio-net interface
            let mut mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
            let tap_name = CString::new(tap_name_str).unwrap();

            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;

                // Add virtio-net with tap backend
                let net_result = krun_add_net_tap(
                    ctx,
                    tap_name.as_ptr(),
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

    // Guest IP configuration for tap0
    // tap0 on host should be configured with 10.0.0.1/24
    // Guest gets 10.0.0.2/24
    const GUEST_IP: &str = "10.0.0.2";
    const NETMASK: &str = "255.255.255.0";
    const HOST_IP: &str = "10.0.0.1";

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

    impl Test for TestNetTap {
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
