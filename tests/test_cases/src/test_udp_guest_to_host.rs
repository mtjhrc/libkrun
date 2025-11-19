use macros::{guest, host};

const PORT: u16 = 9002;

/// Test UDP communication from guest to host.
/// This verifies that the guest can send UDP packets to the host via TSI.
pub struct TestUdpGuestToHost;

impl TestUdpGuestToHost {
    pub fn new() -> Self {
        Self
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::datagram_tester::DatagramTester;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use std::thread;
    use std::time::Duration;

    impl Test for TestUdpGuestToHost {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // Create server socket on the host
            let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT))
                .expect("Failed to bind host socket");
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            // Run server in a separate thread
            thread::spawn(move || {
                let tester = DatagramTester::new(socket);
                tester.run_server();
            });

            // Start the VM
            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_DEBUG))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::datagram_tester::DatagramTester;
    use crate::Test;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::thread;
    use std::time::Duration;

    impl Test for TestUdpGuestToHost {
        fn in_guest(self: Box<Self>) {
            // Give host server time to start
            thread::sleep(Duration::from_millis(100));

            // Create client socket in guest
            let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                .expect("Failed to bind guest socket");
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            // Connect to host on 127.0.0.1 - this should be intercepted by TSI
            let host_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), PORT);

            let tester = DatagramTester::new(socket);
            tester.run_client(host_addr);

            println!("OK");
        }
    }
}
