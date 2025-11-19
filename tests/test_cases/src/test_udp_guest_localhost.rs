use macros::{guest, host};

/// Test UDP communication within the guest (localhost to localhost).
/// This verifies that the TSI hijack feature doesn't break UDP on localhost.
/// The custom kernel's TSI layer should NOT intercept localhost UDP traffic.
pub struct TestUdpGuestLocalhost;

impl TestUdpGuestLocalhost {
    pub fn new() -> Self {
        Self
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;

    impl Test for TestUdpGuestLocalhost {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
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
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use std::thread;
    use std::time::Duration;

    const PORT: u16 = 9001;

    impl Test for TestUdpGuestLocalhost {
        fn in_guest(self: Box<Self>) {
            // Start server thread within the guest

            let server_thread = thread::spawn(|| {
                let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT))
                    .expect("Failed to bind server socket");
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();

                let tester = DatagramTester::new(socket);
                tester.run_server();
            });

            // Give server time to start
            thread::sleep(Duration::from_millis(1000));

            // Start client in the same guest
            let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .expect("Failed to bind client socket");
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            let server_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT).into();
            let tester = DatagramTester::new(socket);
            tester.run_client(server_addr);

            // Wait for server to finish
            //server_thread.join().expect("Server thread panicked");

            println!("OK");
        }
    }
}
