use crate::udp_tester::UdpTester;
use macros::{guest, host};

const PORT: u16 = 8001;

pub struct TestTsiUdp {
    udp_tester: UdpTester,
}

impl TestTsiUdp {
    pub fn new() -> TestTsiUdp {
        Self {
            udp_tester: UdpTester::new(PORT),
        }
    }
}

#[host]
mod host {
    use super::*;

    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;
    use std::thread;

    impl Test for TestTsiUdp {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let socket = self.udp_tester.create_server_socket();
            thread::spawn(move || self.udp_tester.run_server(socket));
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
    use crate::Test;

    impl Test for TestTsiUdp {
        fn in_guest(self: Box<Self>) {
            self.udp_tester.run_client();
            println!("OK");
        }
    }
}
