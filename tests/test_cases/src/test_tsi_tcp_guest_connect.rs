use crate::tcp_tester::TcpTester;
use macros::{guest, host};
use std::net::Ipv4Addr;

const PORT: u16 = 8000;

pub struct TestTsiTcpGuestConnect {
    tcp_tester: TcpTester,
}

impl TestTsiTcpGuestConnect {
    pub fn new() -> TestTsiTcpGuestConnect {
        Self {
            tcp_tester: TcpTester::new(Ipv4Addr::LOCALHOST, PORT),
        }
    }
}

#[host]
mod host {
    use super::*;

    use std::thread;

    use crate::common::{init_krun, setup_standard_devices};
    use crate::{Test, TestSetup};

    const TSI_HIJACK_INET: u32 = 1;

    impl Test for TestTsiTcpGuestConnect {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let listener = self.tcp_tester.create_server_socket();
            thread::spawn(move || self.tcp_tester.run_server(listener));

            init_krun()?;

            let (mut devices, payload) = setup_standard_devices(&test_setup, &[])?;
            devices.add(
                krun::VsockDevice::new(3, TSI_HIJACK_INET)
                    .map_err(|e| anyhow::anyhow!("VsockDevice: {e:?}"))?,
            );

            let mut vmm = krun::VmmBuilder::new()
                .vcpus(1)
                .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
                .ram_mib(512)
                .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|e| anyhow::anyhow!("build: {e:?}"))?;

            vmm.run();
            unreachable!()
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    impl Test for TestTsiTcpGuestConnect {
        fn in_guest(self: Box<Self>) {
            self.tcp_tester.run_client();
            println!("OK");
        }
    }
}
