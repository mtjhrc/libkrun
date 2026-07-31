//! Unified virtio-net integration tests
//!
//! All tests follow the same pattern:
//! 1. Host: Start backend + TCP server
//! 2. Guest: Connect to host TCP server (eth0 configured via DHCP by init)

use crate::tcp_tester::TcpTester;
use macros::{guest, host};

#[host]
use crate::{ShouldRun, TestSetup};

// TODO: export this via ffier from libkrun and use the generated constant instead
#[cfg(any(feature = "host", feature = "host-ffi"))]
pub(crate) const COMPAT_NET_FEATURES: u32 = (1 << 0)  // CSUM
    | (1 << 1)  // GUEST_CSUM
    | (1 << 7)  // GUEST_TSO4
    | (1 << 10) // GUEST_UFO
    | (1 << 11) // HOST_TSO4
    | (1 << 14); // HOST_UFO

#[cfg(any(feature = "host", feature = "host-ffi"))]
pub(crate) mod gvproxy;
#[cfg(any(feature = "host", feature = "host-ffi"))]
pub(crate) mod passt;
#[cfg(any(feature = "host", feature = "host-ffi"))]
pub(crate) mod tap;
#[cfg(any(feature = "host", feature = "host-ffi"))]
pub(crate) mod vmnet_helper;

/// Virtio-net test with configurable backend
pub struct TestNet {
    tcp_tester: TcpTester,
    #[cfg(any(feature = "host", feature = "host-ffi"))]
    should_run: fn() -> ShouldRun,
    #[cfg(any(feature = "host", feature = "host-ffi"))]
    setup_backend: fn(&TestSetup) -> anyhow::Result<krun::NetDevice>,
    #[cfg(any(feature = "host", feature = "host-ffi"))]
    cleanup: Option<fn()>,
}

impl TestNet {
    pub fn new_passt() -> Self {
        Self {
            tcp_tester: TcpTester::new([169, 254, 2, 2].into(), 9000),
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            should_run: passt::should_run,
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            setup_backend: passt::setup_backend,
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            cleanup: None,
        }
    }

    pub fn new_tap() -> Self {
        Self {
            tcp_tester: TcpTester::new([10, 0, 0, 1].into(), 9001),
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            should_run: tap::should_run,
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            setup_backend: tap::setup_backend,
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            cleanup: Some(tap::cleanup),
        }
    }

    pub fn new_gvproxy() -> Self {
        Self {
            tcp_tester: TcpTester::new([192, 168, 127, 254].into(), 9002),
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            should_run: gvproxy::should_run,
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            setup_backend: gvproxy::setup_backend,
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            cleanup: None,
        }
    }

    pub fn new_vmnet_helper() -> Self {
        Self {
            tcp_tester: TcpTester::new([192, 168, 105, 1].into(), 9003),
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            should_run: vmnet_helper::should_run,
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            setup_backend: vmnet_helper::setup_backend,
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            cleanup: None,
        }
    }

    /// Gvproxy backend variant with a socket path ≥ 96 bytes, triggering the
    /// ENAMETOOLONG bug when the local socket was derived from the peer path.
    pub fn new_gvproxy_long_path() -> Self {
        Self {
            tcp_tester: TcpTester::new([192, 168, 127, 254].into(), 9004),
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            should_run: gvproxy::should_run,
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            setup_backend: gvproxy::setup_backend_long_path,
            #[cfg(any(feature = "host", feature = "host-ffi"))]
            cleanup: None,
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::{init_config_builder, init_krun, setup_standard_devices_from};
    use crate::{Test, TestOutcome, TestSetup};

    use std::thread;

    #[cfg(feature = "host-ffi")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(None, &[
            krun::Symbol::KrunNetDeviceNewUnixgramPath,
            krun::Symbol::KrunNetDeviceNewUnixgramFd,
            krun::Symbol::KrunNetDeviceNewUnixstreamPath,
            krun::Symbol::KrunNetDeviceNewUnixstreamFd,
            krun::Symbol::KrunNetDeviceNewTap,
            krun::Symbol::KrunNetDeviceDestroy,
        ])
    }

    impl Test for TestNet {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "host-ffi")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            (self.should_run)()
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            if let Some(cleanup) = self.cleanup {
                cleanup();
            }
            let output = String::from_utf8(stdout).unwrap();
            if output == "OK\n" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!("expected exactly {:?}, got {:?}", "OK\n", output))
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let tcp_tester = self.tcp_tester;
            let listener = tcp_tester.create_server_socket();
            thread::spawn(move || tcp_tester.run_server(listener));

            init_krun()?;
            #[cfg(feature = "host-ffi")]
            require_symbols().unwrap();

            let builder = init_config_builder(&test_setup, &[]).dhcp(true);
            let (mut devices, payload) = setup_standard_devices_from(&test_setup, builder)?;

            let net_device = (self.setup_backend)(&test_setup)?;
            devices.add(net_device);

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

    impl Test for TestNet {
        fn in_guest(self: Box<Self>) {
            self.tcp_tester.run_client();

            println!("OK");
        }
    }
}
