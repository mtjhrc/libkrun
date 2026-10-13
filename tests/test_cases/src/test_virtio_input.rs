use macros::{guest, host};

pub struct TestVirtioInput;

#[cfg(any(feature = "guest", feature = "input", feature = "dynamic-linking"))]
mod protocol {
    pub const DEVICE_NAME: &str = "libkrun ffier integration input";
    pub const SERIAL: &str = "ffier-input-e2e";
    pub const CONTROL_PORT: &str = "input-test-control";
    pub const EV_SYN: u16 = 0;
    pub const EV_KEY: u16 = 1;
    pub const EV_REL: u16 = 2;
    pub const EV_ABS: u16 = 3;
    pub const KEY_A: u16 = 30;
    pub const EVENTS: [(u16, u16, i32); 8] = [
        (EV_KEY, KEY_A, 1),
        (EV_REL, 0, -17),
        (EV_ABS, 0, -127),
        (EV_SYN, 0, 0),
        (EV_KEY, KEY_A, 0),
        (EV_REL, 0, 9),
        (EV_ABS, 0, 321),
        (EV_SYN, 0, 0),
    ];
}

#[host]
#[cfg(not(any(feature = "input", feature = "dynamic-linking")))]
mod disabled {
    use super::TestVirtioInput;
    use crate::{ShouldRun, Test, TestSetup};

    impl Test for TestVirtioInput {
        fn should_run(&self) -> ShouldRun {
            ShouldRun::No("input feature not enabled in this test build")
        }

        fn start_vm(self: Box<Self>, _test_setup: TestSetup) -> anyhow::Result<()> {
            unreachable!()
        }
    }
}

#[host]
#[cfg(any(feature = "input", feature = "dynamic-linking"))]
mod host {
    use super::TestVirtioInput;
    use super::protocol::*;
    use crate::common::{build_init_config, init_krun, setup_standard_devices};
    use crate::{ShouldRun, Test, TestSetup};
    use krun::{
        InputAbsInfo, InputBackendError, InputDeviceIds, InputEvent, InputEventsImpl,
        InputQueryConfig,
    };
    use std::cmp::min;
    use std::io::{self, BufRead, BufReader, ErrorKind};
    use std::os::fd::{AsFd, BorrowedFd};
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::thread;
    use std::time::Duration;

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        use krun::Symbol::*;
        krun::require(
            None,
            &[
                KrunInputDeviceNew,
                KrunInputDeviceDestroy,
                KrunErrorNew,
                KrunConsoleBuilderAddInoutPort,
            ],
        )
    }

    struct InputConfig;

    fn write_config(source: &[u8], destination: &mut [u8]) -> u8 {
        let len = min(source.len(), destination.len());
        destination[..len].copy_from_slice(&source[..len]);
        len as u8
    }

    impl InputQueryConfig for InputConfig {
        fn query_device_name(&self, name: &mut [u8]) -> Result<u8, InputBackendError> {
            Ok(write_config(DEVICE_NAME.as_bytes(), name))
        }

        fn query_serial_name(&self, name: &mut [u8]) -> Result<u8, InputBackendError> {
            Ok(write_config(SERIAL.as_bytes(), name))
        }

        fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError> {
            *ids = InputDeviceIds {
                bustype: 0x06,
                vendor: 0x1234,
                product: 0xabcd,
                version: 0x0102,
            };
            Ok(())
        }

        fn query_event_capabilities(
            &self,
            event_type: u8,
            bitmap: &mut [u8],
        ) -> Result<u8, InputBackendError> {
            let bits: &[u8] = match u16::from(event_type) {
                EV_SYN | EV_REL | EV_ABS => &[1],
                EV_KEY => &[0, 0, 0, 0x40],
                _ => &[],
            };
            Ok(write_config(bits, bitmap))
        }

        fn query_abs_info(
            &self,
            axis: u8,
            info: &mut InputAbsInfo,
        ) -> Result<(), InputBackendError> {
            if axis != 0 {
                return Err(InputBackendError::InvalidParam());
            }
            *info = InputAbsInfo {
                min: -2048,
                max: 2047,
                fuzz: 0,
                flat: 0,
                res: 7,
            };
            Ok(())
        }

        fn query_properties(&self, bitmap: &mut [u8]) -> Result<u8, InputBackendError> {
            Ok(write_config(&[1], bitmap))
        }
    }

    struct InputEvents {
        receiver: UnixDatagram,
    }

    impl InputEventsImpl for InputEvents {
        fn get_read_notify_fd(&self) -> Result<BorrowedFd<'_>, InputBackendError> {
            Ok(self.receiver.as_fd())
        }

        fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError> {
            let mut bytes = [0; 8];
            match self.receiver.recv(&mut bytes) {
                Ok(8) => Ok(Some(InputEvent {
                    type_: u16::from_ne_bytes(bytes[..2].try_into().unwrap()),
                    code: u16::from_ne_bytes(bytes[2..4].try_into().unwrap()),
                    value: i32::from_ne_bytes(bytes[4..].try_into().unwrap()),
                })),
                Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(None),
                _ => Err(InputBackendError::InternalError()),
            }
        }
    }

    fn deliver_events(control: UnixStream, sender: UnixDatagram) -> io::Result<()> {
        let mut ready = String::new();
        BufReader::new(control).read_line(&mut ready)?;
        assert_eq!(ready, "READY\n", "guest input handshake");
        for (type_, code, value) in EVENTS {
            let mut bytes = [0; 8];
            bytes[..2].copy_from_slice(&type_.to_ne_bytes());
            bytes[2..4].copy_from_slice(&code.to_ne_bytes());
            bytes[4..].copy_from_slice(&value.to_ne_bytes());
            assert_eq!(sender.send(&bytes)?, bytes.len());
        }
        Ok(())
    }

    impl Test for TestVirtioInput {
        fn should_run(&self) -> ShouldRun {
            if cfg!(target_arch = "riscv64") {
                return ShouldRun::No("riscv64 firmware does not enable virtio input");
            }
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("input feature not enabled in this libkrun build");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols()?;

            let stdin = io::stdin();
            let stdout = io::stdout();
            let stderr = io::stderr();
            let init_config = build_init_config(&test_setup.test_case, &[]);
            let (guest_control, host_control) = UnixStream::pair()?;
            host_control.set_read_timeout(Some(Duration::from_secs(25)))?;
            let (sender, receiver) = UnixDatagram::pair()?;
            receiver.set_nonblocking(true)?;
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;

            let mut console = krun::ConsoleDevice::builder();
            console
                .add_inout_port(
                    CONTROL_PORT,
                    Some(guest_control.as_fd()),
                    Some(guest_control.as_fd()),
                )
                .map_err(|error| anyhow::anyhow!("input control console: {error:?}"))?;
            devices.add(
                console
                    .build()
                    .map_err(|error| anyhow::anyhow!("input control console: {error:?}"))?,
            );
            devices.add(krun::InputDevice::new(
                InputConfig,
                InputEvents { receiver },
            ));

            let vmm = krun::VmmBuilder::new()
                .vcpus(1)
                .map_err(|error| anyhow::anyhow!("vcpus: {error:?}"))?
                .ram_mib(256)
                .map_err(|error| anyhow::anyhow!("ram_mib: {error:?}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|error| anyhow::anyhow!("build: {error:?}"))?;

            thread::spawn(move || {
                deliver_events(host_control, sender).expect("deliver guest input events");
            });
            vmm.run();
            unreachable!()
        }

        fn timeout_secs(&self) -> u64 {
            30
        }
    }
}

#[guest]
#[cfg(target_os = "linux")]
mod guest {
    use super::TestVirtioInput;
    use super::protocol::*;
    use crate::Test;
    use nix::{ioctl_read, libc};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::{Duration, Instant};

    #[repr(C)]
    #[derive(Debug, Default, PartialEq, Eq)]
    struct AbsInfo {
        value: i32,
        min: i32,
        max: i32,
        fuzz: i32,
        flat: i32,
        resolution: i32,
    }

    ioctl_read!(read_abs_x, b'E', 0x40, AbsInfo);

    fn find_device(class: &str, prefix: &str, name_attribute: &str, name: &str) -> PathBuf {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(entries) = fs::read_dir(class) {
                for entry in entries {
                    let path = entry.unwrap().path();
                    if path
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with(prefix)
                        && fs::read_to_string(path.join(name_attribute))
                            .is_ok_and(|value| value.trim() == name)
                    {
                        return path;
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "device {name:?} missing in {class}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn check_bitmap(path: &Path, expected: &[u16]) {
        let value = fs::read_to_string(path).unwrap();
        let mut bits = Vec::new();
        for (index, word) in value.split_whitespace().rev().enumerate() {
            let word = usize::from_str_radix(word, 16).unwrap();
            for bit in 0..usize::BITS {
                if word & (1 << bit) != 0 {
                    bits.push((index * usize::BITS as usize + bit as usize) as u16);
                }
            }
        }
        assert_eq!(bits, expected, "bitmap {}", path.display());
    }

    impl Test for TestVirtioInput {
        fn in_guest(self: Box<Self>) {
            let event = find_device("/sys/class/input", "event", "device/name", DEVICE_NAME);
            let device = event.join("device");
            assert_eq!(
                fs::read_to_string(device.join("uniq")).unwrap().trim(),
                SERIAL
            );
            for (field, expected) in [
                ("bustype", "0006"),
                ("vendor", "1234"),
                ("product", "abcd"),
                ("version", "0102"),
            ] {
                assert_eq!(
                    fs::read_to_string(device.join("id").join(field))
                        .unwrap()
                        .trim(),
                    expected,
                    "input ID {field}",
                );
            }
            check_bitmap(
                &device.join("capabilities/ev"),
                &[EV_SYN, EV_KEY, EV_REL, EV_ABS],
            );
            check_bitmap(&device.join("capabilities/key"), &[KEY_A]);
            check_bitmap(&device.join("capabilities/rel"), &[0]);
            check_bitmap(&device.join("capabilities/abs"), &[0]);
            check_bitmap(&device.join("properties"), &[0]);

            let mut input = File::open(Path::new("/dev/input").join(event.file_name().unwrap()))
                .expect("open guest evdev input");
            let mut abs = AbsInfo::default();
            unsafe { read_abs_x(input.as_raw_fd(), &mut abs) }.expect("EVIOCGABS(ABS_X)");
            assert_eq!(
                abs,
                AbsInfo {
                    value: 0,
                    min: -2048,
                    max: 2047,
                    fuzz: 0,
                    flat: 0,
                    resolution: 7,
                },
            );

            let control = find_device("/sys/class/virtio-ports", "vport", "name", CONTROL_PORT);
            let mut control = OpenOptions::new()
                .read(true)
                .write(true)
                .open(Path::new("/dev").join(control.file_name().unwrap()))
                .expect("open input control port");
            control.write_all(b"READY\n").unwrap();

            for expected in EVENTS {
                let mut bytes = [0; size_of::<libc::timeval>() + 8];
                input
                    .read_exact(&mut bytes)
                    .expect("read guest evdev input");
                let event = &bytes[size_of::<libc::timeval>()..];
                let actual = (
                    u16::from_ne_bytes(event[..2].try_into().unwrap()),
                    u16::from_ne_bytes(event[2..4].try_into().unwrap()),
                    i32::from_ne_bytes(event[4..].try_into().unwrap()),
                );
                assert_eq!(actual, expected, "guest evdev event");
            }
            println!("OK");
        }
    }
}
