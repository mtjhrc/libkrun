#![cfg(unix)]

use ffier::{FFIER_RESULT_SUCCESS, FfierMutBytes, FfierResult};
use krun_via_cdylib_weak::{
    self as krun, FfiType, InputAbsInfo, InputBackendError, InputDevice, InputDeviceIds,
    InputEvent, InputEventsImpl, InputQueryConfig, Symbol,
};
use libloading::os::unix::{Library, RTLD_GLOBAL, RTLD_NOW};
use std::ffi::c_void;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

static LIBRARY: OnceLock<Library> = OnceLock::new();

struct Config(Arc<AtomicUsize>);

impl Drop for Config {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl InputQueryConfig for Config {
    fn query_device_name(&self, buffer: &mut [u8]) -> Result<u8, InputBackendError> {
        buffer[..5].copy_from_slice(b"ffier");
        Ok(5)
    }

    fn query_serial_name(&self, _: &mut [u8]) -> Result<u8, InputBackendError> {
        Ok(0)
    }

    fn query_device_ids(&self, _: &mut InputDeviceIds) -> Result<(), InputBackendError> {
        Ok(())
    }

    fn query_event_capabilities(&self, _: u8, _: &mut [u8]) -> Result<u8, InputBackendError> {
        Ok(0)
    }

    fn query_abs_info(&self, _: u8, _: &mut InputAbsInfo) -> Result<(), InputBackendError> {
        Ok(())
    }

    fn query_properties(&self, _: &mut [u8]) -> Result<u8, InputBackendError> {
        Ok(0)
    }
}

struct Events {
    fd: File,
    next: usize,
    drops: Arc<AtomicUsize>,
}

impl Drop for Events {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl InputEventsImpl for Events {
    fn get_read_notify_fd(&self) -> Result<BorrowedFd<'_>, InputBackendError> {
        Ok(self.fd.as_fd())
    }

    fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError> {
        let next = self.next;
        self.next += 1;
        match next {
            0 => Ok(Some(InputEvent {
                type_: 3,
                code: 0x4321,
                value: -123_456,
            })),
            1 => Ok(None),
            _ => Err(InputBackendError::InternalError()),
        }
    }
}

#[test]
#[ignore = "requires libkrun built with FFI=1 INPUT=1; set KRUN_INPUT_TEST_LIBRARY to override its path"]
fn generated_callbacks_cross_the_native_input_abi() {
    let library = LIBRARY.get_or_init(|| {
        let path = std::env::var_os("KRUN_INPUT_TEST_LIBRARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../target/debug")
                    .join(if cfg!(target_os = "macos") {
                        "libkrun.dylib"
                    } else {
                        "libkrun.so"
                    })
            });
        unsafe { Library::open(Some(&path), RTLD_NOW | RTLD_GLOBAL) }
            .unwrap_or_else(|error| panic!("failed to load {}: {error}", path.display()))
    });
    krun::require(
        None,
        &[
            Symbol::KrunErrorNew,
            Symbol::KrunErrorDestroy,
            Symbol::KrunInputDeviceNew,
            Symbol::KrunInputDeviceDestroy,
        ],
    )
    .unwrap();

    type QueryName =
        unsafe extern "C" fn(*mut c_void, FfierMutBytes, *mut u8, *mut *mut c_void) -> FfierResult;
    type NotifyFd = unsafe extern "C" fn(*mut c_void, *mut RawFd, *mut *mut c_void) -> FfierResult;
    type NextEvent = unsafe extern "C" fn(
        *mut c_void,
        *mut bool,
        *mut <InputEvent as FfiType>::CRepr,
        *mut *mut c_void,
    ) -> FfierResult;
    let query_name =
        unsafe { library.get::<QueryName>(b"krun_input_query_config_query_device_name\0") }
            .unwrap();
    let notify_fd =
        unsafe { library.get::<NotifyFd>(b"krun_input_events_impl_get_read_notify_fd\0") }.unwrap();
    let next_event =
        unsafe { library.get::<NextEvent>(b"krun_input_events_impl_next_event\0") }.unwrap();

    let config_drops = Arc::new(AtomicUsize::new(0));
    let events_drops = Arc::new(AtomicUsize::new(0));
    let config = Config(config_drops.clone()).__into_callback_handle();
    let fd = File::open("/dev/null").unwrap();
    let expected_fd = fd.as_raw_fd();
    let events = Events {
        fd,
        next: 0,
        drops: events_drops.clone(),
    }
    .__into_callback_handle();

    let mut buffer = [0xa5; 12];
    let mut length = 0;
    let mut error = ptr::null_mut();
    let status = unsafe {
        query_name(
            config.as_raw(),
            buffer.as_mut_slice().into_c(),
            &mut length,
            &mut error,
        )
    };
    assert_eq!(status, FFIER_RESULT_SUCCESS);
    assert!(error.is_null());
    assert_eq!(length, 5);
    assert_eq!(&buffer[..5], b"ffier");
    assert_eq!(&buffer[5..], &[0xa5; 7]);

    let mut returned_fd = -1;
    let status = unsafe { notify_fd(events.as_raw(), &mut returned_fd, &mut error) };
    assert_eq!(status, FFIER_RESULT_SUCCESS);
    assert!(error.is_null());
    assert_eq!(returned_fd, expected_fd);

    let mut present = false;
    let mut event = InputEvent {
        type_: 0,
        code: 0,
        value: 0,
    }
    .into_c();
    let status = unsafe { next_event(events.as_raw(), &mut present, &mut event, &mut error) };
    assert_eq!(status, FFIER_RESULT_SUCCESS);
    assert!(error.is_null());
    assert!(present);
    assert_eq!(
        (event.type_, event.code, event.value),
        (3, 0x4321, -123_456)
    );

    let status = unsafe { next_event(events.as_raw(), &mut present, &mut event, &mut error) };
    assert_eq!(status, FFIER_RESULT_SUCCESS);
    assert!(error.is_null());
    assert!(!present);
    assert_eq!(
        (event.type_, event.code, event.value),
        (3, 0x4321, -123_456)
    );

    present = true;
    let status = unsafe { next_event(events.as_raw(), &mut present, &mut event, &mut error) };
    assert_ne!(status, FFIER_RESULT_SUCCESS);
    assert!(!error.is_null());
    assert!(present);
    assert_eq!(
        (event.type_, event.code, event.value),
        (3, 0x4321, -123_456)
    );
    assert!(matches!(
        unsafe { InputBackendError::from_ffi(status, error) },
        InputBackendError::InternalError()
    ));
    assert_eq!(config_drops.load(Ordering::SeqCst), 0);
    assert_eq!(events_drops.load(Ordering::SeqCst), 0);
    drop(config);
    drop(events);
    assert_eq!(config_drops.load(Ordering::SeqCst), 1);
    assert_eq!(events_drops.load(Ordering::SeqCst), 1);

    let device = InputDevice::new(
        Config(config_drops.clone()),
        Events {
            fd: File::open("/dev/null").unwrap(),
            next: 0,
            drops: events_drops.clone(),
        },
    );
    assert_eq!(config_drops.load(Ordering::SeqCst), 1);
    assert_eq!(events_drops.load(Ordering::SeqCst), 1);
    drop(device);
    assert_eq!(config_drops.load(Ordering::SeqCst), 2);
    assert_eq!(events_drops.load(Ordering::SeqCst), 2);
}
