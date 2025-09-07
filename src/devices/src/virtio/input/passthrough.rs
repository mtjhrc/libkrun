use std::ffi::c_int;
use std::mem::MaybeUninit;
use krun_input::{
    InputAbsInfo, InputBackendError, ObjectNew, InputDeviceIds, InputEvent, InputEventsImpl,
    InputQueryConfig,
};
use nix::{errno::Errno, ioctl_read, ioctl_read_buf, unistd};
use std::os::fd::RawFd;
use libc::abs;

/// Internal passthrough input backend that forwards host /dev/input/* devices
pub struct PassthroughInputBackend {
    fd: RawFd,
}

impl PassthroughInputBackend {
    pub fn new(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl InputQueryConfig for PassthroughInputBackend {
    fn query_serial_name(&self, serial_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        match unsafe { eviocguniq(self.fd, serial_buf) } {
            Ok(len) => Ok(len as u8),
            Err(e) => {
                error!("Failed to get device serial (eviocguniq): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }

    fn query_device_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        match unsafe { eviocgname(self.fd, name_buf) } {
            Ok(len) => Ok(len as u8),
            Err(e) => {
                error!("Failed to get device name (eviocgname): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }

    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<u8, InputBackendError> {
        match unsafe { eviocgid(self.fd, ids) } {
            Ok(_) => Ok(size_of_val(&ids) as u8),
            Err(e) => {
                error!("Failed to get device information ids (eviocgid): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }

    fn query_event_capabilities(
        &self,
        event_type: u8,
        bitmap_buf: &mut [u8],
    ) -> Result<u8, InputBackendError> {
        match unsafe { eviocgbit(self.fd, event_type, bitmap_buf) } {
            Ok(_) => Ok(size_of_val(&bitmap_buf) as u8),
            Err(e) => {
                error!("Failed to get device event capabilities (eviocgbit): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }

    fn query_abs_info(
        &self,
        abs_axis: u8,
        abs_info: &mut InputAbsInfo,
    ) -> Result<u8, InputBackendError> {
        match unsafe { eviocgabs(self.fd, abs_axis, abs_info) } {
            Ok(len) => Ok(len as u8),
            Err(e) => {
                error!("Failed to get device abs_info (eviocgabs): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }

    fn query_properties(&self, properties: &mut [u8]) -> Result<u8, InputBackendError> {
        match unsafe { eviocgprop(self.fd, properties) } {
            Ok(len) => Ok(len as u8),
            Err(e) => {
                error!("Failed to query device properties (eviocgprop): {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }
}

impl ObjectNew<RawFd> for PassthroughInputBackend {
    fn new(userdata: Option<&RawFd>) -> Self {
        let fd = userdata.copied().expect("Missing argument for PassthroughInputBackend::new");
        Self { fd }
    }
}

impl InputEventsImpl for PassthroughInputBackend {
    fn get_read_notify_fd(&self) -> Result<RawFd, InputBackendError> {
        Ok(self.fd)
    }

    fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError> {
        let mut event = unsafe { std::mem::zeroed::<InputEvent>() };
        let event_slice = unsafe {
            std::slice::from_raw_parts_mut(&mut event as *mut _ as *mut u8, size_of::<InputEvent>())
        };

        match unistd::read(self.fd, event_slice) {
            Ok(bytes_read) if bytes_read == size_of::<InputEvent>() => Ok(Some(event)),
            Ok(_bytes_read) => {
                error!("Partial read from /dev/input was unexpected, not implemented!");
                Err(InputBackendError::InternalError)
            }
            Err(e) => {
                error!("Failed to read event from input device: {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }
}

ioctl_read!(eviocgid, b'E', 0x02, InputDeviceIds);
ioctl_read_buf!(eviocgname, b'E', 0x06, u8);
ioctl_read_buf!(eviocguniq, b'E', 0x08, u8);
ioctl_read_buf!(eviocgprop, b'E', 0x09, u8);

unsafe fn eviocgbit(fd: RawFd, evt: u8, buf: &mut [u8]) -> Result<u32, Errno> {
    let ioctl_num =
        nix::request_code_read!(b'E', 0x20 + evt, buf.len());

    let n = libc::ioctl(
        fd,
        ioctl_num as _,
        buf.as_mut_ptr(),
    );
    if n < 0 {
        return Err(Errno::last());
    }
    Ok(n as u32)
}

unsafe fn eviocgabs(fd: RawFd, axis: u8, abs_info: &mut InputAbsInfo) -> Result<u32, Errno> {
    let ioctl_num =
        nix::request_code_read!(b'E', 0x40 + axis, size_of::<InputAbsInfo>());

    let n = libc::ioctl(
        fd,
        ioctl_num as _,
        abs_info as *mut _,
    );
    if n < 0 {
        return Err(Errno::last());
    }
    Ok(n as u32)
}