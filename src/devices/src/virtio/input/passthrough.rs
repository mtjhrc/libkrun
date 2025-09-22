use imago::raw::Raw;
use krun_input::{
    InputAbsInfo, InputBackendError, InputDeviceIds, InputEvent, InputEventsImpl, InputQueryConfig,
    ObjectNew,
};
use libc::{abs, fcntl, F_GETFL, F_SETFL, O_NONBLOCK};
use nix::{errno::Errno, ioctl_read, ioctl_read_buf, unistd};
use std::cmp::max;
use std::ffi::c_int;
use std::mem;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, RawFd};

/// Internal passthrough input backend that forwards host /dev/input/* devices
pub struct PassthroughInputBackend {
    fd: RawFd,
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
        /*
        if event_type == 0 {
            fn write_bitmap(bitmap: &mut [u8], active_bits: &[u16]) -> u8 {
                let mut max_byte: u8 = 0;
                for idx in active_bits {
                    let byte_pos = (idx / 8).try_into().unwrap();
                    let additional_bit = 1 << (idx % 8);
                    if byte_pos as usize > bitmap.len() {
                        panic!("Bit index {idx} out of bounds");
                    }
                    bitmap[byte_pos as usize] |= additional_bit;
                    max_byte = max(max_byte, byte_pos);
                }
                max_byte.checked_add(1).unwrap()
            }
            pub const BTN_TOUCH: u16 = 0x14a;
            pub const ABS_X: u16 = 0x00;
            pub const ABS_Y: u16 = 0x01;
            pub const ABS_MT_POSITION_X: u16 = 0x35;
            pub const ABS_MT_POSITION_Y: u16 = 0x36;

            return Ok(write_bitmap(bitmap_buf, &[BTN_TOUCH, ABS_X, ABS_Y, ABS_MT_POSITION_X, ABS_MT_POSITION_Y]));
        }*/
        match unsafe { eviocgbit(self.fd, event_type, bitmap_buf) } {
            Ok(n) => {
                let len = find_length(&bitmap_buf[..n as usize]) as u8;
                debug!(
                    "eviocgbit: {event_type}, got {n} bytes (from n): {:#?}",
                    &bitmap_buf[..n as usize]
                );
                Ok(len)
            }
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
        let mut linux_abs_info = LinuxAbsInfo::default();
        match unsafe { eviocgabs(self.fd, abs_axis, &mut linux_abs_info) } {
            Ok(_) => {
                *abs_info = InputAbsInfo {
                    min: linux_abs_info.minimum,
                    max: linux_abs_info.maximum,
                    fuzz: linux_abs_info.fuzz,
                    flat: linux_abs_info.flat,
                    res: linux_abs_info.resolution,
                };
                Ok(size_of::<InputAbsInfo>() as u8)
            }
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
        let fd = userdata
            .copied()
            .expect("Missing argument for PassthroughInputBackend::new");

        make_non_blocking(fd)
            .expect("Cannot make device fd non-blocking (Invalid file descriptor?)");
        Self { fd }
    }
}

impl InputEventsImpl for PassthroughInputBackend {
    fn get_read_notify_fd(&self) -> Result<RawFd, InputBackendError> {
        Ok(self.fd)
    }

    fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError> {
        let mut linux_event = unsafe { std::mem::zeroed::<LinuxInputEvent>() };
        let event_slice = unsafe {
            std::slice::from_raw_parts_mut(
                &mut linux_event as *mut _ as *mut u8,
                size_of::<LinuxInputEvent>(),
            )
        };

        match unistd::read(self.fd, event_slice) {
            Ok(bytes_read) if bytes_read == size_of::<LinuxInputEvent>() => {
                trace!("Forwarding input: {linux_event:?}");
                Ok(Some(InputEvent {
                    type_: linux_event.type_,
                    code: linux_event.code,
                    value: linux_event.value,
                }))
            }
            Ok(_bytes_read) => {
                error!("Partial read from /dev/input was unexpected, not implemented!");
                Err(InputBackendError::InternalError)
            }
            Err(Errno::EAGAIN) => Ok(None),
            Err(e) => {
                error!("Failed to read event from input device: {e}");
                Err(InputBackendError::InternalError)
            }
        }
    }
}

#[repr(C)]
#[derive(Debug)]
struct LinuxInputEvent {
    time: libc::timeval,
    type_: u16,
    code: u16,
    value: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
struct LinuxAbsInfo {
    value: u32,
    minimum: u32,
    maximum: u32,
    fuzz: u32,
    flat: u32,
    resolution: u32,
}

ioctl_read!(eviocgid, b'E', 0x02, InputDeviceIds); // Kernel uapi struct is the same as virtio
ioctl_read_buf!(eviocgname, b'E', 0x06, u8);
ioctl_read_buf!(eviocguniq, b'E', 0x08, u8);
ioctl_read_buf!(eviocgprop, b'E', 0x09, u8);

unsafe fn eviocgbit(fd: RawFd, evt: u8, buf: &mut [u8]) -> Result<u32, Errno> {
    let ioctl_num = nix::request_code_read!(b'E', 0x20 + evt, buf.len());

    let n = libc::ioctl(fd, ioctl_num as _, buf.as_mut_ptr());
    if n < 0 {
        return Err(Errno::last());
    }
    Ok(n as u32)
}

unsafe fn eviocgabs(fd: RawFd, axis: u8, abs_info: &mut LinuxAbsInfo) -> Result<u32, Errno> {
    let ioctl_num = nix::request_code_read!(b'E', 0x40 + axis, size_of::<LinuxAbsInfo>());

    let n = libc::ioctl(fd, ioctl_num as _, abs_info as *mut _);
    if n < 0 {
        return Err(Errno::last());
    }
    Ok(mem::size_of::<InputAbsInfo>() as u32)
}

fn make_non_blocking(fd: RawFd) -> Result<(), nix::Error> {
    unsafe {
        let flags = fcntl(fd, F_GETFL, 0);
        if flags < 0 {
            return Err(Errno::last());
        }

        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(Errno::last());
        }
    }
    Ok(())
}

fn find_length(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|b| *b != 0)
        .map(|idx| idx + 1)
        .unwrap_or(0)
}
