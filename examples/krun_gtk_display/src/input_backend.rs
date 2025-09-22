use crate::input_constants;
use crate::input_constants::*;
use krun_input::{
    InputAbsInfo, InputBackendError, InputDeviceIds, InputEvent as KrunInputEvent, InputEventType,
    InputEventsImpl, InputQueryConfig, ObjectNew, write_bitmap,
};
use std::cmp::max;
use std::mem;
use std::os::fd::RawFd;
use utils::pollable_channel::PollableChannelReciever;

pub const KRUN_VENDOR_ID: u16 = u16::from_le_bytes(*b"RH");
pub const KEYBOARD_DEVICE_NAME: &[u8] = b"libkrun Virtual Keyboard";
pub const KEYBOARD_SERIAL_NAME: &[u8] = b"KRUN-KBD";
pub const KEYBOARD_PRODUCT_ID: u16 = 0x0001;

pub const MOUSE_DEVICE_NAME: &[u8] = b"libkrun Virtual Mouse";
pub const MOUSE_SERIAL_NAME: &[u8] = b"KRUN-MOUSE";
pub const MOUSE_PRODUCT_ID: u16 = 0x0002;

pub const TOUCHSCREEN_DEVICE_NAME: &[u8] = b"libkrun Touchscreen";
pub const TOUCHSCREEN_SERIAL_NAME: &[u8] = b"KRUN-TOUCH";
pub const TOUCHSCREEN_PRODUCT_ID: u16 = 0x0003;

// GTK to Linux input key code mapping
pub const GTK_KEY_OFFSET: u32 = 8;

/// Convert GTK key code to Linux input key code
/// Returns the Linux input key code or 0 if no mapping exists
pub fn gtk_keycode_to_linux(gtk_key: u32) -> u16 {
    // GTK key codes are typically offset by 8 from Linux input key codes
    if gtk_key >= GTK_KEY_OFFSET {
        let linux_key = (gtk_key - GTK_KEY_OFFSET) as u16;
        // Verify the key is in our supported set
        if SUPPORTED_KEYBOARD_KEYS.contains(&linux_key) {
            linux_key
        } else {
            0 // Unsupported key
        }
    } else {
        0 // Invalid key
    }
}

pub struct GtkInputEventProvider {
    rx: PollableChannelReciever<KrunInputEvent>,
}

impl ObjectNew<PollableChannelReciever<KrunInputEvent>> for GtkInputEventProvider {
    fn new(userdata: Option<&PollableChannelReciever<KrunInputEvent>>) -> Self {
        Self {
            rx: userdata.expect("GtkInputEvents requires receiver").clone(),
        }
    }
}

impl InputEventsImpl for GtkInputEventProvider {
    fn get_read_notify_fd(&self) -> Result<RawFd, InputBackendError> {
        use std::os::fd::AsRawFd;
        Ok(self.rx.as_raw_fd())
    }

    fn next_event(&mut self) -> Result<Option<KrunInputEvent>, InputBackendError> {
        match self.rx.try_recv() {
            Ok(Some(event)) => Ok(Some(event)),
            Ok(None) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(_) => Err(InputBackendError::InternalError),
        }
    }
}

#[derive(Clone)]
pub struct GtkKeyboardConfig;

impl ObjectNew<()> for GtkKeyboardConfig {
    fn new(_userdata: Option<&()>) -> Self {
        Self
    }
}

impl InputQueryConfig for GtkKeyboardConfig {
    fn query_device_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        let copy_len = std::cmp::min(KEYBOARD_DEVICE_NAME.len(), name_buf.len());
        name_buf[..copy_len].copy_from_slice(&KEYBOARD_DEVICE_NAME[..copy_len]);
        Ok(copy_len as u8)
    }

    fn query_serial_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        let copy_len = std::cmp::min(KEYBOARD_SERIAL_NAME.len(), name_buf.len());
        name_buf[..copy_len].copy_from_slice(&KEYBOARD_SERIAL_NAME[..copy_len]);
        Ok(copy_len as u8)
    }

    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<u8, InputBackendError> {
        *ids = InputDeviceIds {
            bustype: BUS_VIRTUAL,
            vendor: KRUN_VENDOR_ID,
            product: KEYBOARD_PRODUCT_ID,
            version: 1,
        };
        Ok(size_of::<InputDeviceIds>() as u8)
    }

    fn query_event_capabilities(
        &self,
        event_type: u8,
        bitmap_buf: &mut [u8],
    ) -> Result<u8, InputBackendError> {
        let event_type_enum = InputEventType::try_from(event_type as u16)
            .map_err(|_| InputBackendError::InvalidParam)?;
        match event_type_enum {
            InputEventType::Syn => {
                let key_events = write_bitmap(bitmap_buf, SUPPORTED_KEYBOARD_KEYS);
                let rep_events = write_bitmap(bitmap_buf, &[/*REP_DELAY, REP_PERIOD*/]);
                Ok(max(key_events, rep_events))
            }
            InputEventType::Key => Ok(write_bitmap(bitmap_buf, SUPPORTED_KEYBOARD_KEYS)),
            InputEventType::Rep => Ok(write_bitmap(bitmap_buf, &[/*REP_DELAY, REP_PERIOD*/])),
            _ => Ok(0),
        }
    }

    fn query_abs_info(
        &self,
        _abs_axis: u8,
        _abs_info: &mut InputAbsInfo,
    ) -> Result<u8, InputBackendError> {
        Ok(0)
    }

    fn query_properties(&self, bitmap: &mut [u8]) -> Result<u8, InputBackendError> {
        Ok(write_bitmap(bitmap, &[]))
    }
}

#[derive(Clone)]
pub struct GtkMouseConfig;

impl ObjectNew<()> for GtkMouseConfig {
    fn new(_userdata: Option<&()>) -> Self {
        Self
    }
}

impl InputQueryConfig for GtkMouseConfig {
    fn query_device_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        let copy_len = std::cmp::min(MOUSE_DEVICE_NAME.len(), name_buf.len());
        name_buf[..copy_len].copy_from_slice(&MOUSE_DEVICE_NAME[..copy_len]);
        Ok(copy_len as u8)
    }

    fn query_serial_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        let copy_len = std::cmp::min(MOUSE_SERIAL_NAME.len(), name_buf.len());
        name_buf[..copy_len].copy_from_slice(&MOUSE_SERIAL_NAME[..copy_len]);
        Ok(copy_len as u8)
    }

    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<u8, InputBackendError> {
        *ids = InputDeviceIds {
            bustype: BUS_VIRTUAL,
            vendor: KRUN_VENDOR_ID,
            product: MOUSE_PRODUCT_ID,
            version: 1,
        };
        Ok(size_of::<InputDeviceIds>() as u8)
    }

    fn query_event_capabilities(
        &self,
        event_type: u8,
        bitmap_buf: &mut [u8],
    ) -> Result<u8, InputBackendError> {
        let event_type_enum = InputEventType::try_from(event_type as u16)
            .map_err(|_| InputBackendError::InvalidParam)?;

        match event_type_enum {
            InputEventType::Syn => Ok(write_bitmap(
                bitmap_buf,
                &[REL_X, REL_Y, REL_WHEEL, BTN_LEFT, BTN_RIGHT, BTN_MIDDLE],
            )),
            InputEventType::Key => Ok(write_bitmap(bitmap_buf, &[BTN_LEFT, BTN_RIGHT, BTN_MIDDLE])),
            InputEventType::Rel => Ok(write_bitmap(bitmap_buf, &[REL_X, REL_Y, REL_WHEEL])),
            _ => Ok(0),
        }
    }

    fn query_abs_info(
        &self,
        _abs_axis: u8,
        _abs_info: &mut InputAbsInfo,
    ) -> Result<u8, InputBackendError> {
        // We emit relative movement (REL events), not absolute positioning (ABS events), hence we don't specify the axis
        Ok(0)
    }

    fn query_properties(&self, properties: &mut [u8]) -> Result<u8, InputBackendError> {
        Ok(write_bitmap(
            properties,
            &[INPUT_PROP_POINTER, INPUT_PROP_DIRECT],
        ))
    }
}

#[derive(Clone)]
pub struct GtkTouchscreenConfig;

impl ObjectNew<()> for GtkTouchscreenConfig {
    fn new(_userdata: Option<&()>) -> Self {
        Self
    }
}

impl InputQueryConfig for GtkTouchscreenConfig {
    fn query_device_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        let copy_len = std::cmp::min(TOUCHSCREEN_DEVICE_NAME.len(), name_buf.len());
        name_buf[..copy_len].copy_from_slice(&TOUCHSCREEN_DEVICE_NAME[..copy_len]);
        Ok(copy_len as u8)
    }

    fn query_serial_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        let copy_len = std::cmp::min(TOUCHSCREEN_SERIAL_NAME.len(), name_buf.len());
        name_buf[..copy_len].copy_from_slice(&TOUCHSCREEN_SERIAL_NAME[..copy_len]);
        Ok(copy_len as u8)
    }

    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<u8, InputBackendError> {
        *ids = InputDeviceIds {
            bustype: BUS_VIRTUAL,
            vendor: KRUN_VENDOR_ID,
            product: TOUCHSCREEN_PRODUCT_ID,
            version: 1,
        };
        Ok(size_of::<InputDeviceIds>() as u8)
    }

    fn query_event_capabilities(
        &self,
        event_type: u8,
        bitmap_buf: &mut [u8],
    ) -> Result<u8, InputBackendError> {
        let event_type_enum = InputEventType::try_from(event_type as u16)
            .map_err(|_| InputBackendError::InvalidParam)?;

        match event_type_enum {
            InputEventType::Syn => Ok(write_bitmap(bitmap_buf, &[BTN_TOUCH, ABS_X, ABS_Y, ABS_MT_POSITION_X, ABS_MT_POSITION_Y])),
            InputEventType::Key => Ok(write_bitmap(bitmap_buf, &[BTN_TOUCH])),
            InputEventType::Abs => Ok(write_bitmap(
                bitmap_buf,
                &[
                    ABS_MT_SLOT,
                    ABS_X,
                    ABS_Y, ABS_MT_POSITION_X, ABS_MT_POSITION_Y
                ],
            )),
            _ => Ok(0),
        }
    }

    fn query_abs_info(
        &self,
        abs_axis: u8,
        abs_info: &mut InputAbsInfo,
    ) -> Result<u8, InputBackendError> {
        match abs_axis as u16 {
            input_constants::ABS_MT_SLOT => {
                *abs_info = InputAbsInfo {
                    min: 0,
                    max: 10,
                    fuzz: 0,
                    flat: 0,
                    res: 0,
                };
                Ok(mem::size_of::<InputAbsInfo>() as u8)
            }
            input_constants::ABS_MT_TOOL_TYPE => {
                *abs_info = InputAbsInfo {
                    min: 0,
                    max: 2,
                    fuzz: 0,
                    flat: 0,
                    res: 0,
                };
                Ok(mem::size_of::<InputAbsInfo>() as u8)
            }
            input_constants::ABS_MT_POSITION_X => {
                *abs_info = InputAbsInfo {
                    min: 0,
                    max: 13764,
                    fuzz: 0,
                    flat: 0,
                    res: 0,
                };
                Ok(mem::size_of::<InputAbsInfo>() as u8)
            }
            input_constants::ABS_MT_POSITION_Y => {
                *abs_info = InputAbsInfo {
                    min: 0,
                    max: 7740,
                    fuzz: 0,
                    flat: 0,
                    res: 0,
                };
                Ok(mem::size_of::<InputAbsInfo>() as u8)
            }
            input_constants::ABS_X => {
                *abs_info = InputAbsInfo {
                    min: 0,
                    max: 13764,
                    fuzz: 0,
                    flat: 0,
                    res: 40,
                };
                Ok(mem::size_of::<InputAbsInfo>() as u8)
            }
            input_constants::ABS_Y => {
                *abs_info = InputAbsInfo {
                    min: 0,
                    max: 7740,
                    fuzz: 0,
                    flat: 0,
                    res: 40,
                };
                Ok(mem::size_of::<InputAbsInfo>() as u8)
            }
            _ => Ok(0),
        }
    }

    fn query_properties(&self, properties: &mut [u8]) -> Result<u8, InputBackendError> {
        Ok(write_bitmap(properties, &[INPUT_PROP_DIRECT]))
    }
}
