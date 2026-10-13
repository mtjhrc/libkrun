use crate::TouchScreenOptions;
use crate::input_constants::*;
use krun::{
    InputAbsInfo, InputBackendError, InputDeviceIds, InputEvent as KrunInputEvent, InputEventType,
    InputEventsImpl, InputQueryConfig,
};
use krun_input::write_bitmap;
use std::cmp::{max, min};
use std::io::ErrorKind;
use std::os::fd::{AsFd, BorrowedFd};
use utils::pollable_channel::PollableChannelReciever;

pub const KRUN_VENDOR_ID: u16 = u16::from_le_bytes(*b"RH");
pub const KEYBOARD_DEVICE_NAME: &[u8] = b"libkrun Virtual Keyboard";
pub const KEYBOARD_SERIAL_NAME: &[u8] = b"KRUN-KBD";
pub const KEYBOARD_PRODUCT_ID: u16 = 0x0001;

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

impl GtkInputEventProvider {
    pub fn new(rx: PollableChannelReciever<KrunInputEvent>) -> Self {
        Self { rx }
    }
}

impl InputEventsImpl for GtkInputEventProvider {
    fn get_read_notify_fd(&self) -> Result<BorrowedFd<'_>, InputBackendError> {
        Ok(self.rx.as_fd())
    }

    fn next_event(&mut self) -> Result<Option<KrunInputEvent>, InputBackendError> {
        match self.rx.try_recv() {
            Ok(Some(event)) => Ok(Some(event)),
            Ok(None) => Ok(None),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(_) => Err(InputBackendError::InternalError()),
        }
    }
}

pub const MAX_FINGERS: usize = 16;

#[derive(Clone)]
pub enum GtkInputConfig {
    Keyboard,
    TouchScreen(TouchScreenOptions),
}

impl InputQueryConfig for GtkInputConfig {
    fn query_device_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        let name = match self {
            Self::Keyboard => KEYBOARD_DEVICE_NAME,
            Self::TouchScreen(options) => options
                .device_name
                .as_deref()
                .map(str::as_bytes)
                .unwrap_or(TOUCHSCREEN_DEVICE_NAME),
        };
        let copy_len = min(name.len(), name_buf.len());
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Ok(copy_len as u8)
    }

    fn query_serial_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
        let name = match self {
            Self::Keyboard => KEYBOARD_SERIAL_NAME,
            Self::TouchScreen(_) => TOUCHSCREEN_SERIAL_NAME,
        };
        let copy_len = min(name.len(), name_buf.len());
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Ok(copy_len as u8)
    }

    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError> {
        *ids = InputDeviceIds {
            bustype: BUS_VIRTUAL,
            vendor: KRUN_VENDOR_ID,
            product: match self {
                Self::Keyboard => KEYBOARD_PRODUCT_ID,
                Self::TouchScreen(_) => TOUCHSCREEN_PRODUCT_ID,
            },
            version: 1,
        };
        Ok(())
    }

    fn query_event_capabilities(
        &self,
        event_type: u8,
        bitmap_buf: &mut [u8],
    ) -> Result<u8, InputBackendError> {
        let event_type = [
            InputEventType::Syn,
            InputEventType::Key,
            InputEventType::Rel,
            InputEventType::Abs,
            InputEventType::Msc,
            InputEventType::Sw,
            InputEventType::Led,
            InputEventType::Snd,
            InputEventType::Rep,
        ]
        .into_iter()
        .find(|candidate| *candidate as u8 == event_type)
        .ok_or_else(InputBackendError::InvalidParam)?;

        match (self, event_type) {
            (Self::Keyboard, InputEventType::Syn) => {
                let key_events = write_bitmap(bitmap_buf, SUPPORTED_KEYBOARD_KEYS);
                let rep_events = write_bitmap(bitmap_buf, &[/*REP_DELAY, REP_PERIOD*/]);
                Ok(max(key_events, rep_events))
            }
            (Self::Keyboard, InputEventType::Key) => {
                Ok(write_bitmap(bitmap_buf, SUPPORTED_KEYBOARD_KEYS))
            }
            (Self::Keyboard, InputEventType::Rep) => {
                Ok(write_bitmap(bitmap_buf, &[/*REP_DELAY, REP_PERIOD*/]))
            }
            (Self::TouchScreen(options), InputEventType::Key) if options.emit_non_mt => {
                Ok(write_bitmap(bitmap_buf, &[BTN_TOUCH]))
            }
            (Self::TouchScreen(options), InputEventType::Abs) => {
                let bitmap_len1 = if options.emit_non_mt {
                    write_bitmap(bitmap_buf, &[ABS_X, ABS_Y])
                } else {
                    0
                };
                let bitmap_len2 = if options.emit_mt {
                    write_bitmap(
                        bitmap_buf,
                        &[
                            ABS_MT_SLOT,
                            ABS_MT_TRACKING_ID,
                            ABS_MT_POSITION_X,
                            ABS_MT_POSITION_Y,
                        ],
                    )
                } else {
                    0
                };
                Ok(max(bitmap_len1, bitmap_len2))
            }
            _ => Ok(0),
        }
    }

    fn query_abs_info(
        &self,
        abs_axis: u8,
        abs_info: &mut InputAbsInfo,
    ) -> Result<(), InputBackendError> {
        let Self::TouchScreen(options) = self else {
            return Ok(());
        };
        match abs_axis as u16 {
            ABS_MT_SLOT => {
                *abs_info = InputAbsInfo {
                    min: 0,
                    max: MAX_FINGERS as i32,
                    fuzz: 0,
                    flat: 0,
                    res: 0,
                };
            }
            ABS_MT_TOOL_TYPE => {
                *abs_info = InputAbsInfo {
                    min: 0,
                    max: 2,
                    fuzz: 0,
                    flat: 0,
                    res: 0,
                };
            }
            ABS_MT_POSITION_X if options.emit_mt => {
                *abs_info = options.area.x.into();
            }
            ABS_MT_POSITION_Y if options.emit_mt => {
                *abs_info = options.area.y.into();
            }
            ABS_X if options.emit_non_mt => {
                *abs_info = options.area.x.into();
            }
            ABS_Y if options.emit_non_mt => {
                *abs_info = options.area.y.into();
            }
            ABS_MT_TRACKING_ID => {
                *abs_info = InputAbsInfo {
                    min: 0,
                    max: u16::MAX as i32,
                    fuzz: 0,
                    flat: 0,
                    res: 0,
                };
            }
            _ => (),
        };
        Ok(())
    }

    fn query_properties(&self, properties: &mut [u8]) -> Result<u8, InputBackendError> {
        let active = match self {
            Self::Keyboard => &[][..],
            Self::TouchScreen(_) => &[INPUT_PROP_DIRECT][..],
        };
        Ok(write_bitmap(properties, active))
    }
}
