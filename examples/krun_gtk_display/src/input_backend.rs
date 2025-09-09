use crate::input_constants::*;
use krun_input::{
    InputAbsInfo, InputBackendError, InputDeviceIds, InputEvent as KrunInputEvent, InputEventType,
    InputEventsImpl, InputQueryConfig, ObjectNew, write_bitmap,
};
use std::cmp::max;
use std::os::fd::RawFd;
use utils::pollable_channel::PollableChannelReciever;

#[derive(Clone)]
pub enum DeviceType {
    Keyboard,
    Mouse,
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
            product: KRUN_KEYBOARD_PRODUCT_ID,
            version: KRUN_DEVICE_VERSION,
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
                let rep_events = write_bitmap(bitmap_buf, &[REP_DELAY, REP_PERIOD]);
                Ok(max(key_events, rep_events))
            }
            InputEventType::Key => Ok(write_bitmap(bitmap_buf, SUPPORTED_KEYBOARD_KEYS)),
            InputEventType::Rep => Ok(write_bitmap(bitmap_buf, &[REP_DELAY, REP_PERIOD])),
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
            bustype: BUS_USB,
            vendor: KRUN_VENDOR_ID,
            product: KRUN_MOUSE_PRODUCT_ID,
            version: KRUN_DEVICE_VERSION,
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
