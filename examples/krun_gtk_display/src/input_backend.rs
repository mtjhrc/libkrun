use krun_input::{
    InputAbsInfo, InputBackendError, InputBackendNew, InputConfigImpl, InputDeviceIds,
    InputEvent as KrunInputEvent, InputEvent, InputEventsImpl, IntoInputBackend,
};
use log::{debug, error};
use std::os::fd::{AsRawFd, RawFd};
use utils::pollable_channel::{PollableChannelReciever, PollableChannelSender};

pub struct GtkInputEvents {
    event_rx: PollableChannelReciever<KrunInputEvent>,
}

impl InputBackendNew<PollableChannelReciever<InputEvent>> for GtkInputEvents {
    fn new(userdata: Option<&PollableChannelReciever<InputEvent>>) -> Self {
        debug!("Created GtkInputEvents");
        Self {
            event_rx: userdata.expect("Invalid param").clone(),
        }
    }
}

impl InputEventsImpl for GtkInputEvents {
    fn get_ready_efd(&self) -> Result<RawFd, InputBackendError> {
        debug!("get_ready_efd");
        Ok(self.event_rx.as_raw_fd())
    }

    fn next_event(&mut self) -> Result<Option<KrunInputEvent>, InputBackendError> {
        match self.event_rx.try_recv() {
            Ok(Some(event)) => {
                debug!(
                    "Retrieved input event: type={}, code={}, value={}",
                    event.type_, event.code, event.value
                );
                Ok(Some(event))
            }
            Ok(None) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(_) => Err(InputBackendError::InternalError),
        }
    }
}

pub struct GtkInputConfig {}

impl<T: Send + Sync> InputBackendNew<T> for GtkInputConfig {
    fn new(_userdata: Option<&T>) -> Self {
        Self {}
    }
}

impl InputConfigImpl for GtkInputConfig {
    fn write_device_name(&self, buffer: &mut [u8]) -> Result<usize, InputBackendError> {
        let name = b"libkrun/gui_vm virtual keyboard";
        let copy_len = name.len().min(buffer.len());
        buffer[..copy_len].copy_from_slice(&name[..copy_len]);
        Ok(copy_len)
    }

    fn write_device_serial(&self, buffer: &mut [u8]) -> Result<usize, InputBackendError> {
        let serial = b"virtio-keyboard-1";
        let copy_len = serial.len().min(buffer.len());
        buffer[..copy_len].copy_from_slice(&serial[..copy_len]);
        Ok(copy_len)
    }

    fn write_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError> {
        *ids = InputDeviceIds {
            bustype: 0,
            vendor: 0,
            product: 0,
            version: 0,
        };
        Ok(())
    }

    fn write_abs_info(
        &self,
        _axis: u16,
        _abs_info: &mut InputAbsInfo,
    ) -> Result<(), InputBackendError> {
        Err(InputBackendError::MethodNotSupported) // Keyboard doesn't have absolute axes
    }

    fn write_event_bits(
        &self,
        event_type: u16,
        buffer: &mut [u8],
    ) -> Result<usize, InputBackendError> {
        const EV_KEY: u16 = 0x01;
        const EV_REL: u16 = 0x02;
        const EV_REP: u16 = 0x14;

        const REL_X: u16 = 0x00;
        const REL_Y: u16 = 0x01;
        const REL_Z: u16 = 0x02;
        const REL_RX: u16 = 0x03;
        const REL_RY: u16 = 0x04;
        const REL_RZ: u16 = 0x05;
        const REL_HWHEEL: u16 = 0x06;
        const REL_DIAL: u16 = 0x07;
        const REL_WHEEL: u16 = 0x08;

        const REP_DELAY: u16 = 0x00;
        const REP_PERIOD: u16 = 0x01;

        fn write_bits(buffer: &mut [u8], indices: &[u16]) -> usize {
            let mut len = 0;
            for idx in indices {
                let byte_pos = (idx / 8) as usize;
                let bit_byte = 1u8 << (idx % 8);
                if byte_pos < buffer.len() {
                    len = std::cmp::max(len, byte_pos + 1);
                    buffer[byte_pos] |= bit_byte;
                } else {
                    // This would only happen if new event codes (or types, or ABS_*, etc) are defined
                    // to be larger than or equal to 1024, in which case a new version
                    // of the virtio input protocol needs to be defined.
                    // There is nothing we can do about this error except log it.
                    error!("Attempted to set an out of bounds bit: {}", idx);
                }
            }
            len as usize
        }

        match event_type {
            EV_KEY => {
                // For a keyboard, we support all key codes (0-767)
                // This requires 768 bits = 96 bytes
                let required_bytes = 96;
                if buffer.len() < required_bytes {
                    return Ok(required_bytes);
                }

                // Set all bits to 1 (all keys supported)
                buffer[..required_bytes].fill(0xFF);
                Ok(required_bytes)
            }
            EV_REP => {
                write_bits(buffer, &[REP_DELAY, REP_PERIOD]);
                Ok(1)
            }
            EV_REL => {
                write_bits(buffer, &[REL_X, REL_Y, REL_WHEEL]);
                Ok(1)
            }
            _ => {
                error!("Unsupported: {}", event_type);
                Ok(0)
            } // No other event types supported
        }
    }

    fn write_property_bits(&self, buffer: &mut [u8]) -> Result<usize, InputBackendError> {
        buffer.fill(0);
        Ok(buffer.len())
    }
}

/// Convert GTK key code to Linux input key code
pub fn gtk_key_to_linux(gtk_key: u32) -> u16 {
    // GTK key codes are offset by 8 from Linux input key codes
    if gtk_key >= 8 {
        (gtk_key - 8) as u16
        //(gtk_key - 8) as u16 //TODO: check if this way or other way around
    } else {
        0 // Invalid key
    }
}
