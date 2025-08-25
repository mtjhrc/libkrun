mod rust_to_c;
pub use rust_to_c::*;
mod c_to_rust;
pub use c_to_rust::*;

use thiserror::Error;

#[allow(
    non_upper_case_globals,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unused_variables
)]
mod header {
    include!(concat!(env!("OUT_DIR"), "/input_header.rs"));
}

#[derive(Error, Debug)]
#[repr(i32)]
pub enum InputBackendError {
    #[error("Backend implementation error")]
    InternalError = header::KRUN_INPUT_ERR_INTERNAL,
    #[error("Try again later")]
    Again = header::KRUN_INPUT_ERR_EAGAIN,
    #[error("Method not supported")]
    MethodNotSupported = header::KRUN_INPUT_ERR_METHOD_UNSUPPORTED,
    #[error("Invalid parameter")]
    InvalidParam = header::KRUN_INPUT_ERR_INVALID_PARAM,
}

/// Input event types matching Linux input event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum InputEventType {
    Syn = 0x00,     // EV_SYN
    Key = 0x01,     // EV_KEY
    Rel = 0x02,     // EV_REL
    Abs = 0x03,     // EV_ABS
    Msc = 0x04,     // EV_MSC
    Sw = 0x05,      // EV_SW
    Led = 0x11,     // EV_LED
    Snd = 0x12,     // EV_SND
    Rep = 0x14,     // EV_REP
}

impl TryFrom<u16> for InputEventType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Syn),
            0x01 => Ok(Self::Key),
            0x02 => Ok(Self::Rel),
            0x03 => Ok(Self::Abs),
            0x04 => Ok(Self::Msc),
            0x05 => Ok(Self::Sw),
            0x11 => Ok(Self::Led),
            0x12 => Ok(Self::Snd),
            0x14 => Ok(Self::Rep),
            _ => Err(()),
        }
    }
}

impl Into<u16> for InputEventType {
    fn into(self) -> u16 {
        self as u16
    }
}

pub type InputEvent = header::krun_input_event;
pub type InputDeviceIds = header::krun_input_device_ids;
pub type InputAbsInfo = header::krun_input_absinfo;
pub type InputEventsVtable = header::krun_input_events_vtable;
pub type InputConfigVtable = header::krun_input_config_vtable;
pub type InputBackend = header::krun_input_backend;
