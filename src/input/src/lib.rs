#![cfg(not(target_os = "windows"))]

use std::cmp::max;
use std::os::fd::BorrowedFd;

use thiserror::Error;

#[derive(Error, Debug, ffier::FfiError)]
#[non_exhaustive]
pub enum InputBackendError {
    #[error("Backend implementation error")]
    #[ffier(code = 1)]
    InternalError,
    #[error("Try again later")]
    #[ffier(code = 2)]
    Again,
    #[error("Method not supported")]
    #[ffier(code = 3)]
    MethodNotSupported,
    #[error("Invalid parameter")]
    #[ffier(code = 4)]
    InvalidParam,
}

/// Input event types matching Linux input event types
#[ffier::export]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum InputEventType {
    Syn = 0x00, // EV_SYN
    Key = 0x01, // EV_KEY
    Rel = 0x02, // EV_REL
    Abs = 0x03, // EV_ABS
    Msc = 0x04, // EV_MSC
    Sw = 0x05,  // EV_SW
    Led = 0x11, // EV_LED
    Snd = 0x12, // EV_SND
    Rep = 0x14, // EV_REP
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

impl From<InputEventType> for u16 {
    fn from(val: InputEventType) -> Self {
        val as u16
    }
}

#[ffier::export]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct InputEvent {
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

#[ffier::export]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct InputDeviceIds {
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

#[ffier::export]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct InputAbsInfo {
    pub min: i32,
    pub max: i32,
    pub fuzz: i32,
    pub flat: i32,
    pub res: i32,
}

#[ffier::export]
pub trait InputQueryConfig: Send + Sync {
    #[ffier(index = 0)]
    fn query_device_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError>;

    #[ffier(index = 1)]
    fn query_serial_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError>;

    #[ffier(index = 2)]
    fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError>;

    #[ffier(index = 3)]
    fn query_event_capabilities(
        &self,
        event_type: u8,
        bitmap_buf: &mut [u8],
    ) -> Result<u8, InputBackendError>;

    #[ffier(index = 4)]
    fn query_abs_info(
        &self,
        abs_axis: u8,
        abs_info: &mut InputAbsInfo,
    ) -> Result<(), InputBackendError>;

    #[ffier(index = 5)]
    fn query_properties(&self, properties: &mut [u8]) -> Result<u8, InputBackendError>;
}

#[ffier::export]
pub trait InputEventsImpl: Send {
    /// The descriptor becomes readable when input events are available and must
    /// remain valid while the backend is owned by the device.
    #[ffier(index = 0)]
    fn get_read_notify_fd(&self) -> Result<BorrowedFd<'_>, InputBackendError>;

    /// Returns immediately, with None when no events are available.
    #[ffier(index = 1)]
    fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError>;
}

/// Writes the specific bits in bitmap, given the indices of the bits
/// Return the "length" of the newly constructed bitmap
pub fn write_bitmap(bitmap: &mut [u8], active_bits: &[u16]) -> u8 {
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
