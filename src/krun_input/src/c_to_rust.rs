use crate::{InputBackendError, InputEvent, InputEventsVtable, InputConfigVtable, InputDeviceIds, InputAbsInfo, header};
use log::error;
use static_assertions::assert_not_impl_any;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::fd::RawFd;
use std::ptr::{null, null_mut};


#[macro_export]
macro_rules! into_rust_result {
    ($expr:expr) => {
        into_rust_result!($expr,
            0 => Ok(()),
            code @ 0.. => {
                log::warn!("{}: Unknown OK result code: {code}", stringify!($expr));
                Ok(())
            }
        )
    };
    ($expr:expr, $($pat:pat $(if $pat_guard:expr)? => $pat_expr:expr),+ ) => {
        match $expr {
            $($pat $(if $pat_guard)? => $pat_expr,)+
            -1 => Err(InputBackendError::InternalError),
            -2 => Err(InputBackendError::Again),
            -3 => Err(InputBackendError::MethodNotSupported),
            -4 => Err(InputBackendError::InvalidParam),
            code @ i32::MIN.. => {
                log::warn!("{}: Unknown error result code: {code}", stringify!($expr));
                Err(InputBackendError::InternalError)
            }
        }
    };
}

macro_rules! method_call {
    ($self:ident.$method:ident($($args:expr),*) ) => {
        unsafe {
            $self.vtable.$method
                .ok_or(InputBackendError::MethodNotSupported)?( $self.instance, $($args),* )
        }
    };
}

pub struct InputEventsInstance {
    instance: *mut c_void,
    vtable: InputEventsVtable,
}

pub struct InputConfigInstance {
    instance: *mut c_void,
    vtable: InputConfigVtable,
}

// By design the structs are !Send and !Sync to allow for the implementation to safely assume that
// the methods are always called on the appropriate worker thread
assert_not_impl_any!(InputEventsInstance: Sync, Send);
assert_not_impl_any!(InputConfigInstance: Sync, Send);

impl Drop for InputEventsInstance {
    fn drop(&mut self) {
        let Some(destroy_fn) = self.vtable.destroy else {
            return;
        };

        if let Err(e) = into_rust_result!(unsafe { destroy_fn(self.instance) }) {
            error!("Failed to destroy krun input events instance: {e}");
        }
    }
}

impl Drop for InputConfigInstance {
    fn drop(&mut self) {
        let Some(destroy_fn) = self.vtable.destroy else {
            return;
        };

        if let Err(e) = into_rust_result!(unsafe { destroy_fn(self.instance) }) {
            error!("Failed to destroy krun input config instance: {e}");
        }
    }
}

impl InputEventsInstance {
    /// Get the ready event file descriptor that becomes readable when input events are available
    pub fn get_ready_efd(&self) -> Result<RawFd, InputBackendError> {
        let fd = method_call! {
            self.get_ready_efd()
        };
        
        if fd < 0 {
            into_rust_result!(fd, _ => unreachable!())
        } else {
            Ok(fd)
        }
    }

    /// Fetch the next available input event, returns None if no events are available
    pub fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError> {
        let mut event = header::krun_input_event {
            type_: 0,
            code: 0,
            value: 0,
        };

        let result = method_call! {
            self.next_event(&raw mut event)
        };

        match result {
            1 => Ok(Some(InputEvent {
                type_: event.type_,
                code: event.code,
                value: event.value,
            })),
            0 => Ok(None),
            _ => into_rust_result!(result, _ => unreachable!()),
        }
    }
}

impl InputConfigInstance {
    /// Write the device name to the provided buffer (low-level, allocation-free)
    /// Returns the number of bytes written (excluding null terminator)
    pub fn write_device_name(&self, buffer: &mut [u8]) -> Result<usize, InputBackendError> {
        if buffer.is_empty() {
            return Err(InputBackendError::InvalidParam);
        }
        
        let result = method_call! {
            self.get_device_name(buffer.as_mut_ptr() as *mut i8, buffer.len())
        };
        into_rust_result!(result)?;
        
        // Find the length (excluding null terminator)
        let len = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        Ok(len)
    }
    
    /// Write the device serial to the provided buffer (low-level, allocation-free)  
    /// Returns the number of bytes written (excluding null terminator)
    pub fn write_device_serial(&self, buffer: &mut [u8]) -> Result<usize, InputBackendError> {
        if buffer.is_empty() {
            return Err(InputBackendError::InvalidParam);
        }
        
        let result = method_call! {
            self.get_device_serial(buffer.as_mut_ptr() as *mut i8, buffer.len())
        };
        into_rust_result!(result)?;
        
        // Find the length (excluding null terminator)
        let len = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        Ok(len)
    }



    /// Write the device IDs (vendor, product, etc.)
    pub fn write_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError> {
        let result = method_call! {
            self.get_device_ids(ids)
        };
        into_rust_result!(result)
    }

    /// Write absolute axis information for a specific axis
    pub fn write_abs_info(&self, axis: u16, abs_info: &mut InputAbsInfo) -> Result<(), InputBackendError> {
        let result = method_call! {
            self.get_abs_info(axis, abs_info)
        };
        into_rust_result!(result)
    }

    /// Write event bits bitmap to the provided buffer (low-level, allocation-free)
    /// Returns the number of bytes written
    pub fn write_event_bits(&self, event_type: u16, buffer: &mut [u8]) -> Result<usize, InputBackendError> {
        let mut actual_len = 0usize;
        
        let result = method_call! {
            self.get_event_bits(event_type, buffer.as_mut_ptr(), buffer.len(), &raw mut actual_len)
        };
        into_rust_result!(result)?;
        
        Ok(actual_len.min(buffer.len()))
    }
    
    /// Write property bits bitmap to the provided buffer (low-level, allocation-free)
    /// Returns the number of bytes written
    pub fn write_property_bits(&self, buffer: &mut [u8]) -> Result<usize, InputBackendError> {
        let mut actual_len = 0usize;
        
        let result = method_call! {
            self.get_property_bits(buffer.as_mut_ptr(), buffer.len(), &raw mut actual_len)
        };
        into_rust_result!(result)?;
        
        Ok(actual_len.min(buffer.len()))
    }


}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct InputBackendWrapper<'userdata> {
    pub features: u64,
    pub create_userdata: *const c_void,
    pub create_userdata_lifetime: PhantomData<&'userdata c_void>,
    pub create_events_fn: header::krun_input_create_fn,
    pub create_config_fn: header::krun_input_create_fn,
    pub events_vtable: InputEventsVtable,
    pub config_vtable: InputConfigVtable,
}

impl<'a> InputBackendWrapper<'a> {
    /// Create an InputEventsInstance for handling input events
    pub fn create_events_instance(&self) -> Result<InputEventsInstance, InputBackendError> {
        let mut instance = null_mut();
        if let Some(create_fn) = self.create_events_fn {
            into_rust_result!(unsafe {
                create_fn(&raw mut instance, self.create_userdata, null())
            })?;
        }
        assert!(self.verify_events());

        Ok(InputEventsInstance {
            instance,
            vtable: self.events_vtable,
        })
    }

    /// Create an InputConfigInstance for handling device configuration
    pub fn create_config_instance(&self) -> Result<InputConfigInstance, InputBackendError> {
        let mut instance = null_mut();
        if let Some(create_fn) = self.create_config_fn {
            into_rust_result!(unsafe {
                create_fn(&raw mut instance, self.create_userdata, null())
            })?;
        }
        assert!(self.verify_config());

        Ok(InputConfigInstance {
            instance,
            vtable: self.config_vtable,
        })
    }

    pub fn verify_events(&self) -> bool {
        // Check that required methods are present for events
        if self.events_vtable.get_ready_efd.is_none() || self.events_vtable.next_event.is_none() {
            error!("Missing required methods for input events backend");
            return false;
        }
        true
    }

    pub fn verify_config(&self) -> bool {
        // Config methods are all optional, so always return true
        true
    }

    pub fn verify(&self) -> bool {
        self.verify_events() && self.verify_config()
    }
}

unsafe impl<'a> Send for InputBackendWrapper<'a> {}