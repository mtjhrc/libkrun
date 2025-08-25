use crate::{
    InputBackend, InputBackendError, InputConfigVtable, InputDeviceIds, InputEvent,
    InputEventsVtable, InputAbsInfo, header,
};
// use log::error;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::fd::RawFd;
use std::ptr;
use std::ptr::null_mut;

pub trait InputBackendNew<T: Send + Sync> {
    fn new(userdata: Option<&T>) -> Self;
}

pub trait InputEventsImpl {
    /// Get the file descriptor that becomes ready when input events are available
    fn get_ready_efd(&self) -> Result<RawFd, InputBackendError>;

    /// Fetch the next available input event, returns None if no events are available
    fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError>;
}

pub trait InputConfigImpl {
    /// Write the device name to the provided buffer
    /// Returns the number of bytes written (excluding null terminator)
    /// If buffer is too small, returns the required size
    fn write_device_name(&self, buffer: &mut [u8]) -> Result<usize, InputBackendError>;

    /// Write the device serial number to the provided buffer
    /// Returns the number of bytes written (excluding null terminator)  
    /// If buffer is too small, returns the required size
    fn write_device_serial(&self, buffer: &mut [u8]) -> Result<usize, InputBackendError>;

    /// Write the device IDs (vendor, product, etc.)
    fn write_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError>;

    /// Write absolute axis information for a specific axis
    fn write_abs_info(&self, axis: u16, abs_info: &mut InputAbsInfo) -> Result<(), InputBackendError>;

    /// Write event bits bitmap for a specific event type to the provided buffer
    /// Returns the number of bytes written
    /// If buffer is too small, returns the required size  
    fn write_event_bits(
        &self,
        event_type: u16,
        buffer: &mut [u8],
    ) -> Result<usize, InputBackendError>;

    /// Write property bits bitmap to the provided buffer
    /// Returns the number of bytes written
    /// If buffer is too small, returns the required size
    fn write_property_bits(&self, buffer: &mut [u8]) -> Result<usize, InputBackendError>;
}

pub trait IntoInputBackend<T: Sync> {
    fn into_input_backend(userdata: Option<&T>) -> InputBackend;
}

// Helper struct to pair events and config implementations
pub struct InputBackendPair<E, C>(pub PhantomData<E>, pub PhantomData<C>);

impl<T: Send + Sync, E: InputEventsImpl + InputBackendNew<T>, C: InputConfigImpl + InputBackendNew<T>>
    IntoInputBackend<T> for InputBackendPair<E, C>
{
    fn into_input_backend(userdata: Option<&T>) -> InputBackend {
        extern "C" fn create_events_fn<T: Send + Sync, E: InputBackendNew<T>>(
            instance: *mut *mut c_void,
            userdata: *const c_void,
            _reserved: *const c_void,
        ) -> i32 {
            unsafe {
                assert_ne!(
                    instance,
                    null_mut(),
                    "Pointer to location where to create instance cannot be null"
                );
                let userdata_ref = (userdata as *const T).as_ref();
                *(instance as *mut *mut E) = Box::into_raw(Box::new(E::new(userdata_ref)));
            }
            0
        }

        extern "C" fn create_config_fn<T: Send + Sync, C: InputBackendNew<T>>(
            instance: *mut *mut c_void,
            userdata: *const c_void,
            _reserved: *const c_void,
        ) -> i32 {
            unsafe {
                assert_ne!(
                    instance,
                    null_mut(),
                    "Pointer to location where to create instance cannot be null"
                );
                let userdata_ref = (userdata as *const T).as_ref();
                *(instance as *mut *mut C) = Box::into_raw(Box::new(C::new(userdata_ref)));
            }
            0
        }

        extern "C" fn destroy_fn<E>(instance: *mut c_void) -> i32 {
            drop(unsafe { Box::from_raw(instance as *mut E) });
            0
        }

        fn cast_events_instance<'a, E: InputEventsImpl>(instance: *mut c_void) -> &'a mut E {
            assert_ne!(instance, null_mut());
            unsafe { &mut *(instance as *mut E) }
        }

        fn cast_config_instance<'a, C: InputConfigImpl>(instance: *mut c_void) -> &'a C {
            assert_ne!(instance, null_mut());
            unsafe { &*(instance as *mut C) }
        }

        extern "C" fn get_ready_efd_fn<E: InputEventsImpl>(instance: *mut c_void) -> i32 {
            match cast_events_instance::<E>(instance).get_ready_efd() {
                Ok(fd) => fd,
                Err(e) => e as i32,
            }
        }

        extern "C" fn next_event_fn<E: InputEventsImpl>(
            instance: *mut c_void,
            out_event: *mut header::krun_input_event,
        ) -> i32 {
            assert_ne!(out_event, null_mut());

            match cast_events_instance::<E>(instance).next_event() {
                Ok(Some(event)) => {
                    unsafe {
                        (*out_event).type_ = event.type_;
                        (*out_event).code = event.code;
                        (*out_event).value = event.value;
                    }
                    1 // Event available
                }
                Ok(None) => 0, // No events available
                Err(e) => e as i32,
            }
        }

        extern "C" fn get_device_name_fn<C: InputConfigImpl>(
            instance: *mut c_void,
            out_name: *mut i8,
            name_len: usize,
        ) -> i32 {
            assert_ne!(out_name, null_mut());
            if name_len == 0 {
                return -4; // KRUN_INPUT_ERR_INVALID_PARAM
            }

            let buffer = unsafe { std::slice::from_raw_parts_mut(out_name as *mut u8, name_len) };
            match cast_config_instance::<C>(instance).write_device_name(buffer) {
                Ok(written) => {
                    if written < name_len {
                        unsafe {
                            *(out_name.add(written)) = 0;
                        } // Null terminate if space
                    }
                    0
                }
                Err(e) => e as i32,
            }
        }

        extern "C" fn get_device_serial_fn<C: InputConfigImpl>(
            instance: *mut c_void,
            out_serial: *mut i8,
            serial_len: usize,
        ) -> i32 {
            assert_ne!(out_serial, null_mut());
            if serial_len == 0 {
                return -4; // KRUN_INPUT_ERR_INVALID_PARAM
            }

            let buffer =
                unsafe { std::slice::from_raw_parts_mut(out_serial as *mut u8, serial_len) };
            match cast_config_instance::<C>(instance).write_device_serial(buffer) {
                Ok(written) => {
                    if written < serial_len {
                        unsafe {
                            *(out_serial.add(written)) = 0;
                        } // Null terminate if space
                    }
                    0
                }
                Err(e) => e as i32,
            }
        }

        extern "C" fn get_device_ids_fn<C: InputConfigImpl>(
            instance: *mut c_void,
            out_ids: *mut header::krun_input_device_ids,
        ) -> i32 {
            assert_ne!(out_ids, null_mut());
            
            let ids_ref = unsafe { &mut *out_ids };
            match cast_config_instance::<C>(instance).write_device_ids(ids_ref) {
                Ok(()) => 0,
                Err(e) => e as i32,
            }
        }

        extern "C" fn get_abs_info_fn<C: InputConfigImpl>(
            instance: *mut c_void,
            axis: u16,
            out_abs_info: *mut header::krun_input_absinfo,
        ) -> i32 {
            assert_ne!(out_abs_info, null_mut());
            
            let abs_info_ref = unsafe { &mut *out_abs_info };
            match cast_config_instance::<C>(instance).write_abs_info(axis, abs_info_ref) {
                Ok(()) => 0,
                Err(e) => e as i32,
            }
        }

        extern "C" fn get_event_bits_fn<C: InputConfigImpl>(
            instance: *mut c_void,
            event_type: u16,
            out_bitmap: *mut u8,
            bitmap_len: usize,
            actual_len: *mut usize,
        ) -> i32 {
            assert_ne!(out_bitmap, null_mut());
            assert_ne!(actual_len, null_mut());

            let buffer = unsafe { std::slice::from_raw_parts_mut(out_bitmap, bitmap_len) };
            match cast_config_instance::<C>(instance).write_event_bits(event_type, buffer) {
                Ok(written) => {
                    unsafe {
                        *actual_len = written;
                    }
                    0
                }
                Err(e) => e as i32,
            }
        }

        extern "C" fn get_property_bits_fn<C: InputConfigImpl>(
            instance: *mut c_void,
            out_bitmap: *mut u8,
            bitmap_len: usize,
            actual_len: *mut usize,
        ) -> i32 {
            assert_ne!(out_bitmap, null_mut());
            assert_ne!(actual_len, null_mut());

            let buffer = unsafe { std::slice::from_raw_parts_mut(out_bitmap, bitmap_len) };
            match cast_config_instance::<C>(instance).write_property_bits(buffer) {
                Ok(written) => {
                    unsafe {
                        *actual_len = written;
                    }
                    0
                }
                Err(e) => e as i32,
            }
        }

        InputBackend {
            features: 0, // No features defined yet
            create_userdata: userdata.map_or(null_mut(), |t| {
                ptr::from_ref(t) as *const c_void as *mut c_void
            }),
            create_events: Some(create_events_fn::<T, E>),
            create_config: Some(create_config_fn::<T, C>),
            events_vtable: InputEventsVtable {
                destroy: Some(destroy_fn::<E>),
                get_ready_efd: Some(get_ready_efd_fn::<E>),
                next_event: Some(next_event_fn::<E>),
            },
            config_vtable: InputConfigVtable {
                destroy: Some(destroy_fn::<C>),
                get_device_name: Some(get_device_name_fn::<C>),
                get_device_serial: Some(get_device_serial_fn::<C>),
                get_device_ids: Some(get_device_ids_fn::<C>),
                get_abs_info: Some(get_abs_info_fn::<C>),
                get_event_bits: Some(get_event_bits_fn::<C>),
                get_property_bits: Some(get_property_bits_fn::<C>),
            },
        }
    }
}
