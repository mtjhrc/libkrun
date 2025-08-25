#ifndef _LIBKRUN_INPUT_H
#define _LIBKRUN_INPUT_H

#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// The input backend encountered an internal error
#define KRUN_INPUT_ERR_INTERNAL -1
#define KRUN_INPUT_ERR_EAGAIN -2
#define KRUN_INPUT_ERR_METHOD_UNSUPPORTED -3
#define KRUN_INPUT_ERR_INVALID_PARAM -4



/**
 * Represents an input event similar to Linux input events.
 * This structure is compatible with virtio input events.
 */
struct krun_input_event {
    uint16_t type;  // Event type (EV_KEY, EV_REL, EV_ABS, etc.)
    uint16_t code;  // Event code (key code, relative axis, etc.)
    uint32_t value; // Event value
};



/**
 * Called to create an input backend instance.
 *
 * Arguments:
 *  "instance"    - (Output) pointer to userdata which can be used to represent this/self argument.
 *                  Implementation may set it to any value (even NULL)
 *  "userdata"    - userdata specified in the `krun_input_backend` instance
 *  "reserved"    - reserved/unused for now
 *
 * Returns:
 *  Zero on success or a negative error code (KRUN_INPUT_ERR_*) otherwise.
 */
typedef int32_t (*krun_input_create_fn)(void **instance, const void *userdata, const void *reserved);

/**
 * Called to destroy the input backend instance.
 *
 * Arguments:
 *  "instance"    - userdata set by `krun_input_create`, represents this/self argument
 *
 * Returns:
 *  Zero on success or a negative error code (KRUN_INPUT_ERR_*) otherwise.
 */
typedef int32_t (*krun_input_destroy_fn)(void *instance);

/**
 * Gets a file descriptor that becomes ready for reading when input events are available.
 * The implementation should return an eventfd or similar file descriptor that can be used
 * with epoll/poll/select to wait for input events.
 *
 * Arguments:
 *  "instance"    - userdata set by `krun_input_create`, represents this/self argument
 *
 * Returns:
 *  A valid file descriptor (>= 0) or a negative error code (KRUN_INPUT_ERR_*) otherwise.
 */
typedef int (*krun_input_get_ready_efd_fn)(void *instance);

/**
 * Fetches the next available input event from the backend.
 * This function should not block. If no events are available, it should return 0.
 *
 * Arguments:
 *  "instance"    - userdata set by `krun_input_create`, represents this/self argument
 *  "out_event"   - (Output) pointer to where the event should be written
 *
 * Returns:
 *  1 if an event was successfully retrieved and written to out_event
 *  0 if no events are available
 *  negative error code (KRUN_INPUT_ERR_*) on error
 */
typedef int32_t (*krun_input_next_event_fn)(void *instance, struct krun_input_event *out_event);

/**
 * Defines the set of callbacks for input event handling.
 * This structure holds function pointers that an input backend implements to integrate with libkrun.
 *
 * The input device instantiates the input backend using the krun_input_create in a specific thread.
 * All further calls to the input backend will be called from the same thread. The input methods should
 * not block for a long time otherwise this will negatively impact performance.
 *
 * See krun_input_* function pointer typedef definitions for descriptions of individual methods.
 * The user of the library *MUST* zero initialize this struct to make all unset fields NULL.
 */
struct krun_input_vtable {
    krun_input_destroy_fn         destroy;        // (optional)
    krun_input_get_ready_efd_fn   get_ready_efd;  // (required)
    krun_input_next_event_fn      next_event;     // (required)
};

/**
 * Called to get the device name
 */
typedef int32_t (*krun_input_get_device_name_fn)(void *instance, char *out_name, size_t name_len);

/**
 * Called to get the device serial number
 */
typedef int32_t (*krun_input_get_device_serial_fn)(void *instance, char *out_serial, size_t serial_len);

/**
 * Called to get the device IDs
 */
struct krun_input_device_ids {
    uint16_t bustype;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;
};

typedef int32_t (*krun_input_get_device_ids_fn)(void *instance, struct krun_input_device_ids *out_ids);

/**
 * Called to get absolute axis information
 */
struct krun_input_absinfo {
    uint32_t min;
    uint32_t max;
    uint32_t fuzz;
    uint32_t flat;
    uint32_t res;
};

typedef int32_t (*krun_input_get_abs_info_fn)(void *instance, uint16_t axis, struct krun_input_absinfo *out_abs_info);

/**
 * Called to get event bits for a specific event type
 */
typedef int32_t (*krun_input_get_event_bits_fn)(void *instance, uint16_t event_type, uint8_t *out_bitmap, size_t bitmap_len, size_t *actual_len);

/**
 * Called to get property bits
 */
typedef int32_t (*krun_input_get_property_bits_fn)(void *instance, uint8_t *out_bitmap, size_t bitmap_len, size_t *actual_len);

/**
 * Configuration vtable with high-level getter methods
 */
struct krun_input_config_vtable {
    krun_input_destroy_fn                 destroy;          // (optional)
    krun_input_get_device_name_fn         get_device_name;  // (optional)
    krun_input_get_device_serial_fn       get_device_serial; // (optional)
    krun_input_get_device_ids_fn          get_device_ids;   // (optional)
    krun_input_get_abs_info_fn            get_abs_info;     // (optional)
    krun_input_get_event_bits_fn          get_event_bits;   // (optional)
    krun_input_get_property_bits_fn       get_property_bits; // (optional)
};

/**
 * Events vtable for event handling
 */
struct krun_input_events_vtable {
    krun_input_destroy_fn         destroy;        // (optional)
    krun_input_get_ready_efd_fn   get_ready_efd;  // (required)
    krun_input_next_event_fn      next_event;     // (required)
};

/**
 * The main input backend structure with separate objects for events and configuration.
 * Configuration methods use high-level getters, not raw select/subsel.
 */
struct krun_input_backend {
    uint64_t features; // reserved/unused for now
    void *create_userdata; // (optional)
    krun_input_create_fn create_events; // Creates the events object (optional)
    krun_input_create_fn create_config; // Creates the config object (optional)
    struct krun_input_events_vtable events_vtable;
    struct krun_input_config_vtable config_vtable;
};

#ifdef __cplusplus
}
#endif

#endif // _LIBKRUN_INPUT_H
