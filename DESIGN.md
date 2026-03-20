# libkrun v2.0 API Design

## Why v2.0?

The v1 API has accumulated serious design debt:

- **Blind error codes**: 124+ functions return bare `-EINVAL` — the caller can't tell if the MAC address is wrong, the path doesn't exist, or the feature isn't compiled in.
- **Implicit devices**: vsock and console are auto-created. Users must call `krun_disable_implicit_*()` to opt out.
- **Cross-device side effects**: Adding a network device silently disables TSI on the vsock. No documentation, no warning.
- **API generations**: Three generations of block device APIs (`krun_set_root_disk`, `krun_add_disk`, `krun_add_disk2`, `krun_add_disk3`) that silently conflict if mixed.
- **Late validation**: All configuration is accepted with return code 0; errors only surface at `krun_start_enter()`.
- **Type-unsafe constants**: Bare `#define` integers — `krun_add_disk2(ctx, "vda", path, 99, false)` compiles fine, fails at runtime.

v2.0 is a clean break. The Rust side provides a safe, typed API. The C side is auto-generated via `ffier` — a proc-macro framework that emits handles, RTTI, error types, zero-copy byte slices, and per-type C header sections from the Rust API, then assembles them into one readable public header.

---

## Design Principles

1. **Nothing implicit** — zero default devices. If you want a console, create one.
2. **No cross-device effects** — configuring device A never silently changes device B.
3. **Errors carry context** — structured code + human-readable message on every failure.
4. **Eager validation** — bad parameters rejected immediately, not at VM start.
5. **One API per concept** — no deprecated alternatives lingering alongside new ones.
6. **Dual API** — Rust users get types, lifetimes, and `Result<T, E>`. C users get handles, error structs, and Doxygen docs in one public header assembled from generated sections. Both come from the same source.

---

## Error Type

```rust
#[derive(Clone, Copy, ffier::FfiError)]
pub enum KrunErrorCode {
    // Configuration (100–199)
    #[ffier(code = 100)]
    InvalidParam,          // "invalid configuration parameter"
    #[ffier(code = 101)]
    DuplicateDevice,       // "duplicate device identifier"
    #[ffier(code = 102)]
    DeviceLimitExceeded,   // "device limit exceeded"
    #[ffier(code = 103)]
    MissingConfig,         // "missing required configuration"
    #[ffier(code = 104)]
    ConflictingConfig,     // "conflicting configuration"
    #[ffier(code = 105)]
    OutOfRange,            // "value out of range"

    // Resources (200–299)
    #[ffier(code = 200)]
    FileNotFound,          // "file not found"
    #[ffier(code = 201)]
    PermissionDenied,      // "permission denied"
    #[ffier(code = 202)]
    ResourceAlloc,         // "resource allocation failed"
    #[ffier(code = 203)]
    BadFd,                 // "file descriptor invalid"

    // Devices (300–399)
    #[ffier(code = 300)]
    BackendUnavailable,    // "device backend unavailable"
    #[ffier(code = 301, message = "feature not enabled in this build")]
    FeatureDisabled,
    #[ffier(code = 302)]
    DiskFormatError,       // "disk image format error"

    // Runtime (400–499)
    #[ffier(code = 400)]
    AlreadyStarted,        // "VM already started"
    #[ffier(code = 401)]
    ValidationFailed,      // "VM configuration validation failed"
    #[ffier(code = 402)]
    HypervisorError,       // "hypervisor error"
    #[ffier(code = 403)]
    BootError,             // "payload load failed"

    // Internal (900–999)
    #[ffier(code = 900)]
    Internal,              // "internal error"
}
```

Each function that can fail returns `Result<T, KrunError>`, where `KrunError` wraps a code + optional runtime message:

```rust
pub struct KrunError {
    code: KrunErrorCode,
    context: Option<String>, // e.g. "vcpus must be 1..255, got 0"
}
```

### C side

```c
typedef struct {
    uint64_t code;
    char* _msg; /* private — use krun_error_message() */
} KrunError;

#define KRUN_ERROR_INVALID_PARAM      100
#define KRUN_ERROR_DUPLICATE_DEVICE   101
#define KRUN_ERROR_DEVICE_LIMIT_EXCEEDED 102
#define KRUN_ERROR_MISSING_CONFIG     103
#define KRUN_ERROR_OUT_OF_RANGE       105
#define KRUN_ERROR_FILE_NOT_FOUND     200
#define KRUN_ERROR_BAD_FD             203
#define KRUN_ERROR_FEATURE_DISABLED   301
#define KRUN_ERROR_VALIDATION_FAILED  401
/* ... etc ... */

const char* krun_error_message(const KrunError* err);
void krun_error_free(KrunError* err);
```

### Usage pattern

```c
#define CHECK(expr) do { \
    KrunError _e = (expr); \
    if (_e.code != 0) { \
        fprintf(stderr, "error %lu: %s\n", _e.code, krun_error_message(&_e)); \
        krun_error_free(&_e); \
        exit(1); \
    } \
} while(0)
```

When `krun_vmmbuilder_set_vcpus(b, 0)` fails, the message is:
```
error 105: vcpus must be 1..255, got 0
```

Not just `-EINVAL`.

---

## VM Lifecycle

```
VmmBuilder::new()  →  configure  →  .build()?  →  Vmm  →  .run()?
```

Two types enforce the state machine, **both carrying a lifetime `'a`**:

- **`VmmBuilder<'a>`** — mutable configuration. Devices and buffers borrow user data with lifetime `'a`. Can't call `.run()`.
- **`Vmm<'a>`** — validated, ready to run. Preserves the `'a` lifetime — Rust proves all borrowed data outlives the VM. Can't add devices.

The lifetime `'a` is the Rust API's key advantage: the borrow checker guarantees tap buffers, disk images, and resources live long enough. The C API erases lifetimes to `'static` (handled by ffier), and the C caller is responsible for ordering.

### Rust API

```rust
/// Configuration builder. Borrows user-provided data with lifetime 'a.
#[ffier::exportable(prefix = "krun")]
impl<'a> VmmBuilder<'a> {
    /// Create an empty builder. No devices, no defaults.
    pub fn new() -> Self;

    // --- Hardware config ---

    /// Set the number of vCPUs (1–255).
    pub fn set_vcpus(&mut self, count: u8) -> Result<(), KrunError>;

    /// Set RAM in MiB.
    pub fn set_ram_mib(&mut self, mib: u32) -> Result<(), KrunError>;

    // --- Payload ---

    /// Select the VM payload. Exactly one payload must be configured.
    ///
    /// The initial bringup only supports `LibkrunInit`, which uses
    /// libkrunfw + the libkrun init system and requires a virtiofs rootfs.
    #[ffier(dyn_param(payload, "Payload", [
        LibkrunInit<'a>,  // future: KernelPayload<'a>, EfiPayload<'a>, ...
    ]))]
    pub fn set_payload(
        &mut self,
        payload: impl Into<PayloadSlot<'a>>,
    ) -> Result<(), KrunError>;

    // --- Devices ---

    /// Add a device. Accepts any device type via runtime dispatch.
    /// Returns a device index for reference.
    ///
    /// # Arguments
    ///
    /// * `device` - Any device handle (NetDevice, BlockDevice, ...).
    #[ffier(dyn_param(device, "Device", [
        NetDevice<'a>, BlockDevice<'a>, FsDevice<'a>,
        ConsoleDevice<'a>, SerialDevice<'a>,
        GpuDevice, VsockDevice,
        BalloonDevice, RngDevice, InputDevice<'a>,
    ]))]
    pub fn add_device(
        &mut self,
        device: impl Into<DeviceSlot<'a>>,
    ) -> Result<u32, KrunError>;

    // --- Build ---

    /// Validate and produce a runnable Vmm. Consumes the builder.
    /// The returned Vmm<'a> preserves the lifetime — all borrowed data
    /// must outlive the Vmm.
    ///
    /// Checks: payload present, payload/device consistency,
    /// referenced virtiofs rootfs present, resource availability,
    /// hypervisor support, etc.
    pub fn build(self) -> Result<Vmm<'a>, KrunError>;
}

/// A validated, ready-to-run VM. Produced by `VmmBuilder::build()`.
/// Carries lifetime `'a` — Rust proves all borrowed data (buffers, disk
/// mappings, resources) outlive the VM.
#[ffier::exportable(prefix = "krun")]
impl<'a> Vmm<'a> {
    /// Run the VM. Consumes self.
    /// On success, does not return (calls `exit()` with the guest exit code).
    /// On failure before launch, returns an error.
    /// Note: `Ok(())` is unreachable — if this returns, it's always `Err`.
    pub fn run(self) -> Result<(), KrunError>;

    /// Get shutdown eventfd (EFI builds only).
    pub fn get_shutdown_eventfd(&mut self) -> Result<OwnedFd, KrunError>;
}
```

### C API (generated by ffier)

```c
typedef void* KrunVmmBuilder;
typedef void* KrunVmm;
typedef void* KrunDevice;
typedef void* KrunPayload;

/* Create / destroy builder */
KrunVmmBuilder krun_vmmbuilder_new(void);
void krun_vmmbuilder_destroy(KrunVmmBuilder b);

/* Hardware */
KrunError krun_vmmbuilder_set_vcpus(KrunVmmBuilder b, uint8_t count);
KrunError krun_vmmbuilder_set_ram_mib(KrunVmmBuilder b, uint32_t mib);

/* Payload */
KrunError krun_vmmbuilder_set_payload(KrunVmmBuilder b, KrunPayload payload);

/* Devices — one function for all types */
KrunError krun_vmmbuilder_add_device(KrunVmmBuilder b, KrunDevice device, uint32_t* result);

/* Build — validates config, produces a Vmm (consumes builder handle) */
KrunError krun_vmmbuilder_build(KrunVmmBuilder b, KrunVmm* result);

/* Run the validated VM (consumes Vmm handle) */
KrunError krun_vmm_run(KrunVmm vmm);
KrunError krun_vmm_get_shutdown_eventfd(KrunVmm vmm, int* result);
void krun_vmm_destroy(KrunVmm vmm);
```

### String array parameters: `&[&str]` → `const KrunStr* items, uintptr_t count`

This is a new ffier feature. When a method takes `&[&str]`, the C signature gets two parameters: a pointer to an array of `KrunStr` and a count. Example:

```c
/* Pass arguments as an array of KrunStr */
KrunStr args[] = { KRUN_STR("/bin/sh"), KRUN_STR("-c"), KRUN_STR("echo hello") };
CHECK(krun_libkruninitbuilder_set_exec(init_builder, KRUN_STR("/bin/sh"), args, 3));

/* Pass env vars */
KrunStr env[] = { KRUN_STR("HOME=/root"), KRUN_STR("PATH=/usr/bin") };
CHECK(krun_libkruninitbuilder_set_env(init_builder, env, 2));
```

---

## Payload Types

Payload selection is explicit. The initial bringup supports only one payload: libkrunfw + the libkrun init system, injected through virtiofs. The API still uses `set_payload()` because later releases will support alternative payloads behind the same entry point.

### `LibkrunInit` payload

`LibkrunInit` configures libkrun to boot with libkrunfw and the libkrun init system. It also owns the guest process configuration: executable, argv, environment, and working directory.

For the initial bringup, it only works with virtiofs. The builder takes a mutable reference to the `FsDevice` that will become the guest rootfs, and `build()` injects the synthetic `/init.krun` file into that virtiofs mount.

```rust
#[ffier::exportable(prefix = "krun")]
impl<'a> LibkrunInit<'a> {
    /// Create a builder for a virtiofs-backed payload.
    /// `rootfs` receives the synthetic `/init.krun` file and becomes guest `/`.
    pub fn builder(rootfs: &'a mut FsDevice<'a>) -> LibkrunInitBuilder<'a>;
}

#[ffier::exportable(prefix = "krun")]
impl<'a> LibkrunInitBuilder<'a> {
    /// Set the executable and its arguments, relative to the selected rootfs.
    pub fn set_exec(
        &mut self,
        exec_path: &str,
        args: &[&str],
    ) -> Result<(), KrunError>;

    /// Set environment variables.
    pub fn set_env(&mut self, env: &[&str]) -> Result<(), KrunError>;

    /// Set working directory.
    pub fn set_workdir(&mut self, path: &str) -> Result<(), KrunError>;

    /// Finalize the payload and inject `/init.krun` into the referenced virtiofs.
    pub fn build(self) -> Result<LibkrunInit<'a>, KrunError>;
}
```

```c
typedef void* KrunLibkrunInit;
typedef void* KrunLibkrunInitBuilder;

/* Borrows the virtiofs device; caller still adds it to the VMM separately */
KrunLibkrunInitBuilder krun_libkruninit_builder(KrunFsDevice rootfs);
KrunError krun_libkruninitbuilder_set_exec(KrunLibkrunInitBuilder b, KrunStr exec_path, const KrunStr* args, uintptr_t args_len);
KrunError krun_libkruninitbuilder_set_env(KrunLibkrunInitBuilder b, const KrunStr* env, uintptr_t env_len);
KrunError krun_libkruninitbuilder_set_workdir(KrunLibkrunInitBuilder b, KrunStr path);
KrunError krun_libkruninitbuilder_build(KrunLibkrunInitBuilder b, KrunLibkrunInit* result);
void krun_libkruninitbuilder_destroy(KrunLibkrunInitBuilder b);
void krun_libkruninit_destroy(KrunLibkrunInit payload);
```

---

## Device Types

Each device is a separate struct. No device is ever created implicitly. No device's configuration affects any other device.

### virtio-net

```rust
#[ffier::exportable(prefix = "krun")]
impl<'a> NetDevice<'a> {
    /// TAP backend.
    ///
    /// # Arguments
    ///
    /// * `tap_name` - TAP interface name (borrowed, must outlive the device).
    /// * `mac` - MAC address as 6 bytes.
    pub fn new_tap(tap_name: &'a str, mac: &[u8]) -> Result<Self, KrunError>;

    /// Unix stream backend (passt, socket_vmnet).
    /// Pass path="" and fd for pre-connected socket, or path and fd=-1.
    pub fn new_unixstream(path: &'a str, fd: i32, mac: &[u8]) -> Result<Self, KrunError>;

    /// Unix datagram backend (gvproxy).
    pub fn new_unixgram(path: &'a str, fd: i32, mac: &[u8], vfkit_mode: bool) -> Result<Self, KrunError>;

    /// Set virtio feature flags.
    pub fn set_features(&mut self, features: u32);
}
```

```c
typedef void* KrunNetDevice;

KrunError krun_netdevice_new_tap(KrunStr tap_name, KrunBytes mac, KrunNetDevice* result);
KrunError krun_netdevice_new_unixstream(KrunStr path, int32_t fd, KrunBytes mac, KrunNetDevice* result);
KrunError krun_netdevice_new_unixgram(KrunStr path, int32_t fd, KrunBytes mac, bool vfkit, KrunNetDevice* result);
void krun_netdevice_set_features(KrunNetDevice net, uint32_t features);
void krun_netdevice_destroy(KrunNetDevice net);
```

### virtio-blk

```rust
#[ffier::exportable(prefix = "krun")]
impl<'a> BlockDevice<'a> {
    /// Create a block device.
    ///
    /// # Arguments
    ///
    /// * `block_id` - Identifier (e.g. "vda", "vdb").
    /// * `path` - Path to disk image (borrowed, must outlive the device).
    /// * `format` - KRUN_DISK_FORMAT_RAW / QCOW2 / VMDK.
    /// * `read_only` - Mount read-only.
    pub fn new(block_id: &str, path: &'a Path, format: u32, read_only: bool) -> Result<Self, KrunError>;

    /// Set sync mode (KRUN_SYNC_NONE / RELAXED / FULL).
    pub fn set_sync_mode(&mut self, mode: u32) -> Result<(), KrunError>;

    /// Enable O_DIRECT.
    pub fn set_direct_io(&mut self, enable: bool);
}
```

```c
typedef void* KrunBlockDevice;

#define KRUN_DISK_FORMAT_RAW   0
#define KRUN_DISK_FORMAT_QCOW2 1
#define KRUN_DISK_FORMAT_VMDK  2

#define KRUN_SYNC_NONE    0
#define KRUN_SYNC_RELAXED 1
#define KRUN_SYNC_FULL    2

KrunError krun_blockdevice_new(KrunStr block_id, KrunPath path, uint32_t format, bool read_only, KrunBlockDevice* result);
KrunError krun_blockdevice_set_sync_mode(KrunBlockDevice blk, uint32_t mode);
void krun_blockdevice_set_direct_io(KrunBlockDevice blk, bool enable);
void krun_blockdevice_destroy(KrunBlockDevice blk);
```

### virtio-fs

```rust
#[ffier::exportable(prefix = "krun")]
impl<'a> FsDevice<'a> {
    /// Create a virtiofs device.
    ///
    /// # Arguments
    ///
    /// * `tag` - Mount tag.
    /// * `host_path` - Directory on the host (borrowed, must outlive the device).
    pub fn new(tag: &str, host_path: &'a Path) -> Result<Self, KrunError>;

    /// Set DAX shared memory window size (bytes, 0 = default).
    pub fn set_dax_window_size(&mut self, bytes: u64);

    /// If borrowed by `LibkrunInit::builder()`, this device becomes the
    /// guest rootfs and receives the synthetic `/init.krun` file.
}
```

```c
typedef void* KrunFsDevice;

KrunError krun_fsdevice_new(KrunStr tag, KrunPath host_path, KrunFsDevice* result);
void krun_fsdevice_set_dax_window_size(KrunFsDevice fs, uint64_t bytes);
void krun_fsdevice_destroy(KrunFsDevice fs);
```

### virtio-console

No implicit console. Build one explicitly:

```rust
#[ffier::exportable(prefix = "krun")]
impl<'a> ConsoleDevice<'a> {
    /// Create a console builder.
    pub fn builder() -> ConsoleDeviceBuilder<'a>;
}

#[ffier::exportable(prefix = "krun")]
impl<'a> ConsoleDeviceBuilder<'a> {
    /// Add an unnamed TTY port (terminal with resize support).
    /// The fd is borrowed — borrow checker proves it stays open.
    /// Returns the port index.
    pub fn add_tty_port(&mut self, tty_fd: BorrowedFd<'a>) -> Result<u32, KrunError>;

    /// Add a named TTY port.
    /// The name and fd are borrowed for the lifetime of the device.
    /// Returns the port index.
    pub fn add_tty_port_named(&mut self, name: &'a str, tty_fd: BorrowedFd<'a>) -> Result<u32, KrunError>;

    /// Add an unnamed raw I/O port (no terminal features).
    /// Returns the port index.
    pub fn add_io_port(&mut self, input: BorrowedFd<'a>, output: BorrowedFd<'a>) -> Result<u32, KrunError>;

    /// Add a named raw I/O port.
    /// The optional name is modeled as a separate named variant in the API.
    /// Returns the port index.
    pub fn add_io_port_named(
        &mut self,
        name: &'a str,
        input: BorrowedFd<'a>,
        output: BorrowedFd<'a>,
    ) -> Result<u32, KrunError>;

    /// Set which port is the kernel console (for console= cmdline).
    pub fn set_kernel_console(&mut self, port_index: u32) -> Result<(), KrunError>;

    /// Finalize the console device.
    pub fn build(self) -> Result<ConsoleDevice<'a>, KrunError>;
}
```

```c
typedef void* KrunConsoleDevice;
typedef void* KrunConsoleDeviceBuilder;

KrunConsoleDeviceBuilder krun_consoledevice_builder(void);
KrunError krun_consoledevicebuilder_add_tty_port(KrunConsoleDeviceBuilder b, int32_t tty_fd, uint32_t* result);
KrunError krun_consoledevicebuilder_add_tty_port_named(KrunConsoleDeviceBuilder b, KrunStr name, int32_t tty_fd, uint32_t* result);
KrunError krun_consoledevicebuilder_add_io_port(KrunConsoleDeviceBuilder b, int32_t in_fd, int32_t out_fd, uint32_t* result);
KrunError krun_consoledevicebuilder_add_io_port_named(KrunConsoleDeviceBuilder b, KrunStr name, int32_t in_fd, int32_t out_fd, uint32_t* result);
KrunError krun_consoledevicebuilder_set_kernel_console(KrunConsoleDeviceBuilder b, uint32_t port_index);
KrunError krun_consoledevicebuilder_build(KrunConsoleDeviceBuilder b, KrunConsoleDevice* result);
void krun_consoledevicebuilder_destroy(KrunConsoleDeviceBuilder b);
void krun_consoledevice_destroy(KrunConsoleDevice c);
```

### virtio-vsock (TSI is never automatic)

```rust
#[ffier::exportable(prefix = "krun")]
impl VsockDevice {
    /// Create a vsock device. TSI is OFF by default.
    pub fn new() -> Self;

    /// Enable TSI features. KRUN_TSI_HIJACK_INET, KRUN_TSI_HIJACK_UNIX.
    /// Does NOT depend on whether a NetDevice exists.
    pub fn set_tsi_features(&mut self, features: u32);

    /// Map host ports through TSI.
    ///
    /// # Arguments
    ///
    /// * `mappings` - "host_port:guest_port" entries.
    pub fn set_port_map(&mut self, mappings: &[&str]) -> Result<(), KrunError>;

    /// Map a vsock port to a Unix socket on the host.
    pub fn add_unix_port(&mut self, port: u32, socket_path: &Path, listen: bool) -> Result<(), KrunError>;
}
```

```c
typedef void* KrunVsockDevice;

#define KRUN_TSI_HIJACK_INET (1 << 0)
#define KRUN_TSI_HIJACK_UNIX (1 << 1)

KrunVsockDevice krun_vsockdevice_new(void);
void krun_vsockdevice_set_tsi_features(KrunVsockDevice v, uint32_t features);
KrunError krun_vsockdevice_set_port_map(KrunVsockDevice v, const KrunStr* mappings, uintptr_t count);
KrunError krun_vsockdevice_add_unix_port(KrunVsockDevice v, uint32_t port, KrunPath socket_path, bool listen);
void krun_vsockdevice_destroy(KrunVsockDevice v);
```

### virtio-gpu

```rust
#[ffier::exportable(prefix = "krun")]
impl GpuDevice {
    /// Create a GPU device.
    pub fn new(virgl_flags: u32) -> Self;

    /// Set shared memory size.
    pub fn set_shm_size(&mut self, bytes: u64);

    /// Add a display. Returns display index.
    pub fn add_display(&mut self, width: u32, height: u32) -> Result<u32, KrunError>;

    /// Set DPI for a display.
    pub fn display_set_dpi(&mut self, display: u32, dpi: u32) -> Result<(), KrunError>;

    /// Set physical size for a display.
    pub fn display_set_physical_size(&mut self, display: u32, w_mm: u16, h_mm: u16) -> Result<(), KrunError>;

    /// Set refresh rate for a display.
    pub fn display_set_refresh_rate(&mut self, display: u32, hz: u32) -> Result<(), KrunError>;

    /// Set EDID blob for a display.
    pub fn display_set_edid(&mut self, display: u32, edid: &[u8]) -> Result<(), KrunError>;
}
```

### Simple devices

```rust
#[ffier::exportable(prefix = "krun")]
impl BalloonDevice {
    pub fn new() -> Self;
}

#[ffier::exportable(prefix = "krun")]
impl RngDevice {
    pub fn new() -> Self;
}

#[ffier::exportable(prefix = "krun")]
impl<'a> InputDevice<'a> {
    pub fn new_from_fd(fd: BorrowedFd<'a>) -> Result<Self, KrunError>;
}

#[ffier::exportable(prefix = "krun")]
impl<'a> SerialDevice<'a> {
    pub fn new(input_fd: BorrowedFd<'a>, output_fd: BorrowedFd<'a>) -> Result<Self, KrunError>;
}
```

---

## Feature Discovery

```rust
#[ffier::exportable(prefix = "krun")]
impl KrunInfo {
    /// Check if a feature is available in this build.
    pub fn has_feature(feature: u64) -> bool;

    /// Library version string.
    pub fn version() -> &'static str;

    /// Maximum vCPUs supported by the hypervisor.
    pub fn max_vcpus() -> Result<u32, KrunError>;
}
```

```c
#define KRUN_FEATURE_NET   0
#define KRUN_FEATURE_BLK   1
#define KRUN_FEATURE_GPU   2
#define KRUN_FEATURE_INPUT 3
#define KRUN_FEATURE_EFI   4

bool krun_kruninfo_has_feature(uint64_t feature);
KrunStr krun_kruninfo_version(void);
KrunError krun_kruninfo_max_vcpus(uint32_t* result);
```

---

## Logging

```rust
#[ffier::exportable(prefix = "krun")]
impl KrunLog {
    /// Initialize logging.
    ///
    /// # Arguments
    ///
    /// * `fd` - Output fd (-1 for stderr).
    /// * `level` - KRUN_LOG_OFF..KRUN_LOG_TRACE.
    pub fn init(fd: i32, level: u32) -> Result<(), KrunError>;
}
```

```c
#define KRUN_LOG_OFF   0
#define KRUN_LOG_ERROR 1
#define KRUN_LOG_WARN  2
#define KRUN_LOG_INFO  3
#define KRUN_LOG_DEBUG 4
#define KRUN_LOG_TRACE 5

KrunError krun_krunlog_init(int32_t fd, uint32_t level);
```

---

## Complete C Example

```c
#include <libkrun.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define CHECK(expr) do { \
    KrunError _e = (expr); \
    if (_e.code != 0) { \
        fprintf(stderr, "FATAL: %s\n", krun_error_message(&_e)); \
        krun_error_free(&_e); \
        exit(1); \
    } \
} while(0)

int main(void) {
    CHECK(krun_krunlog_init(-1, KRUN_LOG_INFO));

    /* Create builder — nothing exists yet, no devices, no defaults */
    KrunVmmBuilder b = krun_vmmbuilder_new();
    CHECK(krun_vmmbuilder_set_vcpus(b, 2));
    CHECK(krun_vmmbuilder_set_ram_mib(b, 1024));

    /* Initial payload bringup uses virtiofs rootfs */
    KrunFsDevice rootfs;
    CHECK(krun_fsdevice_new(
        KRUN_STR("rootfs"),
        KRUN_PATH("/srv/rootfs"),
        &rootfs));

    /* Payload — libkrunfw + injected /init.krun on the selected virtiofs */
    KrunLibkrunInitBuilder init_builder = krun_libkruninit_builder(rootfs);
    KrunStr guest_args[] = {
        KRUN_STR("/bin/sh"),
        KRUN_STR("-c"),
        KRUN_STR("echo hello from guest")
    };
    CHECK(krun_libkruninitbuilder_set_exec(
        init_builder,
        KRUN_STR("/bin/sh"),
        guest_args,
        3));

    KrunStr guest_env[] = {
        KRUN_STR("HOME=/root"),
        KRUN_STR("PATH=/usr/bin")
    };
    CHECK(krun_libkruninitbuilder_set_env(init_builder, guest_env, 2));
    CHECK(krun_libkruninitbuilder_set_workdir(init_builder, KRUN_STR("/")));

    KrunLibkrunInit payload;
    CHECK(krun_libkruninitbuilder_build(init_builder, &payload));
    CHECK(krun_vmmbuilder_set_payload(b, (KrunPayload)payload));

    uint32_t rootfs_idx;
    CHECK(krun_vmmbuilder_add_device(b, (KrunDevice)rootfs, &rootfs_idx));

    /* Network device — does NOT affect vsock/TSI in any way */
    uint8_t mac[] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    KrunNetDevice net;
    CHECK(krun_netdevice_new_tap(KRUN_STR("tap0"), KRUN_BYTES(mac), &net));

    uint32_t net_idx;
    CHECK(krun_vmmbuilder_add_device(b, (KrunDevice)net, &net_idx));

    /* Vsock with TSI — explicitly enabled, NOT coupled to network config */
    KrunVsockDevice vsock = krun_vsockdevice_new();
    krun_vsockdevice_set_tsi_features(vsock, KRUN_TSI_HIJACK_INET);

    KrunStr port_map[] = { KRUN_STR("8080:80"), KRUN_STR("2222:22") };
    CHECK(krun_vsockdevice_set_port_map(vsock, port_map, 2));

    uint32_t vsock_idx;
    CHECK(krun_vmmbuilder_add_device(b, (KrunDevice)vsock, &vsock_idx));

    /* Console — explicitly built, not auto-inserted */
    KrunConsoleDeviceBuilder console_builder = krun_consoledevice_builder();
    uint32_t console_port;
    CHECK(krun_consoledevicebuilder_add_tty_port_named(
        console_builder,
        KRUN_STR("console"),
        STDIN_FILENO,
        &console_port));
    CHECK(krun_consoledevicebuilder_set_kernel_console(console_builder, console_port));

    KrunConsoleDevice console;
    CHECK(krun_consoledevicebuilder_build(console_builder, &console));

    uint32_t console_idx;
    CHECK(krun_vmmbuilder_add_device(b, (KrunDevice)console, &console_idx));

    /* Build — validates config, produces a runnable Vmm (consumes builder) */
    KrunVmm vmm;
    CHECK(krun_vmmbuilder_build(b, &vmm));
    /* b is consumed — don't use it after this */

    /* Run — does not return on success */
    CHECK(krun_vmm_run(vmm));
    return 1; /* unreachable */
}
```

---

## Complete Rust Example

```rust
use libkrun::*;
use std::io;
use std::os::fd::AsFd;
use std::path::Path;

fn main() -> Result<(), KrunError> {
    KrunLog::init(-1, 3)?; // INFO level

    // These live on the stack — the borrow checker guarantees they
    // outlive the VmmBuilder and the Vmm it produces.
    let rootfs_path = Path::new("/srv/rootfs");
    let stdin = io::stdin();

    // Initial payload bringup uses virtiofs. The payload builder mutably
    // borrows rootfs to inject `/init.krun`, then rootfs is added as a device.
    let mut rootfs = FsDevice::new("rootfs", rootfs_path)?;
    let mut payload = LibkrunInit::builder(&mut rootfs);
    payload.set_exec("/bin/sh", &["/bin/sh", "-c", "echo hello from guest"])?;
    payload.set_env(&["HOME=/root", "PATH=/usr/bin"])?;
    payload.set_workdir("/")?;
    let payload = payload.build()?;

    let mut b = VmmBuilder::new();
    b.set_vcpus(2)?;
    b.set_ram_mib(1024)?;
    b.set_payload(payload)?;
    b.add_device(rootfs)?;

    // Network — has zero effect on vsock
    let net = NetDevice::new_tap("tap0", &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56])?;
    b.add_device(net)?;

    // Vsock with TSI — explicit opt-in
    let mut vsock = VsockDevice::new();
    vsock.set_tsi_features(1); // HIJACK_INET
    vsock.set_port_map(&["8080:80", "2222:22"])?;
    b.add_device(vsock)?;

    // Console — explicit, built via builder
    let mut console = ConsoleDevice::builder();
    let console_port = console.add_tty_port_named("console", stdin.as_fd())?;
    console.set_kernel_console(console_port)?;
    let console = console.build()?;
    b.add_device(console)?;

    // build() validates, run() launches.
    // Vmm<'a> preserves the lifetime — rootfs_path and stdin
    // must live until run() completes (the compiler enforces this).
    b.build()?.run()?;

    // drop(rootfs_path); ← would be a compile error if placed before run()!

    Ok(())
}
```

The borrow checker catches use-after-free at compile time:

```rust
// ❌ COMPILE ERROR: disk_path borrowed by vmm
let disk_path = String::from("/var/lib/disk.qcow2");
let blk = BlockDevice::new("vda", Path::new(&disk_path), 1, false)?;
b.add_device(blk)?;
drop(disk_path);  // error: cannot move out of `disk_path` because it is borrowed
b.build()?.run()?;
```

In C, this safety is the caller's responsibility — ffier erases lifetimes to `'static` at the FFI boundary.

---

## Key Behavioral Changes from v1

| v1 behavior | v2 behavior |
|---|---|
| `krun_create_ctx()` auto-creates implicit vsock + console | `krun_vmmbuilder_new()` creates nothing |
| Adding a net device silently disables TSI | Adding net has zero effect on vsock |
| TSI enabled by heuristic (no net → TSI on, has net → TSI off) | TSI enabled only by `vsockdevice_set_tsi_features()` |
| Init payload hidden in lower layers / cmdline conventions | Explicit payload via `vmmbuilder_set_payload()` |
| Rootfs + guest process config split across unrelated setters | `LibkrunInit::builder(&mut rootfs)` ties virtiofs root + exec/env/workdir together |
| `krun_set_root_disk()` + `krun_add_disk()` silently conflict | One API: `blockdevice_new()` |
| Error: `-EINVAL` | Error: `KrunError { code=105, msg="vcpus must be 1..255, got 0" }` |
| Validation at `krun_start_enter()` only | Eager validation on each setter + `build()` validates fully |
| Port maps are global VM settings | Port maps are on the `VsockDevice` |
| `krun_disable_implicit_console()` | No implicit console to disable |
| `krun_disable_implicit_vsock()` | No implicit vsock to disable |
| Context IDs in a global `HashMap<u32, ...>` | Opaque handles with RTTI type checking |
| `const char**` for string arrays | `const KrunStr* items, uintptr_t count` |
| Bare `#define` for enums | Grouped `#define` constants, validated at Rust boundary |

---

## ffier Support Needed

The initial 2.0 API depends on four ffier capabilities:

1. Opaque C types should drop the redundant `Handle` suffix:

```c
typedef void* KrunVmmBuilder;
typedef void* KrunNetDevice;
```

2. `&[&str]` should expand to `const KrunStr* items, uintptr_t count`:

```rust
pub fn set_exec(&mut self, path: &str, args: &[&str]) -> Result<(), KrunError>;
```

```c
KrunError krun_libkruninitbuilder_set_exec(KrunLibkrunInitBuilder b, KrunStr path, const KrunStr* args, uintptr_t args_len);
```

3. `BorrowedFd<'a>` should map to `int32_t` on the C side while preserving the Rust lifetime:

```rust
pub fn add_tty_port(&mut self, tty_fd: BorrowedFd<'a>) -> Result<u32, KrunError>;
```

```c
KrunError krun_consoledevicebuilder_add_tty_port(KrunConsoleDeviceBuilder b, int32_t tty_fd, uint32_t* result);
```

4. ffier should support builder-style APIs for incrementally configured types such as `virtio-console` and `LibkrunInit`, while simpler types can keep `new()` / `new(args...)` constructors:

```rust
pub fn builder() -> ConsoleDeviceBuilder<'a>;
pub fn build(self) -> Result<ConsoleDevice<'a>, KrunError>;
```

Builder entry points may also need to borrow an already-configured object:

```rust
pub fn builder(rootfs: &'a mut FsDevice<'a>) -> LibkrunInitBuilder<'a>;
```

No vtable-based device implementation is required for the initial 2.0 API. C-implemented devices can wait for a later release.

---

## Appendix: Enum Constants

```c
/* Disk formats */
#define KRUN_DISK_FORMAT_RAW   0
#define KRUN_DISK_FORMAT_QCOW2 1
#define KRUN_DISK_FORMAT_VMDK  2

/* Sync modes */
#define KRUN_SYNC_NONE    0
#define KRUN_SYNC_RELAXED 1
#define KRUN_SYNC_FULL    2

/* TSI features (bitmask) */
#define KRUN_TSI_HIJACK_INET (1 << 0)
#define KRUN_TSI_HIJACK_UNIX (1 << 1)

/* Net features (bitmask) */
#define KRUN_NET_FEATURE_CSUM        (1 << 0)
#define KRUN_NET_FEATURE_GUEST_CSUM  (1 << 1)
#define KRUN_NET_FEATURE_GUEST_TSO4  (1 << 7)
#define KRUN_NET_FEATURE_GUEST_TSO6  (1 << 8)
#define KRUN_NET_FEATURE_HOST_TSO4   (1 << 11)
#define KRUN_NET_FEATURE_HOST_TSO6   (1 << 12)

/* Log levels */
#define KRUN_LOG_OFF   0
#define KRUN_LOG_ERROR 1
#define KRUN_LOG_WARN  2
#define KRUN_LOG_INFO  3
#define KRUN_LOG_DEBUG 4
#define KRUN_LOG_TRACE 5

/* Features for krun_kruninfo_has_feature() */
#define KRUN_FEATURE_NET   0
#define KRUN_FEATURE_BLK   1
#define KRUN_FEATURE_GPU   2
#define KRUN_FEATURE_INPUT 3
#define KRUN_FEATURE_EFI   4
```
