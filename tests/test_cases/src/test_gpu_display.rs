//! GPU display integration test
//!
//! This test verifies the virtio-gpu display pipeline by:
//! 1. Host: Setting up a dummy display backend that captures frames
//! 2. Guest: Using DRM ioctls to create resources, transfer data, and trigger display
//! 3. Host: Verifying the captured frame matches the expected pattern

use macros::{guest, host};

/// Display dimensions (standard VGA)
const DISPLAY_WIDTH: u32 = 640;
const DISPLAY_HEIGHT: u32 = 480;

pub struct TestGpuDisplay {
    /// If true, inject a bad pixel to test that verification catches it
    pub inject_bad_pixel: bool,
}

impl TestGpuDisplay {
    pub fn new() -> Self {
        Self { inject_bad_pixel: false }
    }

    pub fn xfail() -> Self {
        Self { inject_bad_pixel: true }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::dummy_display::{DummyDisplay, SharedFrameCapture};
    use crate::{krun_call, krun_call_u32, Test, TestSetup};
    use krun_display::IntoDisplayBackend;
    use krun_sys::*;
    use std::cell::Cell;
    use std::ffi::{c_void, CString};
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    const COLOR_RED: u32 = 0x00FF0000;
    const COLOR_BLUE: u32 = 0x000000FF;

    impl Test for TestGpuDisplay {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let (guest_fd, host_stream) = UnixStream::pair()?;
            let host_writer: &'static Cell<Option<UnixStream>> =
                Box::leak(Box::new(Cell::new(Some(host_stream))));

            let expected_color: &'static Cell<u32> = Box::leak(Box::new(Cell::new(0)));
            let frame_count: &'static Cell<u32> = Box::leak(Box::new(Cell::new(0)));

            let verifier = Box::new(move |frame: &crate::dummy_display::CapturedFrame| {
                assert_eq!(frame.width, DISPLAY_WIDTH);
                assert_eq!(frame.height, DISPLAY_HEIGHT);

                let pixels: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        frame.data.as_ptr() as *const u32,
                        frame.data.len() / 4,
                    )
                };

                let expected = expected_color.get();
                for (i, &pixel) in pixels.iter().enumerate() {
                    assert_eq!(pixel, expected, "Pixel {} mismatch", i);
                }

                let count = frame_count.get();
                frame_count.set(count + 1);

                if count == 0 {
                    // First frame verified (red), now send blue
                    expected_color.set(COLOR_BLUE);
                    if let Some(mut writer) = host_writer.take() {
                        writer.write_all(&COLOR_BLUE.to_le_bytes()).unwrap();
                        writer.flush().unwrap();
                        host_writer.set(Some(writer));
                    }
                } else if count == 1 {
                    // Second frame verified (blue), send confirmation to guest
                    if let Some(mut writer) = host_writer.take() {
                        writer.write_all(&[0xFFu8]).unwrap();
                        writer.flush().unwrap();
                    }
                    println!("OK");
                }
            });

            let shared_capture = Box::leak(Box::new(SharedFrameCapture::with_verifier(verifier)));
            let display_backend = DummyDisplay::into_display_backend(Some(shared_capture));

            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 1024))?;

                // Disable implicit console, add our own
                krun_call!(krun_disable_implicit_console(ctx))?;
                krun_call!(krun_add_virtio_console_default(ctx, -1, std::io::stdout().as_raw_fd(), -1))?;

                // Add sync console port
                let console_id = krun_call_u32!(krun_add_virtio_console_multiport(ctx))?;
                let port_name = CString::new("gpu-sync")?;
                krun_call!(krun_add_console_port_inout(
                    ctx,
                    console_id,
                    port_name.as_ptr(),
                    guest_fd.as_raw_fd(),
                    guest_fd.as_raw_fd()
                ))?;
                std::mem::forget(guest_fd);

                // Send first color to guest
                expected_color.set(COLOR_RED);
                if let Some(mut writer) = host_writer.take() {
                    writer.write_all(&COLOR_RED.to_le_bytes()).unwrap();
                    writer.flush().unwrap();
                    host_writer.set(Some(writer));
                }

                // Enable GPU with virgl
                krun_call!(krun_set_gpu_options(
                    ctx,
                    VIRGLRENDERER_USE_EGL | VIRGLRENDERER_THREAD_SYNC | VIRGLRENDERER_USE_ASYNC_FENCE_CB
                ))?;

                // Try to add display - if GPU is disabled, skip the test
                let display_result = krun_add_display(ctx, DISPLAY_WIDTH, DISPLAY_HEIGHT);
                if display_result == -95 {
                    // ENOTSUP - GPU not available
                    println!("SKIP");
                    return Ok(());
                }
                let display_id = if display_result < 0 {
                    let err = std::io::Error::from_raw_os_error(-display_result);
                    anyhow::bail!("`krun_add_display`: {}", err);
                } else {
                    display_result as u32
                };
                assert_eq!(display_id, 0);

                krun_call!(krun_set_display_backend(
                    ctx,
                    &display_backend as *const _ as *const c_void,
                    std::mem::size_of_val(&display_backend)
                ))?;

                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use nix::errno::Errno;
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;
    use std::fs;
    use std::io::Read;
    use std::os::fd::AsRawFd;

    // DRM ioctl definitions
    const DRM_IOCTL_BASE: u8 = b'd';

    /// DRM mode create dumb buffer
    #[repr(C)]
    #[derive(Default)]
    struct DrmModeCreateDumb {
        height: u32,
        width: u32,
        bpp: u32,
        flags: u32,
        handle: u32,  // Output
        pitch: u32,   // Output
        size: u64,    // Output
    }

    /// DRM mode map dumb buffer
    #[repr(C)]
    #[derive(Default)]
    struct DrmModeMapDumb {
        handle: u32,
        pad: u32,
        offset: u64,  // Output: fake offset for mmap
    }

    /// DRM mode framebuffer command
    #[repr(C)]
    #[derive(Default)]
    struct DrmModeFbCmd {
        fb_id: u32,   // Output
        width: u32,
        height: u32,
        pitch: u32,
        bpp: u32,
        depth: u32,
        handle: u32,
    }

    /// DRM mode crtc
    #[repr(C)]
    #[derive(Default)]
    struct DrmModeCrtc {
        set_connectors_ptr: u64,
        count_connectors: u32,
        crtc_id: u32,
        fb_id: u32,
        x: u32,
        y: u32,
        gamma_size: u32,
        mode_valid: u32,
        mode: DrmModeInfo,
    }

    /// DRM mode info (modeinfo)
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct DrmModeInfo {
        clock: u32,
        hdisplay: u16,
        hsync_start: u16,
        hsync_end: u16,
        htotal: u16,
        hskew: u16,
        vdisplay: u16,
        vsync_start: u16,
        vsync_end: u16,
        vtotal: u16,
        vscan: u16,
        vrefresh: u32,
        flags: u32,
        type_: u32,
        name: [u8; 32],
    }

    /// DRM mode card resources
    #[repr(C)]
    #[derive(Default)]
    struct DrmModeCardRes {
        fb_id_ptr: u64,
        crtc_id_ptr: u64,
        connector_id_ptr: u64,
        encoder_id_ptr: u64,
        count_fbs: u32,
        count_crtcs: u32,
        count_connectors: u32,
        count_encoders: u32,
        min_width: u32,
        max_width: u32,
        min_height: u32,
        max_height: u32,
    }

    /// DRM mode get connector
    #[repr(C)]
    #[derive(Default)]
    struct DrmModeGetConnector {
        encoders_ptr: u64,
        modes_ptr: u64,
        props_ptr: u64,
        prop_values_ptr: u64,
        count_modes: u32,
        count_props: u32,
        count_encoders: u32,
        encoder_id: u32,
        connector_id: u32,
        connector_type: u32,
        connector_type_id: u32,
        connection: u32,
        mm_width: u32,
        mm_height: u32,
        subpixel: u32,
        pad: u32,
    }

    /// DRM mode dirty framebuffer command
    #[repr(C)]
    #[derive(Default)]
    struct DrmModeFbDirtyCmd {
        fb_id: u32,
        flags: u32,
        color: u32,
        num_clips: u32,
        clips_ptr: u64,
    }

    // Define ioctl wrappers using nix macros
    nix::ioctl_readwrite!(drm_ioctl_mode_getresources, DRM_IOCTL_BASE, 0xA0, DrmModeCardRes);
    nix::ioctl_readwrite!(drm_ioctl_mode_getconnector, DRM_IOCTL_BASE, 0xA7, DrmModeGetConnector);
    nix::ioctl_readwrite!(drm_ioctl_mode_setcrtc, DRM_IOCTL_BASE, 0xA2, DrmModeCrtc);
    nix::ioctl_readwrite!(drm_ioctl_mode_addfb, DRM_IOCTL_BASE, 0xAE, DrmModeFbCmd);
    nix::ioctl_readwrite!(drm_ioctl_mode_dirtyfb, DRM_IOCTL_BASE, 0xB1, DrmModeFbDirtyCmd);
    nix::ioctl_readwrite!(drm_ioctl_mode_create_dumb, DRM_IOCTL_BASE, 0xB2, DrmModeCreateDumb);
    nix::ioctl_readwrite!(drm_ioctl_mode_map_dumb, DRM_IOCTL_BASE, 0xB3, DrmModeMapDumb);

    fn find_drm_device() -> Option<String> {
        // Try common DRM device paths
        for i in 0..4 {
            let path = format!("/dev/dri/card{}", i);
            if std::path::Path::new(&path).exists() {
                return Some(path);
            }
        }

        // Also check renderD nodes
        for i in 128..132 {
            let path = format!("/dev/dri/renderD{}", i);
            if std::path::Path::new(&path).exists() {
                return Some(path);
            }
        }

        None
    }

    fn open_sync_port() -> Option<fs::File> {
        let ports_dir = "/sys/class/virtio-ports";
        for entry in fs::read_dir(ports_dir).ok()? {
            let entry = entry.ok()?;
            let name_path = entry.path().join("name");
            if name_path.exists() {
                let name = fs::read_to_string(&name_path).ok()?.trim().to_string();
                if name == "gpu-sync" {
                    let path = format!("/dev/{}", entry.file_name().to_string_lossy());
                    return fs::File::open(path).ok();
                }
            }
        }
        None
    }

    fn read_color(sync_port: &mut fs::File) -> u32 {
        let mut buf = [0u8; 4];
        sync_port.read_exact(&mut buf).expect("Failed to read color");
        u32::from_le_bytes(buf)
    }

    impl Test for TestGpuDisplay {
        fn in_guest(self: Box<Self>) {
            let mut sync_port = open_sync_port().expect("gpu-sync port not found");

            // Find and open DRM device
            let drm_path = find_drm_device().expect("No DRM device found");
            let fd = open(drm_path.as_str(), OFlag::O_RDWR, Mode::empty())
                .expect("Failed to open DRM device");
            let raw_fd = fd.as_raw_fd();

            // Get resources
            let mut res = DrmModeCardRes::default();
            unsafe { drm_ioctl_mode_getresources(raw_fd, &mut res) }
                .expect("DRM_IOCTL_MODE_GETRESOURCES failed");

            let mut fb_ids = vec![0u32; res.count_fbs as usize];
            let mut crtc_ids = vec![0u32; res.count_crtcs as usize];
            let mut connector_ids = vec![0u32; res.count_connectors as usize];
            let mut encoder_ids = vec![0u32; res.count_encoders as usize];

            res.fb_id_ptr = if fb_ids.is_empty() { 0 } else { fb_ids.as_mut_ptr() as u64 };
            res.crtc_id_ptr = if crtc_ids.is_empty() { 0 } else { crtc_ids.as_mut_ptr() as u64 };
            res.connector_id_ptr = if connector_ids.is_empty() { 0 } else { connector_ids.as_mut_ptr() as u64 };
            res.encoder_id_ptr = if encoder_ids.is_empty() { 0 } else { encoder_ids.as_mut_ptr() as u64 };

            unsafe { drm_ioctl_mode_getresources(raw_fd, &mut res) }
                .expect("DRM_IOCTL_MODE_GETRESOURCES (2nd) failed");

            let crtc_id = crtc_ids[0];
            let connector_id = connector_ids[0];

            // Get connector modes from EDID
            let mut conn = DrmModeGetConnector {
                connector_id,
                ..Default::default()
            };
            unsafe { drm_ioctl_mode_getconnector(raw_fd, &mut conn) }
                .expect("DRM_IOCTL_MODE_GETCONNECTOR failed");

            assert!(conn.count_modes > 0, "No modes available");

            // Allocate arrays for all fields the kernel will write to
            let mut modes = vec![DrmModeInfo::default(); conn.count_modes as usize];
            let mut encoders = vec![0u32; conn.count_encoders as usize];
            let mut props = vec![0u32; conn.count_props as usize];
            let mut prop_values = vec![0u64; conn.count_props as usize];

            conn.modes_ptr = modes.as_mut_ptr() as u64;
            conn.encoders_ptr = if encoders.is_empty() { 0 } else { encoders.as_mut_ptr() as u64 };
            conn.props_ptr = if props.is_empty() { 0 } else { props.as_mut_ptr() as u64 };
            conn.prop_values_ptr = if prop_values.is_empty() { 0 } else { prop_values.as_mut_ptr() as u64 };

            unsafe { drm_ioctl_mode_getconnector(raw_fd, &mut conn) }
                .expect("DRM_IOCTL_MODE_GETCONNECTOR (2nd) failed");

            let mode = modes[0]; // First mode is usually preferred
            let width = mode.hdisplay as u32;
            let height = mode.vdisplay as u32;

            // Create dumb buffer using mode dimensions
            let mut create_dumb = DrmModeCreateDumb {
                width,
                height,
                bpp: 32,
                ..Default::default()
            };
            unsafe { drm_ioctl_mode_create_dumb(raw_fd, &mut create_dumb) }
                .expect("DRM_IOCTL_MODE_CREATE_DUMB failed");

            // Map buffer
            let mut map_dumb = DrmModeMapDumb {
                handle: create_dumb.handle,
                ..Default::default()
            };
            unsafe { drm_ioctl_mode_map_dumb(raw_fd, &mut map_dumb) }
                .expect("DRM_IOCTL_MODE_MAP_DUMB failed");

            let buffer_ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    create_dumb.size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    raw_fd,
                    map_dumb.offset as i64,
                )
            };
            assert!(buffer_ptr != libc::MAP_FAILED, "mmap failed: {}", Errno::last());

            let buffer = unsafe {
                std::slice::from_raw_parts_mut(
                    buffer_ptr as *mut u32,
                    (create_dumb.size as usize) / 4,
                )
            };

            // Create framebuffer
            let mut fb_cmd = DrmModeFbCmd {
                width,
                height,
                pitch: create_dumb.pitch,
                bpp: 32,
                depth: 24,
                handle: create_dumb.handle,
                ..Default::default()
            };
            unsafe { drm_ioctl_mode_addfb(raw_fd, &mut fb_cmd) }
                .expect("DRM_IOCTL_MODE_ADDFB failed");

            // Setup CRTC with mode from EDID
            let mut crtc = DrmModeCrtc {
                crtc_id,
                fb_id: fb_cmd.fb_id,
                x: 0,
                y: 0,
                mode_valid: 1,
                mode,
                set_connectors_ptr: &connector_id as *const u32 as u64,
                count_connectors: 1,
                ..Default::default()
            };

            // Read first color from host, display it
            let color1 = read_color(&mut sync_port);
            for pixel in buffer.iter_mut() {
                *pixel = color1;
            }
            if self.inject_bad_pixel {
                buffer[12345] = 0xDEADBEEF;
            }
            unsafe { drm_ioctl_mode_setcrtc(raw_fd, &mut crtc) }
                .expect("DRM_IOCTL_MODE_SETCRTC failed");

            // Read second color from host, display it
            let color2 = read_color(&mut sync_port);
            for pixel in buffer.iter_mut() {
                *pixel = color2;
            }
            let mut dirty_cmd = DrmModeFbDirtyCmd {
                fb_id: fb_cmd.fb_id,
                ..Default::default()
            };
            unsafe { drm_ioctl_mode_dirtyfb(raw_fd, &mut dirty_cmd) }
                .expect("DRM_IOCTL_MODE_DIRTYFB failed");

            // Wait for host confirmation that second frame was verified
            let mut confirm = [0u8; 1];
            sync_port.read_exact(&mut confirm).expect("Failed to read confirmation");

            unsafe {
                libc::munmap(buffer_ptr, create_dumb.size as usize);
            }
        }
    }
}
