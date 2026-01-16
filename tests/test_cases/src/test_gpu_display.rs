//! GPU display integration test
//!
//! This test verifies the virtio-gpu display pipeline by:
//! 1. Host: Setting up a dummy display backend that captures frames
//! 2. Guest: Using DRM ioctls to create resources, transfer data, and trigger display
//! 3. Host: Verifying the captured frame matches the expected pattern

use macros::{guest, host};

/// Display dimensions
const DISPLAY_WIDTH: u32 = 64;
const DISPLAY_HEIGHT: u32 = 64;

pub struct TestGpuDisplay;

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::dummy_display::{DummyDisplay, SharedFrameCapture};
    use crate::{krun_call, krun_call_u32, Test, TestSetup};
    use krun_display::IntoDisplayBackend;
    use krun_sys::*;
    use std::ffi::c_void;

    use std::cell::Cell;

    const TEST_PATTERN_RED_BGRX: u32 = 0x00FF0000;
    const TEST_PATTERN_BLUE_BGRX: u32 = 0x000000FF;

    impl Test for TestGpuDisplay {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            // State: 0 = nothing, 1 = seen red, 2 = seen blue
            let state: &'static Cell<u8> = Box::leak(Box::new(Cell::new(0)));

            let verifier = Box::new(move |frame: &crate::dummy_display::CapturedFrame| {
                assert_eq!(frame.width, DISPLAY_WIDTH);
                assert_eq!(frame.height, DISPLAY_HEIGHT);

                let pixels: &[u32] = unsafe {
                    std::slice::from_raw_parts(
                        frame.data.as_ptr() as *const u32,
                        frame.data.len() / 4,
                    )
                };

                let first_pixel = pixels[0];
                let expected_color = match first_pixel {
                    TEST_PATTERN_RED_BGRX => TEST_PATTERN_RED_BGRX,
                    TEST_PATTERN_BLUE_BGRX => {
                        assert!(state.get() >= 1, "Got blue before red");
                        TEST_PATTERN_BLUE_BGRX
                    }
                    _ => panic!("Unknown color 0x{:08X}", first_pixel),
                };

                for (i, &pixel) in pixels.iter().enumerate() {
                    assert_eq!(pixel, expected_color, "Pixel {} mismatch", i);
                }

                match (state.get(), expected_color) {
                    (0, TEST_PATTERN_RED_BGRX) => state.set(1),
                    (1, TEST_PATTERN_RED_BGRX) => {}
                    (1, TEST_PATTERN_BLUE_BGRX) => {
                        state.set(2);
                        println!("OK");
                    }
                    (2, TEST_PATTERN_BLUE_BGRX) => {}
                    (s, c) => panic!("Invalid transition: state {} + color 0x{:08X}", s, c),
                }
            });

            // Create shared frame capture with verifier - leaked to ensure it lives long enough
            let shared_capture = Box::leak(Box::new(SharedFrameCapture::with_verifier(verifier)));
            let display_backend = DummyDisplay::into_display_backend(Some(shared_capture));

            unsafe {
                krun_call!(krun_set_log_level(KRUN_LOG_LEVEL_TRACE))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 1024))?;

                // Enable GPU with virgl
                krun_call!(krun_set_gpu_options(
                    ctx,
                    VIRGLRENDERER_USE_EGL | VIRGLRENDERER_THREAD_SYNC | VIRGLRENDERER_USE_ASYNC_FENCE_CB
                ))?;

                // Add display
                let display_id = krun_call_u32!(krun_add_display(ctx, DISPLAY_WIDTH, DISPLAY_HEIGHT))?;
                assert_eq!(display_id, 0);

                // Set display backend
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
    use std::os::fd::AsRawFd;

    /// Test pattern: solid red color (XRGB8888 format)
    const TEST_PATTERN_RED: u32 = 0x00FF0000;
    /// Test pattern: solid blue color (XRGB8888 format)
    const TEST_PATTERN_BLUE: u32 = 0x000000FF;

    // DRM ioctl definitions
    const DRM_IOCTL_BASE: u8 = b'd';

    /// DRM version ioctl structure
    #[repr(C)]
    struct DrmVersion {
        version_major: i32,
        version_minor: i32,
        version_patchlevel: i32,
        name_len: usize,
        name: *mut u8,
        date_len: usize,
        date: *mut u8,
        desc_len: usize,
        desc: *mut u8,
    }

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

    /// DRM mode page flip
    #[repr(C)]
    #[derive(Default)]
    struct DrmModePageFlip {
        crtc_id: u32,
        fb_id: u32,
        flags: u32,
        reserved: u32,
        user_data: u64,
    }

    // Define ioctl wrappers using nix macros
    nix::ioctl_readwrite!(drm_ioctl_version, DRM_IOCTL_BASE, 0x00, DrmVersion);
    nix::ioctl_readwrite!(drm_ioctl_mode_getresources, DRM_IOCTL_BASE, 0xA0, DrmModeCardRes);
    nix::ioctl_readwrite!(drm_ioctl_mode_setcrtc, DRM_IOCTL_BASE, 0xA2, DrmModeCrtc);
    nix::ioctl_readwrite!(drm_ioctl_mode_page_flip, DRM_IOCTL_BASE, 0xA7, DrmModePageFlip);
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

    fn list_dev_contents() {
        eprintln!("Checking /dev contents:");
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                eprintln!("  /dev/{}", entry.file_name().to_string_lossy());
            }
        } else {
            eprintln!("  Cannot read /dev");
        }

        eprintln!("Checking /dev/dri contents:");
        if let Ok(entries) = std::fs::read_dir("/dev/dri") {
            for entry in entries.flatten() {
                eprintln!("  /dev/dri/{}", entry.file_name().to_string_lossy());
            }
        } else {
            eprintln!("  /dev/dri does not exist");
        }
    }

    impl Test for TestGpuDisplay {
        fn in_guest(self: Box<Self>) {
            list_dev_contents();

            // Find and open DRM device
            let drm_path = find_drm_device().expect("No DRM device found");
            eprintln!("Found DRM device: {}", drm_path);

            let fd = open(drm_path.as_str(), OFlag::O_RDWR, Mode::empty())
                .expect("Failed to open DRM device");
            let raw_fd = fd.as_raw_fd();

            // Get DRM version to verify we have a valid device
            let mut name_buf = [0u8; 64];
            let mut version = DrmVersion {
                version_major: 0,
                version_minor: 0,
                version_patchlevel: 0,
                name_len: name_buf.len(),
                name: name_buf.as_mut_ptr(),
                date_len: 0,
                date: std::ptr::null_mut(),
                desc_len: 0,
                desc: std::ptr::null_mut(),
            };

            unsafe { drm_ioctl_version(raw_fd, &mut version) }
                .expect("DRM_IOCTL_VERSION failed");

            let driver_name = std::str::from_utf8(&name_buf[..version.name_len])
                .unwrap_or("unknown");
            eprintln!("DRM driver: {} v{}.{}.{}",
                driver_name, version.version_major, version.version_minor, version.version_patchlevel);

            // Get resources to find CRTC
            let mut res = DrmModeCardRes::default();
            unsafe { drm_ioctl_mode_getresources(raw_fd, &mut res) }
                .expect("DRM_IOCTL_MODE_GETRESOURCES failed");

            eprintln!("DRM resources: {} CRTCs, {} connectors, {} encoders, {} fbs",
                res.count_crtcs, res.count_connectors, res.count_encoders, res.count_fbs);

            // Allocate arrays for ALL resource types (kernel writes to all non-zero counts)
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

            eprintln!("Got CRTC IDs: {:?}, connector IDs: {:?}", crtc_ids, connector_ids);

            assert!(!crtc_ids.is_empty(), "No CRTCs available");
            let crtc_id = crtc_ids[0];
            eprintln!("Using CRTC {}", crtc_id);

            // Create a dumb buffer
            let mut create_dumb = DrmModeCreateDumb {
                width: DISPLAY_WIDTH,
                height: DISPLAY_HEIGHT,
                bpp: 32,
                ..Default::default()
            };

            unsafe { drm_ioctl_mode_create_dumb(raw_fd, &mut create_dumb) }
                .expect("DRM_IOCTL_MODE_CREATE_DUMB failed");

            eprintln!("Created dumb buffer: handle={}, pitch={}, size={}",
                create_dumb.handle, create_dumb.pitch, create_dumb.size);

            // Map the dumb buffer
            let mut map_dumb = DrmModeMapDumb {
                handle: create_dumb.handle,
                ..Default::default()
            };

            unsafe { drm_ioctl_mode_map_dumb(raw_fd, &mut map_dumb) }
                .expect("DRM_IOCTL_MODE_MAP_DUMB failed");

            // mmap the buffer
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

            // Write test pattern (solid red) to buffer
            let buffer = unsafe {
                std::slice::from_raw_parts_mut(
                    buffer_ptr as *mut u32,
                    (create_dumb.size as usize) / 4,
                )
            };

            for pixel in buffer.iter_mut() {
                *pixel = TEST_PATTERN_RED;
            }

            eprintln!("Wrote test pattern to buffer");

            // Create framebuffer
            let mut fb_cmd = DrmModeFbCmd {
                width: DISPLAY_WIDTH,
                height: DISPLAY_HEIGHT,
                pitch: create_dumb.pitch,
                bpp: 32,
                depth: 24,
                handle: create_dumb.handle,
                ..Default::default()
            };

            unsafe { drm_ioctl_mode_addfb(raw_fd, &mut fb_cmd) }
                .expect("DRM_IOCTL_MODE_ADDFB failed");

            eprintln!("Created framebuffer: fb_id={}", fb_cmd.fb_id);

            // Set CRTC to display the framebuffer
            let connector_id = if !connector_ids.is_empty() { connector_ids[0] } else { 0 };

            let mut crtc = DrmModeCrtc {
                crtc_id,
                fb_id: fb_cmd.fb_id,
                x: 0,
                y: 0,
                mode_valid: 1,
                mode: DrmModeInfo {
                    hdisplay: DISPLAY_WIDTH as u16,
                    vdisplay: DISPLAY_HEIGHT as u16,
                    vrefresh: 60,
                    clock: 25175, // Standard VGA clock
                    hsync_start: (DISPLAY_WIDTH + 16) as u16,
                    hsync_end: (DISPLAY_WIDTH + 16 + 96) as u16,
                    htotal: (DISPLAY_WIDTH + 16 + 96 + 48) as u16,
                    vsync_start: (DISPLAY_HEIGHT + 10) as u16,
                    vsync_end: (DISPLAY_HEIGHT + 10 + 2) as u16,
                    vtotal: (DISPLAY_HEIGHT + 10 + 2 + 33) as u16,
                    ..Default::default()
                },
                set_connectors_ptr: &connector_id as *const u32 as u64,
                count_connectors: if connector_id != 0 { 1 } else { 0 },
                ..Default::default()
            };

            unsafe { drm_ioctl_mode_setcrtc(raw_fd, &mut crtc) }
                .expect("DRM_IOCTL_MODE_SETCRTC failed");
            eprintln!("Set CRTC successfully (frame 0: red)");

            // Give the display backend time to process first frame
            std::thread::sleep(std::time::Duration::from_millis(100));

            // === Render second frame with blue (using a new buffer + page flip) ===

            // Create second dumb buffer for blue frame
            let mut create_dumb2 = DrmModeCreateDumb {
                width: DISPLAY_WIDTH,
                height: DISPLAY_HEIGHT,
                bpp: 32,
                ..Default::default()
            };

            unsafe { drm_ioctl_mode_create_dumb(raw_fd, &mut create_dumb2) }
                .expect("DRM_IOCTL_MODE_CREATE_DUMB (2) failed");

            let mut map_dumb2 = DrmModeMapDumb {
                handle: create_dumb2.handle,
                ..Default::default()
            };

            unsafe { drm_ioctl_mode_map_dumb(raw_fd, &mut map_dumb2) }
                .expect("DRM_IOCTL_MODE_MAP_DUMB (2) failed");

            let buffer_ptr2 = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    create_dumb2.size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    raw_fd,
                    map_dumb2.offset as i64,
                )
            };

            assert!(buffer_ptr2 != libc::MAP_FAILED, "mmap (2) failed: {}", Errno::last());

            // Write blue pattern to second buffer
            let buffer2 = unsafe {
                std::slice::from_raw_parts_mut(
                    buffer_ptr2 as *mut u32,
                    (create_dumb2.size as usize) / 4,
                )
            };

            for pixel in buffer2.iter_mut() {
                *pixel = TEST_PATTERN_BLUE;
            }
            eprintln!("Wrote blue pattern to buffer 2");

            // Create second framebuffer
            let mut fb_cmd2 = DrmModeFbCmd {
                width: DISPLAY_WIDTH,
                height: DISPLAY_HEIGHT,
                pitch: create_dumb2.pitch,
                bpp: 32,
                depth: 24,
                handle: create_dumb2.handle,
                ..Default::default()
            };

            unsafe { drm_ioctl_mode_addfb(raw_fd, &mut fb_cmd2) }
                .expect("DRM_IOCTL_MODE_ADDFB (2) failed");

            eprintln!("Created framebuffer 2: fb_id={}", fb_cmd2.fb_id);

            // Set CRTC to display the second framebuffer
            crtc.fb_id = fb_cmd2.fb_id;
            unsafe { drm_ioctl_mode_setcrtc(raw_fd, &mut crtc) }
                .expect("DRM_IOCTL_MODE_SETCRTC (frame 1) failed");
            eprintln!("Set CRTC to frame 1 (blue) successful");

            // Mark the new framebuffer as dirty to trigger a flush
            let mut dirty_cmd = DrmModeFbDirtyCmd {
                fb_id: fb_cmd2.fb_id,
                ..Default::default()
            };
            unsafe { drm_ioctl_mode_dirtyfb(raw_fd, &mut dirty_cmd) }
                .expect("DRM_IOCTL_MODE_DIRTYFB (frame 1) failed");
            eprintln!("Marked framebuffer 2 dirty");

            // Give the display backend time to process second frame
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Cleanup
            unsafe {
                libc::munmap(buffer_ptr, create_dumb.size as usize);
                libc::munmap(buffer_ptr2, create_dumb2.size as usize);
            }
        }
    }
}
