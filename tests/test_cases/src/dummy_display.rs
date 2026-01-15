//! Dummy display backend for testing GPU output
//!
//! This implements a DisplayBackend that captures frames for verification.

use krun_display::{
    DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendNew, ResourceFormat, Rect,
    MAX_DISPLAYS,
};
use std::sync::Mutex;

/// A captured frame from the display backend
#[derive(Clone)]
pub struct CapturedFrame {
    pub scanout_id: u32,
    pub width: u32,
    pub height: u32,
    pub format: ResourceFormat,
    pub data: Vec<u8>,
}

/// Frame verification function type
pub type FrameVerifier = Box<dyn Fn(&CapturedFrame) + Send + Sync>;

/// Shared state for capturing frames from the display backend
pub struct SharedFrameCapture {
    pub frames: Mutex<Vec<CapturedFrame>>,
    pub verifier: Option<FrameVerifier>,
}

impl SharedFrameCapture {
    pub fn new() -> Self {
        Self {
            frames: Mutex::new(Vec::new()),
            verifier: None,
        }
    }

    pub fn with_verifier(verifier: FrameVerifier) -> Self {
        Self {
            frames: Mutex::new(Vec::new()),
            verifier: Some(verifier),
        }
    }
}

unsafe impl Sync for SharedFrameCapture {}

/// State for a single scanout
struct ScanoutState {
    display_width: u32,
    display_height: u32,
    width: u32,
    height: u32,
    format: ResourceFormat,
    /// Frame buffers - each entry is (frame_id, buffer)
    frames: Vec<Vec<u8>>,
    /// Next frame ID to allocate
    next_frame_id: u32,
}

impl ScanoutState {
    fn new(
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: ResourceFormat,
    ) -> Self {
        Self {
            display_width,
            display_height,
            width,
            height,
            format,
            frames: Vec::new(),
            next_frame_id: 0,
        }
    }

    fn buffer_size(&self) -> usize {
        (self.width as usize) * (self.height as usize) * ResourceFormat::BYTES_PER_PIXEL
    }
}

/// Dummy display backend that captures frames for testing
pub struct DummyDisplay {
    shared: *const SharedFrameCapture,
    scanouts: [Option<ScanoutState>; MAX_DISPLAYS],
}

impl DisplayBackendNew<SharedFrameCapture> for DummyDisplay {
    fn new(userdata: Option<&SharedFrameCapture>) -> Self {
        Self {
            shared: userdata
                .map(|u| u as *const SharedFrameCapture)
                .unwrap_or(std::ptr::null()),
            scanouts: std::array::from_fn(|_| None),
        }
    }
}

impl DisplayBackendBasicFramebuffer for DummyDisplay {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: ResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        eprintln!("DummyDisplay::configure_scanout(scanout_id={}, display={}x{}, resource={}x{}, format={:?})",
            scanout_id, display_width, display_height, width, height, format);
        let scanout_idx = scanout_id as usize;
        if scanout_idx >= MAX_DISPLAYS {
            return Err(DisplayBackendError::InvalidScanoutId);
        }

        self.scanouts[scanout_idx] = Some(ScanoutState::new(
            display_width,
            display_height,
            width,
            height,
            format,
        ));

        Ok(())
    }

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError> {
        let scanout_idx = scanout_id as usize;
        if scanout_idx >= MAX_DISPLAYS {
            return Err(DisplayBackendError::InvalidScanoutId);
        }

        self.scanouts[scanout_idx] = None;
        Ok(())
    }

    fn alloc_frame(&mut self, scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        eprintln!("DummyDisplay::alloc_frame(scanout_id={})", scanout_id);
        let scanout_idx = scanout_id as usize;
        if scanout_idx >= MAX_DISPLAYS {
            return Err(DisplayBackendError::InvalidScanoutId);
        }

        let scanout = self.scanouts[scanout_idx]
            .as_mut()
            .ok_or(DisplayBackendError::InvalidScanoutId)?;

        let frame_id = scanout.next_frame_id;
        scanout.next_frame_id += 1;
        eprintln!("DummyDisplay::alloc_frame -> frame_id={}", frame_id);

        let buffer_size = scanout.buffer_size();
        let buffer = vec![0u8; buffer_size];

        // Store the frame buffer
        let frame_idx = frame_id as usize;
        if frame_idx >= scanout.frames.len() {
            scanout.frames.resize(frame_idx + 1, Vec::new());
        }
        scanout.frames[frame_idx] = buffer;

        // Return reference to the buffer
        let buffer_ref = &mut scanout.frames[frame_idx];
        Ok((frame_id, buffer_ref.as_mut_slice()))
    }

    fn present_frame(
        &mut self,
        scanout_id: u32,
        frame_id: u32,
        _rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        eprintln!("DummyDisplay::present_frame(scanout_id={}, frame_id={})", scanout_id, frame_id);

        let scanout_idx = scanout_id as usize;
        if scanout_idx >= MAX_DISPLAYS {
            return Err(DisplayBackendError::InvalidScanoutId);
        }

        let scanout = self.scanouts[scanout_idx]
            .as_ref()
            .ok_or(DisplayBackendError::InvalidScanoutId)?;

        let frame_idx = frame_id as usize;
        if frame_idx >= scanout.frames.len() {
            return Err(DisplayBackendError::InvalidParam);
        }

        // Capture the frame
        let captured = CapturedFrame {
            scanout_id,
            width: scanout.width,
            height: scanout.height,
            format: scanout.format,
            data: scanout.frames[frame_idx].clone(),
        };

        eprintln!("DummyDisplay: captured frame {}x{}, {} bytes",
            captured.width, captured.height, captured.data.len());

        // Store in shared capture if available
        if !self.shared.is_null() {
            // SAFETY: We trust the caller to provide a valid pointer
            let shared = unsafe { &*self.shared };

            // Call verifier if set (will panic on failure)
            if let Some(ref verifier) = shared.verifier {
                eprintln!("DummyDisplay: running frame verifier...");
                verifier(&captured);
                eprintln!("DummyDisplay: frame verification PASSED");
            }

            shared.frames.lock().unwrap().push(captured);
        }

        Ok(())
    }
}
