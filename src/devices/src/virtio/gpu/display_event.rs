use std::fmt::Display;
use crate::virtio::gpu::protocol::virtio_gpu_rect;
use sdl3::pixels::PixelFormat;
use thiserror::Error;

pub enum DisplayEvent {
    EnableScanout(ScanoutId, Dimensions),
    DisableScanout(ScanoutId),
    UpdateScanout(ScanoutId, ScanoutUpdate),
    ShowWindow(usize),
}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub struct ScanoutId(pub u32);

impl ScanoutId {
    pub fn as_index(&self) -> usize {
        self.0 as usize
    }
}

impl Display for ScanoutId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Into<usize> for ScanoutId {
    fn into(self) -> usize {
        self.0 as usize
    }
}

pub struct ScanoutUpdate {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// Pitch/ specified in pixels
    pub pitch: u32,
    pub damage_area: Rect,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn dimensions(&self) -> Dimensions {
        Dimensions::new(self.width, self.height)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Dimensions {
    pub width: u32,
    pub height: u32,
}

impl Dimensions {
    pub fn new(width: u32, height: u32) -> Dimensions {
        Self { width, height }
    }

    pub fn as_rect(&self) -> Rect {
        Rect::new(0, 0, self.width, self.height)
    }
}

impl From<virtio_gpu_rect> for Rect {
    fn from(rect: virtio_gpu_rect) -> Self {
        Self {
            x: rect.x,
            y: rect.y,
            width: rect.width,
            height: rect.height,
        }
    }
}

impl TryInto<sdl3::rect::Rect> for Rect {
    type Error = <i32 as TryInto<u32>>::Error;
    fn try_into(self) -> Result<sdl3::rect::Rect, Self::Error> {
        Ok(sdl3::rect::Rect::new(
            self.x.try_into()?,
            self.y.try_into()?,
            self.width,
            self.height,
        ))
    }
}
