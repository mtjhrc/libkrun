mod display_backend;
mod display_worker;
mod scanout_paintable;

use crate::gtk_display::display_worker::DisplayWorker;
use anyhow::Context;
pub use display_backend::DisplayEvent;
pub use display_backend::GtkDisplayBackend;
use krun_display::{DisplayBackend, DisplayFeatures, IntoDisplayBackend};
use utils::pollable_channel::{PollableChannelReciever, PollableChannelSender, pollable_channel};

pub struct DisplayBackendHandle {
    tx: PollableChannelSender<DisplayEvent>,
}

impl DisplayBackendHandle {
    pub fn get(&self) -> DisplayBackend {
        GtkDisplayBackend::into_display_backend(Some(&self.tx))
    }

    pub fn features(&self) -> u64 {
        DisplayFeatures::BASIC_FRAMEBUFFER.bits()
    }
}

pub struct DisplayBackendWorker {
    rx: PollableChannelReciever<DisplayEvent>,
}
impl DisplayBackendWorker {
    /// NOTE: on macOS GTK has to run on the main thread of the application. This doesn't matter
    /// on Linux.
    pub fn run(self) {
        DisplayWorker::run(self.rx)
    }
}

pub fn crate_display() -> (DisplayBackendHandle, DisplayBackendWorker) {
    let (tx, rx) = pollable_channel()
        .context("Failed to create channel")
        .expect("TODO");

    (DisplayBackendHandle { tx }, DisplayBackendWorker { rx })
}
