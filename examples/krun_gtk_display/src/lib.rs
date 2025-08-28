mod display_backend;
mod display_worker;
mod input_backend;
mod scanout_paintable;

use crate::display_worker::DisplayWorker;
use crate::input_backend::{GtkInputConfig, GtkInputEvents};
use anyhow::Context;
pub use display_backend::DisplayEvent;
pub use display_backend::GtkDisplayBackend;
use krun_display::{DisplayBackend, IntoDisplayBackend};
use krun_input::{InputBackend, InputBackendProvider, InputEvent as KrunInputEvent, InputEvent, IntoInputBackend};
use utils::pollable_channel::{PollableChannelReciever, PollableChannelSender, pollable_channel};

pub struct DisplayBackendHandle {
    tx: PollableChannelSender<DisplayEvent>,
}

impl DisplayBackendHandle {
    pub fn get(&self) -> DisplayBackend {
        GtkDisplayBackend::into_display_backend(Some(&self.tx))
    }
}

pub struct InputBackendHandle {
    input_event_rx: PollableChannelReciever<KrunInputEvent>,
}

impl InputBackendHandle {
    pub fn get(&self) -> InputBackend {
        struct Foo;
        impl InputBackendProvider for Foo {
            type EventsObject = GtkInputEvents;
            type ConfigObject = GtkInputConfig;
        }

        Foo::into_input_backend(Some(
            &self.input_event_rx,
        ))
    }
}

pub struct DisplayBackendWorker {
    app_name: String,
    rx: PollableChannelReciever<DisplayEvent>,
    input_event_tx: Option<PollableChannelSender<InputEvent>>,
}

impl DisplayBackendWorker {
    /// NOTE: on macOS GTK has to run on the main thread of the application.
    pub fn run(self) {
        DisplayWorker::run(self.app_name, self.rx, self.input_event_tx)
    }
}

pub fn crate_display(app_name: String) -> (DisplayBackendHandle, DisplayBackendWorker) {
    let (tx, rx) = pollable_channel()
        .context("Failed to create channel")
        .unwrap();

    (
        DisplayBackendHandle { tx },
        DisplayBackendWorker {
            app_name,
            rx,
            input_event_tx: None,
        },
    )
}

pub fn create_display_with_input(
    app_name: String,
) -> (
    DisplayBackendHandle,
    InputBackendHandle,
    DisplayBackendWorker,
) {
    let (display_tx, display_rx) = pollable_channel()
        .context("Failed to create display channel")
        .unwrap();

    // Create the input event channel and forwarder
    let (input_event_tx, input_event_rx) = pollable_channel()
        .context("Failed to create input channel")
        .unwrap();

    (
        DisplayBackendHandle { tx: display_tx },
        InputBackendHandle { input_event_rx },
        DisplayBackendWorker {
            app_name,
            rx: display_rx,
            input_event_tx: Some(input_event_tx),
        },
    )
}
