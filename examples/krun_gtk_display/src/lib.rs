mod display_backend;
mod display_worker;
mod input_backend;
mod input_constants;
mod scanout_paintable;

use crate::display_worker::DisplayWorker;
use crate::input_backend::{
    GtkInputEventProvider, GtkKeyboardConfig, GtkMouseConfig, GtkTouchscreenConfig,
};
use anyhow::Context;
pub use display_backend::DisplayEvent;
pub use display_backend::GtkDisplayBackend;
use krun_display::{DisplayBackend, IntoDisplayBackend};
use krun_input::{InputConfigBackend, InputEventProviderBackend};
use krun_input::{InputEvent, IntoInputConfig, IntoInputEvents};
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
    rx: PollableChannelReciever<InputEvent>,
    input_type: InputType,
}

impl InputBackendHandle {
    fn new(rx: PollableChannelReciever<InputEvent>, device_type: InputType) -> Self {
        Self { rx, input_type: device_type }
    }

    pub fn get_events(&self) -> InputEventProviderBackend {
        GtkInputEventProvider::into_input_events(Some(&self.rx))
    }

    pub fn get_config(&self) -> InputConfigBackend {
        match self.input_type {
            InputType::Keyboard => GtkKeyboardConfig::into_input_config(None),
            InputType::Mouse => {
                unreachable!();
                GtkMouseConfig::into_input_config(None)
            },
            InputType::TouchScreen => GtkTouchscreenConfig::into_input_config(None),
        }
    }
}

pub struct DisplayBackendWorker {
    app_name: String,
    display_rx: PollableChannelReciever<DisplayEvent>,
    keyboard_tx: Option<PollableChannelSender<InputEvent>>,
    mouse_tx: Option<PollableChannelSender<InputEvent>>,
    touch_tx: Option<PollableChannelSender<InputEvent>>,
}

impl DisplayBackendWorker {
    /// NOTE: on macOS GTK has to run on the main thread of the application.
    pub fn run(self) {
        DisplayWorker::run(
            self.app_name,
            self.display_rx,
            self.keyboard_tx,
            self.mouse_tx,
            self.touch_tx,
        );
    }
}


#[derive(Clone)]
pub enum InputType {
    Keyboard,
    Mouse,
    TouchScreen,
}

/// Create gtk display and input backends
pub fn create_display_with_input(
    app_name: String,
) -> anyhow::Result<(
    DisplayBackendHandle,
    Vec<InputBackendHandle>,
    DisplayBackendWorker,
)> {
    let (display_tx, display_rx) =
        pollable_channel().context("Failed to create display events channel")?;
    let (keyboard_tx, keyboard_rx) =
        pollable_channel().context("Failed to create keyboard events channel")?;
    let (mouse_tx, mouse_rx) =
        pollable_channel().context("Failed to create mouse events channel")?;

    let (touch_tx, touch_rx) =
        pollable_channel().context("Failed to create mouse events channel")?;

    let display_backend = DisplayBackendHandle { tx: display_tx };
    let input_handles = vec![
        InputBackendHandle::new(keyboard_rx, InputType::Keyboard),
        //InputBackendHandle::new(mouse_rx, InputType::Mouse),
        InputBackendHandle::new(touch_rx, InputType::TouchScreen),
    ];
    let worker = DisplayBackendWorker {
        app_name,
        display_rx,
        keyboard_tx: Some(keyboard_tx),
        mouse_tx: Some(mouse_tx),
        touch_tx: Some(touch_tx),
    };

    Ok((display_backend, input_handles, worker))
}
