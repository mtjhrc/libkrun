use super::scanout_paintable::ScanoutPaintable;
use crate::DisplayEvent;
use krun_display::Rect;
use krun_input::{InputEvent, InputEventType};
use log::{debug, trace, warn};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::iter;
use std::os::fd::AsRawFd;
use std::rc::Rc;
use std::time::Duration;

use utils::pollable_channel::{PollableChannelReciever, PollableChannelSender};

use crate::input_backend::gtk_keycode_to_linux;
use crate::input_constants::{
    ABS_MT_POSITION_X, ABS_MT_POSITION_Y, ABS_MT_SLOT, ABS_X, ABS_Y, BTN_TOUCH,
};
use gtk::builders::EventControllerMotionBuilder;
use gtk::ffi::gtk_file_dialog_get_accept_label;
use gtk::gdk::InputSource::Keyboard;
use gtk::gdk::{Display, EventSequence, EventType, InputSource, SeatCapabilities, TouchEvent};
use gtk::glib::{
    idle_add_once, timeout_add, timeout_add_local, timeout_add_seconds, timeout_source_new,
};
use gtk::{
    AlertDialog, Align, Application, ApplicationWindow, Button, EventControllerKey,
    EventControllerLegacy, EventControllerMotion, HeaderBar, Overlay, Picture, Revealer,
    RevealerTransitionType, Window, gdk,
    gdk::MemoryFormat,
    gio::ActionEntry,
    gio::Cancellable,
    glib::{self, Bytes, ControlFlow, IOCondition, Propagation, unix_fd_add_local},
    prelude::*,
};
use krun_display::MAX_DISPLAYS;

type EventSender = PollableChannelSender<InputEvent>;

struct FingerState {
    seq: EventSequence,
    current_position: Option<(u32, u32)>,
}

struct TouchSequencedSender {
    fingers: Vec<FingerState>,
    synced_pos: (u32, u32),
    pending_pos: (u32, u32),
    active_slot: u16,
    queue: Vec<InputEvent>,
    tx: EventSender,
}

impl TouchSequencedSender {
    fn new(tx: EventSender) -> Self {
        Self {
            fingers: Vec::new(),
            synced_pos: (0, 0),
            pending_pos: (0, 0),
            tx,
            active_slot: u16::MAX,
            queue: Vec::new(),
        }
    }

    fn sync(&mut self) {
        if self.queue.is_empty() {
            return;
        }

        debug!("Sync: {:#?}", &self.queue);

        let pending_events = [const {
            InputEvent {
                type_: 0,
                code: 0,
                value: 0,
            }
        }; 2];
        let mut pending_events_len = 0;

        if self.pending_pos.0 != self.synced_pos.0 {
            self.queue.push(InputEvent {
                type_: InputEventType::Abs as u16,
                code: ABS_X,
                value: self.pending_pos.0,
            });
            pending_events_len += 1;
        }

        if self.pending_pos.1 != self.synced_pos.1 {
            self.queue.push(InputEvent {
                type_: InputEventType::Abs as u16,
                code: ABS_Y,
                value: self.pending_pos.1,
            });
            pending_events_len += 1;
        }

        let final_sync_event = iter::once(InputEvent {
            type_: InputEventType::Syn as u16,
            code: 0,
            value: 0,
        });

        let input_events = self.queue.drain(..);

        self.synced_pos = self.pending_pos;

        let iter = (&pending_events[..pending_events_len]).iter().copied();
        self.tx
            .send_many(
                input_events
                    .chain(final_sync_event)
                    .chain(iter),
            )
            .unwrap();
    }

    fn clear_finger_positions(&mut self) {
        for f in &mut self.fingers {
            f.current_position = None;
        }
    }

    // Map gtk coordinates to ours
    fn map_position((x, y): (f64, f64)) -> (u32, u32) {
        ((x * 13764.0 / 1280.0) as u32, (y * 7740.0 / 720.0) as u32)
    }

    fn emit_finger_id(&mut self, finger_id: u16) {
        if self.active_slot == finger_id {
            return;
        }
        self.queue.push(InputEvent {
            type_: InputEventType::Abs as u16,
            code: ABS_MT_SLOT,
            value: finger_id as u32,
        });
        self.active_slot = finger_id;
    }

    fn push_event(&mut self, event: &TouchEvent) {
        let finger_idx = self.track_finger(event.event_sequence());
        let (x, y) = Self::map_position(event.position().unwrap());

        if finger_idx == 0 {
            self.pending_pos = (x, y);
        }

        // TODO: do we need to sync here, or just leave it up to the timer?
        if self.fingers[finger_idx as usize].current_position.is_some() {
            self.sync();
        }

        let ev_type = event.event_type();

        let (old_x, old_y) = self.fingers[finger_idx as usize]
            .current_position
            .map(|(x, y)| (Some(x), Some(y)))
            .unwrap_or((None, None));

        self.emit_finger_id(finger_idx);

        if old_x.is_none_or(|old_x| old_x == x) {
            self.queue.push(InputEvent {
                type_: InputEventType::Abs as u16,
                code: ABS_MT_POSITION_X,
                value: x,
            });
        }

        if old_y.is_none_or(|old_y| old_y == y) {
            self.queue.push(InputEvent {
                type_: InputEventType::Abs as u16,
                code: ABS_MT_POSITION_Y,
                value: y,
            });
        }

        if ev_type == EventType::TouchBegin {
            self.queue.push(InputEvent {
                type_: InputEventType::Key as u16,
                code: BTN_TOUCH,
                value: 1,
            });
            self.sync();
        } else if ev_type == EventType::TouchEnd {
            self.queue.push(InputEvent {
                type_: InputEventType::Key as u16,
                code: BTN_TOUCH,
                value: 0,
            });
            self.sync();
            self.clear_finger_positions();
        }
    }

    fn track_finger(&mut self, seq: EventSequence) -> u16 {
        if let Some(i) = self.fingers.iter().position(|s| s.seq == seq) {
            return i as u16;
        }

        self.fingers.push(FingerState {
            seq,
            current_position: None,
        });
        (self.fingers.len() - 1) as u16
    }
}

struct ScanoutWindow {
    window: ApplicationWindow,
    width: i32,
    height: i32,
    format: MemoryFormat,
    scanout_paintable: ScanoutPaintable,
}

impl ScanoutWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app: &Application,
        title: &str,
        display_width: i32,
        display_height: i32,
        width: i32,
        height: i32,
        format: MemoryFormat,
        keyboard_forwarder: Option<EventSender>,
        mouse_forwarder: Option<EventSender>,
        touch_forwarder: Option<EventSender>,
    ) -> Self {
        let header_bar = HeaderBar::new();
        let window = ApplicationWindow::builder()
            .application(app)
            .title(title)
            .titlebar(&header_bar)
            .build();

        window.connect_close_request(|window| {
            let dialog = AlertDialog::builder()
                .buttons(["Kill VM", "Only close the window", "Cancel"].as_ref())
                .default_button(0)
                .cancel_button(2)
                .modal(true)
                .message("Do you want kill the VM?")
                .detail("WARNING: Killing the VM may lead to loss of data or corruption of the VM image.\n\n\
                If you only close the window the VM will keep running and rendering the display in the background.")
                .build();
            dialog.choose(Some(window), None::<&Cancellable>, glib::clone!(
                #[strong]
                window,
                move |b| match b {
                    Ok(0) => {
                        // SAFETY: Safe because we are terminating the process anyway.
                        // Currently, libkrun also uses _exit on normal VM exit, so we mimic that
                        // behavior here.
                        unsafe { libc::_exit(125) }
                    }
                    Ok(1) => {
                        window.set_visible(false);
                    },
                    Ok(2) => (),
                    Ok(_) => unreachable!("Unknown action"),
                    Err(e) => panic!("Failed to select option: {e}"),
                }
            ));
            Propagation::Stop
        });

        window.add_action_entries([
            ActionEntry::builder("fullscreen")
                .activate(move |window: &ApplicationWindow, _, _| window.fullscreen())
                .build(),
            ActionEntry::builder("unfullscreen")
                .activate(move |window: &ApplicationWindow, _, _| window.unfullscreen())
                .build(),
        ]);

        let fullscreen_btn = Button::builder()
            .icon_name("view-fullscreen")
            .tooltip_text("Enter fullscreen mode")
            .action_name("win.fullscreen")
            .build();

        let scanout_paintable = ScanoutPaintable::new(display_width, display_height);
        let picture = Picture::for_paintable(&scanout_paintable);

        window.set_titlebar(Some(&header_bar));
        header_bar.pack_end(&fullscreen_btn);

        let overlay = build_overlay(
            window.as_ref(),
            keyboard_forwarder,
            mouse_forwarder,
            touch_forwarder,
        );
        overlay.set_child(Some(&picture));
        window.set_child(Some(&overlay));
        window.set_visible(true);

        Self {
            window,
            width,
            height,
            format,
            scanout_paintable,
        }
    }

    pub fn reconfigure(&mut self, width: i32, height: i32, format: gdk::MemoryFormat) {
        self.width = width;
        self.height = height;
        self.format = format;
    }

    pub fn update(&self, buffer: Bytes, rect: Option<Rect>) {
        self.scanout_paintable
            .update(buffer, self.width, self.height, self.format, rect);
    }
}

impl Drop for ScanoutWindow {
    fn drop(&mut self) {
        self.window.destroy();
    }
}

fn build_overlay(
    window: &Window,
    keyboard_event_tx: Option<EventSender>,
    mouse_event_tx: Option<EventSender>,
    touch_event_tx: Option<EventSender>,
) -> Overlay {
    let overlay_bar = HeaderBar::builder()
        .valign(Align::Start)
        .hexpand_set(false)
        .hexpand(false)
        .opacity(0.8)
        .build();

    let overlay = Overlay::new();
    let revealer = Revealer::builder()
        .transition_type(RevealerTransitionType::SwingDown)
        .transition_duration(300)
        .reveal_child(false)
        .build();
    revealer.set_child(Some(&overlay_bar));
    overlay.add_overlay(&revealer);

    let overlay_unfullscreen_btn = Button::builder()
        .tooltip_text("Exit fullscreen mode")
        .icon_name("view-restore")
        .action_name("win.unfullscreen")
        .build();

    let bar_controller = EventControllerMotion::new();
    bar_controller.connect_leave(glib::clone!(
        #[weak]
        revealer,
        move |_| {
            revealer.set_reveal_child(false);
        }
    ));
    overlay_bar.add_controller(bar_controller);

    // Set up keyboard event forwarding to keyboard input backend
    if let Some(keyboard_tx) = keyboard_event_tx {
        let key_controller = EventControllerKey::new();

        // Handle key press events
        let forwarder_press = keyboard_tx.clone();
        let pressed_keys = Rc::new(RefCell::new(HashSet::new()));
        let pressed_keys_clone = pressed_keys.clone();
        key_controller.connect_key_pressed(move |_controller, key, keycode, _modifiers| {
            let linux_keycode = gtk_keycode_to_linux(keycode);
            if linux_keycode == 0 {
                debug!("Unknown key GTK key={}, code={}", key, keycode);
                return Propagation::Proceed;
            } else {
                debug!(
                    "Forwarding key press: GTK key={}, code={}, Linux code={}",
                    key, keycode, linux_keycode
                );
            }
            let is_first_keypress = pressed_keys_clone.borrow_mut().insert(linux_keycode);
            let input_event = InputEvent {
                type_: InputEventType::Key as u16,
                code: linux_keycode,
                value: if is_first_keypress { 1 } else { 2 },
            };
            forwarder_press.send(input_event).unwrap();
            let syn = InputEvent {
                type_: InputEventType::Syn as u16,
                code: 0,
                value: 0,
            };
            forwarder_press.send(syn).unwrap();
            Propagation::Proceed
        });

        // Handle key release events
        let forwarder_release = keyboard_tx.clone();
        key_controller.connect_key_released(move |_controller, key, keycode, _modifiers| {
            let linux_keycode = gtk_keycode_to_linux(keycode);
            let input_event = InputEvent {
                type_: InputEventType::Key as u16,
                code: linux_keycode,
                value: 0, // Key release
            };
            debug!(
                "Forwarding key release: GTK key={}, code={}, Linux code={}",
                key, keycode, linux_keycode
            );
            pressed_keys.borrow_mut().remove(&linux_keycode);

            forwarder_release.send(input_event).unwrap();
            let syn = InputEvent {
                type_: InputEventType::Syn as u16,
                code: 0,
                value: 0,
            };
            forwarder_release.send(syn).unwrap();
            debug!("sent!");
        });
        window.add_controller(key_controller);
    }

    if let Some(touch_event_tx) = touch_event_tx {
        let input_controller = EventControllerLegacy::new();
        let mut touch_sender = Rc::new(RefCell::new(TouchSequencedSender::new(touch_event_tx)));
        let touch_sender_for_sync = touch_sender.clone();
        input_controller.connect_event(move |_, event| {
            if let Some(touch) = event.downcast_ref::<gdk::TouchEvent>() {
                let seq_id = touch_sender.borrow_mut().push_event(touch);
            }
            glib::Propagation::Proceed
        });
        //TODO: conditionally enable this timer only if we have a pending event?
        let timer = timeout_add_local(Duration::from_millis(8), move || {
            touch_sender_for_sync.borrow_mut().sync();
            ControlFlow::Continue
        });
        // TODO call upon syncing
        //timer.remove()

        overlay.add_controller(input_controller);
    }

    let overlay_controller = EventControllerMotion::new();
    overlay_controller.connect_motion(glib::clone!(
        #[weak]
        revealer,
        #[weak]
        window,
        move |_motion, _x, y| {
            if window.is_fullscreen() && y < 1.0 {
                revealer.set_reveal_child(true);
            }
        }
    ));
    overlay.add_controller(overlay_controller);

    overlay_bar.pack_end(&overlay_unfullscreen_btn);
    overlay_bar.set_show_title_buttons(false);

    overlay
}

pub struct DisplayWorker {
    app: Application,
    app_name: String,
    rx: PollableChannelReciever<DisplayEvent>,
    keyboard_event_tx: Option<EventSender>,
    mouse_event_tx: Option<EventSender>,
    touch_event_tx: Option<EventSender>,
    scanouts: RefCell<[Option<ScanoutWindow>; MAX_DISPLAYS]>,
}

impl DisplayWorker {
    pub fn new(
        app: Application,
        app_name: String,
        rx: PollableChannelReciever<DisplayEvent>,
        keyboard_event_tx: Option<EventSender>,
        mouse_event_tx: Option<EventSender>,
        touch_event_tx: Option<EventSender>,
    ) -> Self {
        Self {
            app,
            app_name,
            rx,
            keyboard_event_tx,
            mouse_event_tx,
            touch_event_tx,
            scanouts: Default::default(),
        }
    }

    fn handle_event(&self) {
        let mut scanouts = self.scanouts.borrow_mut();
        while let Some(msg) = self.rx.try_recv().unwrap() {
            match msg {
                DisplayEvent::ConfigureScanout {
                    scanout_id,
                    display_width,
                    display_height,
                    width,
                    height,
                    format,
                } => {
                    if let Some(ref mut scanout) = scanouts[scanout_id as usize] {
                        trace!(
                            "Update params of scanout {scanout_id}: width={width} height={height} format={format:?}"
                        );
                        scanout.reconfigure(width as i32, height as i32, format);
                    } else {
                        debug!(
                            "Enable scanout {scanout_id} width={width} height={height} format={format:?}"
                        );
                        scanouts[scanout_id as usize] = Some(ScanoutWindow::new(
                            &self.app,
                            &format!(
                                "{name} - display {scanout_id} ({width}x{height})",
                                name = self.app_name
                            ),
                            display_width as i32,
                            display_height as i32,
                            width as i32,
                            height as i32,
                            format,
                            self.keyboard_event_tx.clone(),
                            self.mouse_event_tx.clone(),
                            self.touch_event_tx.clone(),
                        ));
                    }
                }
                DisplayEvent::DisableScanout { scanout_id } => {
                    debug!("Disable scanout {scanout_id}");
                    scanouts[scanout_id as usize] = None;
                }
                DisplayEvent::UpdateScanout {
                    scanout_id,
                    buffer,
                    rect,
                } => {
                    if let Some(scanout) = &mut scanouts[scanout_id as usize] {
                        trace!("Update scanout {scanout_id}");
                        scanout.update(buffer, rect);
                    } else {
                        warn!("Attempted to update non-existent scanout: {scanout_id}");
                    }
                }
            }
        }
    }

    /// Run a GTK application in the current thread handling the krun_gtk_display events send over the channel.
    /// The events are produces by the `DisplayBackend` which is hooked up into libkrun.
    pub fn run(
        app_name: String,
        rx: PollableChannelReciever<DisplayEvent>,
        keyboard_tx: Option<EventSender>,
        mouse_tx: Option<EventSender>,
        touch_tx: Option<EventSender>,
    ) {
        let app = Application::builder().build();

        // Hold the application so it doesn't close when we don't have any windows open. We hold the
        // app forever, because currently libkrun just exits the process on VM shutdown so there is
        // no way for us to do anything better here for now.
        let _app_hold = app.hold();
        let rx_fd = rx.as_raw_fd();

        let display_worker = Rc::new(DisplayWorker::new(
            app.clone(),
            app_name,
            rx,
            keyboard_tx,
            mouse_tx,
            touch_tx,
        ));
        app.connect_activate(move |_app| {
            let display_worker = display_worker.clone();
            unix_fd_add_local(rx_fd, IOCondition::IN, move |_, _| {
                display_worker.handle_event();
                ControlFlow::Continue
            });
        });
        app.run_with_args::<&str>(&[]);
    }
}
