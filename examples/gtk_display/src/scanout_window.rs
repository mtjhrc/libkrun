use crate::scanout_paintable::ScanoutPaintable;
use gtk4::gio::Cancellable;
use gtk4::glib::Propagation;
use gtk4::{
    AlertDialog, Align, ApplicationWindow, Button, EventControllerMotion, HeaderBar, Overlay,
    Picture, Revealer, RevealerTransitionType, Window, gdk,
    gio::{ActionEntry, SimpleActionGroup},
    glib,
    prelude::*,
};
use log::trace;

pub struct ScanoutWindow {
    window: ApplicationWindow,
    width: i32,
    height: i32,
    format: gdk::MemoryFormat,
    scanout_paintable: ScanoutPaintable,
}

impl ScanoutWindow {
    pub fn new(
        title: String,
        display_width: i32,
        display_height: i32,
        width: i32,
        height: i32,
        format: gdk::MemoryFormat,
    ) -> Self {
        let header_bar = HeaderBar::new();
        let window = ApplicationWindow::builder()
            .title(title)
            // Enforce a minimum window size:
            .height_request(64)
            .titlebar(&header_bar)
            .build();

        window.connect_close_request(|window| {
            let dialog = AlertDialog::builder()
                .buttons(["Kill VM", "Cancel"].as_ref())
                .default_button(0)
                .cancel_button(1)
                .modal(true)
                .message("Do you want to kill the VM?")
                .detail("WARNING: This may lead to loss of data or corruption of the VM image.")
                .build();
            dialog.choose(Some(window), None::<&Cancellable>, |b| {
                if b.is_ok_and(|b| b == 0) {
                    // SAFETY: Safe because we are terminating the process anyway.
                    // We also use _exit during normal VM exit, so we don't clean up
                    // ever anyway.
                    unsafe { libc::_exit(125) };
                }
            });
            Propagation::Stop
        });

        let actions = SimpleActionGroup::new();
        window.add_action_entries([
            ActionEntry::builder("fullscreen")
                .activate(glib::clone!(
                    #[weak]
                    window,
                    move |_, _, _| {
                        window.fullscreen();
                    }
                ))
                .build(),
            ActionEntry::builder("unfullscreen")
                .activate(glib::clone!(
                    #[weak]
                    window,
                    move |_, _, _| {
                        window.unfullscreen();
                    }
                ))
                .build(),
        ]);
        window.insert_action_group("scanout", Some(&actions));

        let fullscreen_btn = Button::builder()
            .icon_name("view-fullscreen")
            .tooltip_text("Enter fullscreen mode")
            .action_name("win.fullscreen")
            .build();

        let scanout_paintable = ScanoutPaintable::new(display_width, display_height);
        let picture = Picture::for_paintable(&scanout_paintable);

        window.set_titlebar(Some(&header_bar));
        header_bar.pack_end(&fullscreen_btn);

        let overlay = build_overlay(window.as_ref());
        overlay.set_child(Some(&picture));
        window.set_child(Some(&overlay));
        window.set_visible(true);
        trace!("Shown window");

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

    pub fn update(&mut self, data: Vec<u8>) {
        self.scanout_paintable
            .update(data, self.width, self.height, self.format);
    }
}

impl Drop for ScanoutWindow {
    fn drop(&mut self) {
        self.window.destroy();
    }
}

fn build_overlay(window: &Window) -> Overlay {
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
