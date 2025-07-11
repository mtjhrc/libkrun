use gtk4::gdk::ffi::gdk_paintable_invalidate_contents;
use gtk4::gdk::{MemoryTexture, Paintable, PaintableFlags, RGBA, Texture};
use gtk4::glib;
use gtk4::graphene::Rect;
use gtk4::prelude::{PaintableExt, SnapshotExt, TextureExt};
use gtk4::subclass::prelude::{ObjectImpl, ObjectSubclass, PaintableImpl};
use gtk4::{prelude::*, subclass::prelude::*};
use std::cell::{Cell, RefCell};
use log::{error, warn};

#[derive(Default)]
pub struct ScanoutPaintable {
    // Store the texture that this paintable will draw.
    pub texture: RefCell<Option<Texture>>,
    pub default_width: Cell<i32>,
    pub default_height: Cell<i32>,
    pub rect: Rect,
}

// Implement the GObjectSubclass trait for our MyPaintable struct.
#[glib::object_subclass]
impl ObjectSubclass for ScanoutPaintable {
    const NAME: &'static str = "ScanoutPaintable";
    type Type = super::ScanoutPaintable;
    type Interfaces = (Paintable,);
}

impl ObjectImpl for ScanoutPaintable {
    fn dispose(&self) {
        error!("ScanoutPaintable::dispose");
    }
}

impl PaintableImpl for ScanoutPaintable {
    fn snapshot(&self, snapshot: &gtk4::gdk::Snapshot, width: f64, height: f64) {
        if let Some(texture) = self.texture.borrow().as_ref() {
            snapshot.append_texture(texture, &Rect::new(0.0, 0.0, width as f32, height as f32));
        } else {
            snapshot.append_color(
                &RGBA::new(0.0, 0.0, 0.0, 1.0),
                &Rect::new(0.0, 0.0, width as f32, height as f32),
            );
        }
    }

    fn flags(&self) -> PaintableFlags {
        PaintableFlags::empty()
    }

    fn intrinsic_aspect_ratio(&self) -> f64 {
        if let Some(texture) = self.texture.borrow().as_ref() {
            texture.width() as f64 / texture.height() as f64
        } else {
            self.default_width.get() as f64 / self.default_height.get() as f64
        }
    }

    fn intrinsic_width(&self) -> i32 {
        self.texture
            .borrow()
            .as_ref()
            .map(|t| t.width())
            .unwrap_or(self.default_width.get())
    }

    fn intrinsic_height(&self) -> i32 {
        self.texture
            .borrow()
            .as_ref()
            .map(|t| t.height())
            .unwrap_or(self.default_height.get())
    }
}
