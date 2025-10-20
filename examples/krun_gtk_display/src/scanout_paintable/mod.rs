mod imp;

use gtk::{
    cairo::{RectangleInt, Region},
    gdk::{self, MemoryFormat, MemoryTextureBuilder},
    glib,
    glib::Bytes,
    prelude::*,
    subclass::prelude::*,
};
use krun_display::{Rect, ResourceFormat};

glib::wrapper! {
    pub struct ScanoutPaintable(ObjectSubclass<imp::ScanoutPaintable>) @implements gdk::Paintable;
}

impl ScanoutPaintable {
    pub fn new(default_width: i32, default_height: i32) -> Self {
        glib::Object::builder()
            .property("default-width", default_width)
            .property("default-height", default_height)
            .build()
    }

    pub fn update(
        &self,
        buffer: Bytes,
        width: i32,
        height: i32,
        format: MemoryFormat,
        rect: Option<Rect>,
    ) {
        assert_eq!(buffer.len(), width as usize * height as usize * 4);
        let imp = self.imp();
        let builder = MemoryTextureBuilder::new()
            .set_width(width)
            .set_height(height)
            .set_format(format)
            .set_stride(width as usize * ResourceFormat::BYTES_PER_PIXEL)
            .set_bytes(Some(&buffer));

        let builder = if let Some(rect) = rect {
            builder
                .set_update_region(Some(&Region::create_rectangle(&RectangleInt::new(
                    rect.x as i32,
                    rect.y as i32,
                    rect.width as i32,
                    rect.height as i32,
                ))))
                .set_update_texture(imp.texture.borrow().as_ref())
        } else {
            builder
        };

        let old_texture = imp.texture.replace(Some(builder.build()));

        self.invalidate_contents();
        if let Some(old_texture) = old_texture
            && old_texture.width() != width
            && old_texture.height() != height
        {
            self.invalidate_size();
        }
    }

    pub fn set_texture(
        &self,
        display_width: i32,
        display_height: i32,
        texture: gdk::Texture,
    ) {
        let imp = self.imp();
        imp.display_width.set(display_width);
        imp.display_height.set(display_height);

        let old_texture = imp.texture.replace(Some(texture.clone()));
        self.invalidate_contents();
        
        if let Some(old_texture) = old_texture {
            let new_size = (texture.width(), texture.height());
            let old_size = (old_texture.width(), old_texture.height());
            if new_size != old_size {
                self.invalidate_size();
            }
        } else {
            self.invalidate_size();
        }
    }
}
