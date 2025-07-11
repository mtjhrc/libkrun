mod imp;

use gtk4::gdk::{MemoryFormat, MemoryTextureBuilder};
use gtk4::glib::Bytes;
use gtk4::prelude::{ObjectExt, PaintableExt, TextureExt};
use gtk4::subclass::prelude::ObjectSubclassIsExt;
use gtk4::{cairo, gdk, glib};
use std::ops::Deref;
use gtk4::cairo::RectangleInt;

glib::wrapper! {
    pub struct ScanoutPaintable(ObjectSubclass<imp::ScanoutPaintable>) @implements gdk::Paintable;
}

impl ScanoutPaintable {
    pub fn new(default_width: i32, default_height: i32) -> Self {
        let self_: Self = glib::Object::new();
        self_.init(default_width, default_height);
        self_
    }

    fn init(&self, default_width: i32, default_height: i32) {
        self.imp().default_width.replace(default_width);
        self.imp().default_height.replace(default_height);
    }

    pub fn update(&mut self, data: Vec<u8>, width: i32, height: i32, format: MemoryFormat) {
        assert_eq!(data.len(), width as usize * height as usize * 4);
        let imp = self.imp();
        let bytes = Bytes::from_owned(data);
        let builder = MemoryTextureBuilder::new();
        builder.set_width(width);
        builder.set_height(height);
        builder.set_format(format);
        builder.set_stride(width as usize * 4);
        //builder.set_update_region(Some(&cairo::Region::create_rectangle(&RectangleInt::new(0, 0, width, height))));
        //builder.set_update_texture(imp.texture.borrow().as_ref());
        builder.set_bytes(Some(&bytes));

        let old_texture = imp.texture.replace(Some(builder.build()));

        self.invalidate_contents();
        if let Some(old_texture) = old_texture {
            if old_texture.width() != width && old_texture.height() != height {
                self.invalidate_size();
            }
        }
    }
}
