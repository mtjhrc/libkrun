mod imp;

use gtk::{
    cairo::{RectangleInt, Region},
    gdk::{self, DmabufTextureBuilder, MemoryFormat, MemoryTextureBuilder},
    glib,
    glib::Bytes,
    prelude::*,
    subclass::prelude::*,
};
use krun_display::{DmabufInfo, Rect, ResourceFormat};
use log::error;

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

    pub fn configure_dmabuf(&self, dmabuf_info: &DmabufInfo) {
        let imp = self.imp();

        log::debug!(
            "Storing dmabuf info: width={}, height={}, fourcc=0x{:08x}, modifier=0x{:016x}, strides={:?}, offsets={:?}, fd={}",
            dmabuf_info.width,
            dmabuf_info.height,
            dmabuf_info.fourcc,
            dmabuf_info.modifier,
            dmabuf_info.strides,
            dmabuf_info.offsets,
            dmabuf_info.dmabuf_fd,
        );

        imp.dmabuf_info.replace(Some(*dmabuf_info));
    }

    pub fn update_dmabuf(&self, rect: Option<Rect>) {
        let imp = self.imp();

        let Some(dmabuf_info) = imp.dmabuf_info.borrow().as_ref().copied() else {
            error!("update_dmabuf called without prior configure_dmabuf");
            return;
        };

        log::trace!(
            "Building dmabuf texture from stored info: fd={}, fourcc=0x{:08x}, modifier=0x{:016x}",
            dmabuf_info.dmabuf_fd,
            dmabuf_info.fourcc,
            dmabuf_info.modifier
        );

        // FIXME: n_planes should be passed through DmabufInfo struct properly
        let n_planes = 1;

        // Duplicate the fd so we can close it independently
        let duped_fd = dmabuf_info.dmabuf_fd;
            ;/*unsafe { libc::dup(dmabuf_info.dmabuf_fd) };
        if duped_fd < 0 {
            error!(
                "Failed to dup dmabuf fd={}: errno={}",
                dmabuf_info.dmabuf_fd,
                std::io::Error::last_os_error()
            );
            return;
        }*/

        log::trace!(
            "Duplicated dmabuf fd {} -> {} for texture building",
            dmabuf_info.dmabuf_fd,
            duped_fd
        );

        let mut builder = DmabufTextureBuilder::new()
            .set_display(gdk::Display::default().as_ref().unwrap())
            .set_width(dmabuf_info.width)
            .set_height(dmabuf_info.height)
            .set_fourcc(dmabuf_info.fourcc)
            .set_modifier(dmabuf_info.modifier)
            .set_n_planes(n_planes);

        builder = if let Some(rect) = rect {
            builder
                .set_update_texture(imp.texture.borrow().as_ref())
                .set_update_region(Some(&Region::create_rectangle(&RectangleInt::new(
                    0 as i32,
                    0 as i32,
                    dmabuf_info.width as i32,
                    dmabuf_info.height as i32,
                ))))
        } else {
            todo!()
        };

        for (i, (&stride, &offset)) in dmabuf_info
            .strides
            .iter()
            .zip(dmabuf_info.offsets.iter())
            .enumerate()
            .take(n_planes as usize)
        {
            builder = builder
                .set_stride(i as u32, stride)
                .set_offset(i as u32, offset);
            unsafe {
                builder = builder.set_fd(i as u32, duped_fd);
            }
        }

        match unsafe {
            builder.build_with_release_func(move || {
                //libc::close(duped_fd);
                log::debug!(
                    "Closed duplicated dmabuf fd={} (texture destroyed)",
                    duped_fd
                );
            })
        } {
            Ok(texture) => {
                log::trace!(
                    "Successfully built dmabuf texture (fd={}, fourcc=0x{:08x}, modifier=0x{:016x})",
                    dmabuf_info.dmabuf_fd,
                    dmabuf_info.fourcc,
                    dmabuf_info.modifier
                );
                let old_texture = imp.texture.replace(Some(texture.upcast()));
                self.invalidate_contents();
                if let Some(old_texture) = old_texture {
                    let new_size = (dmabuf_info.width, dmabuf_info.height);
                    let old_size = (old_texture.width(), old_texture.height());
                    if new_size != (old_size.0 as u32, old_size.1 as u32) {
                        self.invalidate_size();
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to build dmabuf texture: {e} (fd={}, fourcc=0x{:08x}, modifier=0x{:016x})",
                    dmabuf_info.dmabuf_fd, dmabuf_info.fourcc, dmabuf_info.modifier
                );
                unsafe {
                    libc::close(duped_fd);
                }
                log::debug!(
                    "Closed duplicated dmabuf fd={} after build failure",
                    duped_fd
                );
            }
        }
    }
}
