use crate::virtio::gpu::display_event::ScanoutId;
use crate::virtio::gpu::display_event::{Dimensions, DisplayEvent, Rect, ScanoutUpdate};
use crate::virtio::gpu::protocol::{virtio_gpu_rect, VIRTIO_GPU_MAX_SCANOUTS};
use crossbeam_channel::Sender;
use imago::format::wrapped::WrappedFormat;
use libc::{_exit, c_int};
use nix::sys::signal::{kill, SIGINT};
use nix::unistd::getpid;
use sdl3::event::EventType::WindowCloseRequested;
use sdl3::event::WindowEvent::PixelSizeChanged;
use sdl3::event::{Event, EventSender, EventWatchCallback, WindowEvent};
use sdl3::pixels::{PixelFormat, PixelMasks};
use sdl3::render::Canvas;
use sdl3::surface::Surface;
use sdl3::sys::everything::{
    SDL_PixelFormat, SDL_SetTrayEntryChecked, SDL_SetTrayTooltip, SDL_TrayEntry,
    SDL_PIXELFORMAT_XRGB8888,
};
use sdl3::sys::pixels::{SDL_PIXELFORMAT_RGBA8888, SDL_PIXELFORMAT_RGBX8888};
use sdl3::sys::surface::{SDL_LoadBMP, SDL_Surface};
use sdl3::sys::tray::{
    SDL_CreateTray, SDL_CreateTrayMenu, SDL_DestroyTray, SDL_GetTrayEntryChecked,
    SDL_GetTrayEntryEnabled, SDL_GetTrayEntryLabel, SDL_InsertTrayEntryAt, SDL_RemoveTrayEntry,
    SDL_SetTrayEntryCallback, SDL_SetTrayEntryEnabled, SDL_SetTrayEntryLabel, SDL_Tray,
    SDL_TrayMenu, SDL_TRAYENTRY_BUTTON, SDL_TRAYENTRY_CHECKBOX,
};
use sdl3::video::Window;
use sdl3::Error as SdlError;
use sdl3::{EventPump, EventSubsystem, VideoSubsystem};
use std::ffi::{c_void, CStr, CString};
use std::ops::{Deref, DerefMut};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::thread::JoinHandle;

struct DisplayHandleInner {
    displays: Box<[DisplayInfo]>,
    event_sender: EventSender,
    thread: JoinHandle<()>,
}

#[derive(Clone)]
pub struct DisplayHandle(Arc<DisplayHandleInner>);

impl DisplayHandle {
    fn push_event(&self, event: DisplayEvent) {
        self.0.event_sender.push_custom_event(event).unwrap()
    }

    pub fn display_info(&self) -> &[DisplayInfo] {
        &self.0.displays
    }

    /// Enable the given scanout. The x/y of the rectangle specify the display placement relative
    /// to each other.
    pub fn enable_scanout(&self, scanout_id: ScanoutId, dimensions: Dimensions) {
        self.push_event(DisplayEvent::EnableScanout(scanout_id, dimensions));
    }

    pub fn disable_scanout(&self, scanout_id: ScanoutId) {
        self.push_event(DisplayEvent::DisableScanout(scanout_id));
    }

    // TODO: add format argument
    pub fn update_scanout(
        &self,
        scanout_id: ScanoutId,
        data: Vec<u8>,
        width: u32,
        height: u32,
        damage_area: Rect,
        pitch: u32,
    ) {
        let update = ScanoutUpdate {
            data,
            width,
            height,
            damage_area,
            pitch,
        };

        self.push_event(DisplayEvent::UpdateScanout(scanout_id, update));
    }
}

pub fn sdl_display_start(displays: Box<[DisplayInfo]>) -> DisplayHandle {
    let (tx, rx) = crossbeam_channel::bounded(1);

    let displays_clone = displays.clone();
    let thread = thread::spawn(move || {
        display_thread(displays_clone, tx);
    });
    let event_sender = rx.recv().expect("SDL display thread panicked");

    DisplayHandle(Arc::new(DisplayHandleInner {
        displays: displays,
        event_sender,
        thread,
    }))
}

type TrayCallback = Box<dyn FnMut(*mut SDL_TrayEntry)>;

struct Tray<'sdl_video> {
    sdl_video: &'sdl_video VideoSubsystem,
    // SAFETY: the pointers point to heap allocations by SDL, moving the struct is therefor safe
    tray: *mut SDL_Tray,
    tray_menu: *mut SDL_TrayMenu,
    entries: Vec<*mut SDL_TrayEntry>,
    // pointers  (allocated using Box::new) to TrayCallback
    callback_clousures: Vec<*mut c_void>,
}

extern "C" fn forward_callback(userdata: *mut c_void, entry: *mut SDL_TrayEntry) {
    let mut callback = unsafe { userdata as *mut TrayCallback };
    let Some(callback) = (unsafe { callback.as_mut() }) else {
        panic!("Invalid callback ptr");
    };
    callback(entry);
}

impl Tray<'_> {
    pub fn new<'sdl_video>(
        sdl_video: &'sdl_video VideoSubsystem,
        name: &CStr,
        icon: *mut SDL_Surface,
    ) -> Result<Tray<'sdl_video>, SdlError> {
        unsafe {
            let tray = SDL_CreateTray(icon, name.as_ptr());
            if tray.is_null() {
                return Err(sdl3::get_error());
            }

            let tray_menu = SDL_CreateTrayMenu(tray);
            if tray_menu.is_null() {
                return Err(sdl3::get_error());
            }

            SDL_SetTrayTooltip(tray, c"libkrun displays".as_ptr());

            Ok(Tray {
                sdl_video,
                tray,
                tray_menu,
                entries: Vec::new(),
                callback_clousures: Vec::new(),
            })
        }
    }

    fn workaround_reset_checkbox(&mut self, index: usize) {
        let old_entry = self.entries[index];
        let label = unsafe { CStr::from_ptr(SDL_GetTrayEntryLabel(old_entry)).to_owned() };

        let checked: bool = unsafe { SDL_GetTrayEntryChecked(old_entry) };

        unsafe {
            SDL_RemoveTrayEntry(old_entry);
        }

        let entry = unsafe {
            SDL_InsertTrayEntryAt(
                self.tray_menu,
                index as c_int,
                label.as_ptr(),
                SDL_TRAYENTRY_CHECKBOX,
            )
        };

        self.entries[index] = entry;
        unsafe {
            SDL_SetTrayEntryCallback(
                entry,
                Some(forward_callback),
                self.callback_clousures[index],
            );
        }
        self.set_checked(index, checked);
    }

    pub fn push_checkbox(&mut self, label: &CStr, callback: TrayCallback) -> Result<(), SdlError> {
        unsafe {
            let entry =
                SDL_InsertTrayEntryAt(self.tray_menu, -1, label.as_ptr(), SDL_TRAYENTRY_CHECKBOX);

            if entry.is_null() {
                return Err(sdl3::get_error());
            }
            self.entries.push(entry);

            let boxed_clousure = Box::new(callback);
            let boxed_clousure_ptr = Box::into_raw(boxed_clousure) as *mut c_void;
            self.callback_clousures.push(boxed_clousure_ptr);
            SDL_SetTrayEntryCallback(entry, Some(forward_callback), boxed_clousure_ptr);
        }
        Ok(())
    }

    pub fn push_tray_separator(&mut self) -> Result<(), SdlError> {
        unsafe {
            let entry = SDL_InsertTrayEntryAt(self.tray_menu, -1, null(), 0);
            if entry.is_null() {
                return Err(sdl3::get_error());
            }
            self.entries.push(entry);
        }
        Ok(())
    }

    pub fn set_checked(&self, index: usize, checked: bool) {
        unsafe {
            SDL_SetTrayEntryChecked(self.entries[index], checked);
        };
    }

    pub fn set_enabled(&mut self, index: usize, enabled: bool) {
        if !enabled {
            unsafe {
                SDL_SetTrayEntryEnabled(self.entries[index], false);
            }
        } else {
            // For some reason re-enabling the checkbox doesn't work, so just recreate it
            self.workaround_reset_checkbox(index);
        }
    }
}

impl Drop for Tray<'_> {
    fn drop(&mut self) {
        unsafe {
            for c in self.callback_clousures.iter() {
                drop(Box::from_raw(*c))
            }

            SDL_DestroyTray(self.tray);
        }
    }
}

fn construct_tray<'sdl>(
    video_sys: &'sdl VideoSubsystem,
    event_sys: &'sdl EventSubsystem,
    displays: &[DisplayInfo],
) -> Tray<'sdl> {
    let icon = unsafe { SDL_LoadBMP(c"/home/mhrica/krun.bmp".as_ptr()) };

    if icon.is_null() {
        panic!("Failed to load icon: {}", sdl3::get_error());
    }

    let mut tray = Tray::new(&video_sys, c"krun", icon).unwrap();

    for (i, display) in displays.iter().enumerate() {
        let label = format!("[{i}]: {}x{}px", display.width(), display.height());
        let sender = event_sys.event_sender();
        tray.push_checkbox(
            &CString::new(label).unwrap(),
            Box::new(move |entry| {
                debug!("Clicked");
                sender
                    .push_custom_event(DisplayEvent::ShowWindow(i))
                    .unwrap()
            }),
        )
        .unwrap();
        tray.set_enabled(i, false);
    }

    tray.push_tray_separator();
    tray.push_checkbox(c"Kill vmm", Box::new(|try_item| unsafe { _exit(0) }))
        .expect("TODO: panic message");
    tray
}

fn display_thread(displays: Box<[DisplayInfo]>, tx: Sender<EventSender>) {
    let sdl = sdl3::init().unwrap();
    let video_sys = sdl.video().unwrap();
    let event_sys = sdl.event().unwrap();
    event_sys.register_custom_event::<DisplayEvent>().unwrap();

    let mut event_pump = sdl.event_pump().unwrap();
    tx.send(event_sys.event_sender()).unwrap();
    drop(tx);

    let mut windows: [Option<Window>; VIRTIO_GPU_MAX_SCANOUTS as usize] =
        [const { None }; VIRTIO_GPU_MAX_SCANOUTS as usize];

    let mut tray = construct_tray(&video_sys, &event_sys, &displays);

    loop {
        while let Some(event) = Some(event_pump.wait_event()) {
            trace!("sdl event loop iteration");
            if let Some(mut display_event) = event.as_user_event_type::<DisplayEvent>() {
                match display_event {
                    DisplayEvent::EnableScanout(scanout_id, dimensions) => {
                        debug!("Enable scanout {scanout_id}");
                        let window_ref = &mut windows[scanout_id.as_index()];

                        if window_ref.is_none() {
                            let mut new_window = video_sys
                                .window(
                                    &format!(
                                        "libkrun scanout {} ({}x{}px)",
                                        scanout_id.0, dimensions.width, dimensions.height
                                    ),
                                    dimensions.width,
                                    dimensions.height,
                                )
                                .build()
                                .unwrap();
                            new_window.show();
                            *window_ref = Some(new_window);
                            tray.set_checked(scanout_id.0 as usize, true);
                            tray.set_enabled(scanout_id.0 as usize, true);
                        }
                    }
                    DisplayEvent::DisableScanout(scanout_id) => {
                        debug!("Disable scanout {scanout_id}");
                        windows[scanout_id.as_index()] = None;
                        tray.set_checked(scanout_id.0 as usize, false);
                        tray.set_enabled(scanout_id.0 as usize, false);
                    }
                    DisplayEvent::UpdateScanout(scanout_id, mut update) => {
                        debug!("Update scanout {scanout_id}");
                        // TODO: unhardcode
                        let format = unsafe { PixelFormat::from_ll(SDL_PIXELFORMAT_XRGB8888) };

                        let src_surface = Surface::from_data(
                            update.data.as_mut_slice(),
                            update.width,
                            update.height,
                            update.pitch,
                            format,
                        )
                        .unwrap();

                        let window: &mut Window = windows
                            .get_mut(scanout_id.as_index())
                            .unwrap()
                            .as_mut()
                            .unwrap();

                        let mut window_surface = window.surface(&event_pump).unwrap();

                        let damage_area = update.damage_area.try_into().unwrap();
                        src_surface
                            .blit::<sdl3::rect::Rect, sdl3::rect::Rect>(
                                damage_area,
                                window_surface.deref_mut(),
                                damage_area,
                            )
                            .unwrap();
                        window_surface.update_window_rects(&[damage_area]).unwrap();
                    }
                    DisplayEvent::ShowWindow(window_index) => {
                        if let Some(window) = &mut windows[window_index] {
                            window.show();
                            window.raise();
                            tray.set_checked(window_index, true);
                        }
                    }
                }
            }

            match event {
                Event::Window {
                    win_event: WindowEvent::CloseRequested,
                    window_id,
                    ..
                } => {
                    for (index, window) in windows.iter_mut().enumerate() {
                        if let Some(window) = window
                            .as_mut()
                            .and_then(|w| (w.id() == window_id).then_some(w))
                        {
                            window.hide();
                            tray.set_checked(index, false);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DisplayInfo {
    width: u32,
    height: u32,
}
impl DisplayInfo {
    pub fn new(width: u32, height: u32) -> Self {
        DisplayInfo { width, height }
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }
}
