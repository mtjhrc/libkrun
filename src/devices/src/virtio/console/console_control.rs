use crate::virtio::console::defs::control_event::{
    VIRTIO_CONSOLE_CONSOLE_PORT, VIRTIO_CONSOLE_PORT_ADD, VIRTIO_CONSOLE_PORT_NAME,
    VIRTIO_CONSOLE_PORT_OPEN, VIRTIO_CONSOLE_RESIZE,
};
use crate::virtio::Queue as VirtQueue;
use libc::EFD_NONBLOCK;
use std::collections::VecDeque;
use std::mem::size_of;
use std::ops::Deref;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use utils::eventfd::EventFd;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap};

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed(4))]
pub struct VirtioConsoleControl {
    /// Port number
    pub id: u32,
    /// The kind of control event
    pub event: u16,
    /// Extra information for the event
    pub value: u16,
}

// Safe because it only has data and has no implicit padding.
// But NOTE that this relies on CPU being little endian, to have correct semantics
unsafe impl ByteValued for VirtioConsoleControl {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioConsoleResize {
    // The order of these fields in the kernel and in the spec do not match
    pub rows: u16,
    pub cols: u16,
}

// Safe because it only has data and has no implicit padding.
// but NOTE, that we rely on CPU being little endian, for the values to be correct
unsafe impl ByteValued for VirtioConsoleResize {}

pub enum Msg {
    FixedLen(VirtioConsoleControl),
    DynamicLen(Vec<u8>),
}

impl Deref for Msg {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &match self {
            Msg::FixedLen(b) => b.as_slice(),
            Msg::DynamicLen(b) => b.as_slice(),
        }
    }
}

// Utility for sending commands into control rx queue
pub struct ConsoleControl {
    queue: Mutex<VecDeque<Msg>>,
    queue_evt: EventFd,
}

impl ConsoleControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            queue: Default::default(),
            queue_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
        })
    }

    pub fn send_mark_console_port(&self, mem: &GuestMemoryMmap, port_id: u32) {
        self.send_msg(VirtioConsoleControl {
            id: port_id,
            event: VIRTIO_CONSOLE_CONSOLE_PORT,
            value: 1,
        })
    }

    pub fn resize_console(&self, port_id: u32, new_size: &VirtioConsoleResize) {
        let mut buf = Vec::new();
        buf.extend(
            VirtioConsoleControl {
                id: port_id,
                event: VIRTIO_CONSOLE_RESIZE,
                value: 0,
            }
            .as_slice(),
        );
        buf.extend(new_size.as_slice());
        self.send_vec(buf)
    }

    /// Adds another port with the specified port_id
    pub fn add_port(&self, port_id: u32) {
        self.send_msg(VirtioConsoleControl {
            id: port_id,
            event: VIRTIO_CONSOLE_PORT_ADD,
            value: 0,
        })
    }

    pub fn set_port_open(&self, port_id: u32, open: bool) {
        self.send_msg(VirtioConsoleControl {
            id: port_id,
            event: VIRTIO_CONSOLE_PORT_OPEN,
            value: open as u16,
        })
    }

    pub fn set_port_name(&self, port_id: u32, name: &str) {
        let mut buf: Vec<u8> = Vec::new();

        buf.extend_from_slice(
            VirtioConsoleControl {
                id: port_id,
                event: VIRTIO_CONSOLE_PORT_NAME,
                value: 1, // Unspecified/unused in the spec, lets use the same value as QEMU.
            }
            .as_slice(),
        );

        // The spec says the name shouldn't be NUL terminated.
        buf.extend(name.as_bytes());
        self.send_vec(buf)
    }

    pub fn queue_pop(&self) -> Option<Msg> {
        let mut queue = self.queue.lock().expect("Poisoned lock");
        queue.pop_front()
    }

    pub fn queue_evt(&self) -> &EventFd {
        &self.queue_evt
    }

    fn send_msg(&self, msg: VirtioConsoleControl) {
        let mut queue = self.queue.lock().expect("Poisoned lock");
        queue.push_back(Msg::FixedLen(msg));
        if let Err(e) = self.queue_evt.write(1) {
            log::trace!("ConsoleControl failed to write to notify {e}")
        }
    }

    fn send_vec(&self, buf: Vec<u8>) {
        let mut queue = self.queue.lock().expect("Poisoned lock");
        queue.push_back(Msg::DynamicLen(buf));
        if let Err(e) = self.queue_evt.write(1) {
            log::trace!("ConsoleControl failed to write to notify {e}")
        }
    }
}
