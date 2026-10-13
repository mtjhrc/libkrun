use log::{debug, error};
use std::io;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::thread::{self, JoinHandle};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use virtio_bindings::virtio_input;
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::DeviceQueue;
use crate::virtio::InterruptTransport;
use crate::virtio::descriptor_utils::{Reader, Writer};
use krun_input::InputEventsImpl;

// Create a wrapper type to work around orphan rules
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct VirtioInputEvent {
    type_: u16,
    code: u16,
    value: i32,
}

unsafe impl ByteValued for VirtioInputEvent {}

pub struct InputWorker {
    event_q: DeviceQueue,  // Device -> Guest events
    status_q: DeviceQueue, // Guest -> Device events
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    backend: Box<dyn InputEventsImpl>,
    stop_fd: EventFd,
}

impl InputWorker {
    pub fn new(
        event_q: DeviceQueue,
        status_q: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        backend: Box<dyn InputEventsImpl>,
        stop_fd: EventFd,
    ) -> Self {
        Self {
            event_q,
            status_q,
            interrupt,
            mem,
            backend,
            stop_fd,
        }
    }

    pub fn run(self) -> JoinHandle<Box<dyn InputEventsImpl>> {
        thread::Builder::new()
            .name("input worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) -> Box<dyn InputEventsImpl> {
        self.work_events();
        self.backend
    }

    fn work_events(&mut self) {
        debug!("input worker: starting");

        const EVENTQ: u64 = 1;
        const STATUSQ: u64 = 2;
        const EVENTQ_USER: u64 = 3;
        const QUIT: u64 = 4;
        // Set up epoll to wait for events
        let mut epoll = match Epoll::new() {
            Ok(epoll) => epoll,
            Err(e) => {
                error!("Failed to create input epoll: {e}");
                return;
            }
        };

        let ready_fd = match self.backend.get_read_notify_fd() {
            Ok(fd) => fd.as_raw_fd(),
            Err(e) => {
                error!("Failed to get ready fd: {:?}", e);
                return;
            }
        };

        for (fd, token) in [
            (ready_fd, EVENTQ_USER),
            (self.event_q.event.as_raw_fd(), EVENTQ),
            (self.status_q.event.as_raw_fd(), STATUSQ),
            (self.stop_fd.as_raw_fd(), QUIT),
        ] {
            if let Err(e) = epoll.ctl(
                ControlOperation::Add,
                fd,
                &EpollEvent::new(EventSet::IN, token),
            ) {
                error!("Failed to add input fd to epoll: {e}");
                return;
            }
        }

        let mut events = vec![EpollEvent::default(); 16];

        'event_loop: loop {
            let num_events = match epoll.wait(events.len(), 1000, &mut events) {
                Ok(n) => n,
                Err(e) => {
                    error!("Epoll wait failed: {:?}", e);
                    break;
                }
            };

            let mut needs_interrupt = false;

            for event in &events[..num_events] {
                match event.data() {
                    EVENTQ_USER => {
                        trace!("EVENTQ_USER");
                        needs_interrupt |= self.process_event_queue();
                    }
                    EVENTQ => {
                        self.event_q.event.read().unwrap();
                        trace!("EVENTQ");
                        needs_interrupt |= self.process_event_queue();
                    }
                    STATUSQ => {
                        self.status_q.event.read().unwrap();
                        needs_interrupt |= self.process_status_queue();
                    }
                    QUIT => {
                        // Stop signal received
                        let _ = self.stop_fd.read();
                        break 'event_loop;
                    }
                    x => {
                        error!("TODO: {x}")
                    }
                }
                if needs_interrupt {
                    self.interrupt.signal_used_queue();
                }
            }
        }

        debug!("input worker: stopping");
    }

    /// Fills a virtqueue with events from the source. Returns the number of bytes written.
    fn fill_event_virtqueue(&mut self, writer: &mut Writer) -> Result<(usize, bool), ()> {
        let avail_bytes = writer.available_bytes();
        let mut eof = false;
        while writer.bytes_written() + size_of::<VirtioInputEvent>() <= avail_bytes {
            match self.backend.next_event() {
                Ok(Some(event)) => {
                    let virtio_event = VirtioInputEvent {
                        type_: event.type_,
                        code: event.code,
                        value: event.value,
                    };
                    debug!("Writing: {virtio_event:?}");
                    writer
                        .write_obj(virtio_event)
                        .expect("Failed to write input event to virtqueue");
                }
                // No more events available
                Ok(None) => {
                    eof = true;
                    break;
                }
                Err(e) => {
                    error!("Error getting next event: {:?}", e);
                    eof = true;
                    break;
                }
            }
        }
        Ok((writer.bytes_written(), eof))
    }

    fn process_event_queue(&mut self) -> bool {
        let mut needs_interrupt = false;
        let mem = self.mem.clone();

        while let Some(desc_chain) = self.event_q.queue.pop(&mem) {
            let mut writer = match Writer::new(&mem, desc_chain.clone()) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create writer: {:?}", e);
                    break;
                }
            };

            let (bytes_written, eof) = self.fill_event_virtqueue(&mut writer).unwrap();

            if bytes_written != 0 {
                self.event_q
                    .queue
                    .add_used(&mem, desc_chain.index, bytes_written as u32)
                    .expect("TODO");
                needs_interrupt = true;
            }

            if bytes_written == 0 {
                self.event_q.queue.undo_pop();
                break;
            }

            if eof {
                break;
            }
        }
        needs_interrupt
    }

    /// Reads events from guest and sends them to the event source (currently no-op)
    fn read_status_virtqueue(&mut self, reader: &mut Reader) -> Result<usize, io::Error> {
        while reader.available_bytes() >= size_of::<VirtioInputEvent>() {
            let mut buffer: [u8; size_of::<virtio_input::virtio_input_event>()] =
                [0; size_of::<virtio_input::virtio_input_event>()];
            reader.read_exact(&mut buffer)?;
            debug!("Not implemented status queue request: {buffer:?}");
            // For now, we don't send events back to the input source
            // This would be used for things like setting LEDs on keyboards, haptic feedback, etc.
        }
        Ok(reader.bytes_read())
    }

    /// Process the status queue (guest -> device events)
    fn process_status_queue(&mut self) -> bool {
        let mut needs_interrupt = false;
        let mem = self.mem.clone();

        while let Some(desc_chain) = self.status_q.queue.pop(&mem) {
            let mut reader = match Reader::new(&mem, desc_chain.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("Failed to create reader for status queue: {e}");
                    return false;
                }
            };
            match self.read_status_virtqueue(&mut reader) {
                Ok(bytes_read) => {
                    self.status_q
                        .queue
                        .add_used(&mem, desc_chain.index, bytes_read as u32)
                        .unwrap();
                }
                Err(e) => {
                    error!("Input: failed to read events from virtqueue: {:?}", e);
                }
            }

            needs_interrupt = true;
        }

        needs_interrupt
    }
}
