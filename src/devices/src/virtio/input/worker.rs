use log::{debug, error};
use std::os::fd::AsRawFd;
use std::thread::{self, JoinHandle};

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::Queue;
use crate::virtio::descriptor_utils::{Reader, Writer};
use crate::virtio::InterruptTransport;
use krun_input::{InputBackendWrapper, InputEventsInstance};

const EV_SYN: u8 = 0x00;
const EV_KEY: u8 = 0x01;
const EV_REL: u8 = 0x02;
const EV_ABS: u8 = 0x03;
const EV_MSC: u8 = 0x04;
const EV_SW: u8 = 0x05;

const SYN_REPORT: u8 = 0x00;

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
    event_queue: Queue,  // Device -> Guest events
    status_queue: Queue, // Guest -> Device events
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    backend_wrapper: InputBackendWrapper<'static>,
    stop_fd: EventFd,
    pub event_queue_efd: EventFd,
    pub status_queue_efd: EventFd,
}

impl InputWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_queue: Queue,
        event_queue_efd: EventFd,
        status_queue: Queue,
        status_queue_efd: EventFd,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        backend: InputBackendWrapper<'static>,
        stop_fd: EventFd,
    ) -> Self {
        Self {
            event_queue,
            event_queue_efd,
            status_queue,
            status_queue_efd,
            interrupt,
            mem,
            backend_wrapper: backend,
            stop_fd,
        }
    }

    pub fn run(self) -> JoinHandle<()> {
        thread::Builder::new()
            .name("input worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        debug!("input worker: starting");

        // Create the events instance in this thread
        let mut events_instance = match self.backend_wrapper.create_events_instance() {
            Ok(instance) => instance,
            Err(e) => {
                error!("Failed to create events instance: {:?}", e);
                return;
            }
        };

        // Set up epoll to wait for events
        let epoll = Epoll::new().expect("Failed to create epoll");

        let ready_fd = match events_instance.get_ready_efd() {
            Ok(fd) => fd,
            Err(e) => {
                error!("Failed to get ready fd: {:?}", e);
                return;
            }
        };

        epoll
            .ctl(
                ControlOperation::Add,
                ready_fd,
                &EpollEvent::new(EventSet::IN, 3),
            )
            .expect("Failed to add ready fd to epoll");

        epoll
            .ctl(
                ControlOperation::Add,
                ready_fd,
                &EpollEvent::new(EventSet::IN, 3),
            )
            .expect("Failed to add ready fd to epoll");

        epoll
            .ctl(
                ControlOperation::Add,
                self.stop_fd.as_raw_fd(),
                &EpollEvent::new(EventSet::IN, 4),
            )
            .expect("Failed to add stop fd to epoll");

        let mut events = vec![EpollEvent::default(); 2];

        'event_loop: loop {
            let num_events = match epoll.wait(events.len(), 1000, &mut events) {
                Ok(n) => n,
                Err(e) => {
                    error!("Epoll wait failed: {:?}", e);
                    break;
                }
            };

            let mut event_queue_needs_interrupt = false;

            for event in &events[..num_events] {
                match event.data() {
                    3 => {
                        // Input events available from backend
                        event_queue_needs_interrupt |= self.send_events(&mut events_instance);
                    }
                    4 => {
                        // Stop signal received
                        let _ = self.stop_fd.read();
                        break 'event_loop;
                    }
                    _ => {}
                }
            }

            if event_queue_needs_interrupt {
                self.interrupt.signal_used_queue();
            }
        }

        debug!("input worker: stopping");
    }

    /// Fills a virtqueue with events from the source. Returns the number of bytes written.
    fn fill_event_virtqueue(
        &mut self,
        events_instance: &mut InputEventsInstance,
        writer: &mut Writer,
    ) -> Result<usize, ()> {
        let avail_bytes = writer.available_bytes();
        while writer.bytes_written() + size_of::<VirtioInputEvent>() <= avail_bytes {
            match events_instance.next_event() {
                Ok(Some(event)) => {
                    let virtio_event = VirtioInputEvent {
                        type_: event.type_,
                        code: event.code,
                        value: event.value as i32,
                    };
                    writer
                        .write_obj(virtio_event)
                        .expect("Failed to write input event to virtqueue");
                }
                Ok(None) => break, // No more events available
                Err(e) => {
                    error!("Error getting next event: {:?}", e);
                    break;
                }
            }
        }
        Ok(writer.bytes_written())
    }

    /// Send events from the source to the guest
    fn send_events(&mut self, events_instance: &mut InputEventsInstance) -> bool {
        let mut needs_interrupt = false;
        let mem = self.mem.clone();

        // Only process the queue if we might have events to send
        while let Some(desc_chain) = self.event_queue.pop(&mem) {
            let mut writer = match Writer::new(&mem, desc_chain.clone()) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create writer: {:?}", e);
                    break;
                }
            };

            let Ok(bytes_written) = self.fill_event_virtqueue(events_instance, &mut writer) else {
                break;
            };

            self.event_queue
                .add_used(&mem, desc_chain.index, bytes_written as u32);
            needs_interrupt = true;

            // If we didn't write any events, stop processing for now
            if bytes_written == 0 {
                break;
            }
        }

        needs_interrupt
    }

    /// Reads events from guest and sends them to the event source (currently no-op)
    fn read_event_virtqueue(
        &mut self,
        reader: &mut Reader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        while reader.available_bytes() >= std::mem::size_of::<VirtioInputEvent>() {
            // Skip reading for now - would need ByteValued implementation
            //let _evt: virtio_bindings::virtio_input::virtio_input_event = reader.read_obj()?;
            // For now, we don't send events back to the input source
            // This would be used for things like setting LEDs on keyboards, haptic feedback, etc.
        }
        Ok(())
    }

    /// Process the status queue (guest -> device events)
    fn process_status_queue(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        let mut needs_interrupt = false;
        let mem = self.mem.clone();

        while let Some(desc_chain) = self.status_queue.pop(&mem) {
            let mut reader = Reader::new(&mem, desc_chain.clone())?;

            if let Err(e) = self.read_event_virtqueue(&mut reader) {
                error!("Input: failed to read events from virtqueue: {:?}", e);
            }

            self.status_queue.add_used(&mem, desc_chain.index, 0);
            needs_interrupt = true;
        }

        Ok(needs_interrupt)
    }
}
