use crate::virtio::console::irq_signaler::IRQSignaler;

use crate::virtio::{PortInput, Queue};



use std::thread::{JoinHandle};
use std::{io, mem, thread};
use std::os::fd::AsRawFd;
use nix::poll::{poll, PollFd, PollFlags};
use vm_memory::{
    GuestMemory, GuestMemoryMmap, GuestMemoryRegion, ReadVolatile, VolatileMemoryError,
};
use polly::event_manager::Error::Poll;

enum State {
    Stopped {
        input: PortInput,
    },
    Starting,
    Running {
        thread: JoinHandle<()>,
    },
}

pub struct PortRx {
    state: State,
}

impl PortRx {
    pub fn new(input: PortInput) -> Self {
        Self {
            state: State::Stopped { input }
        }
    }

    pub fn start(&mut self, mem: GuestMemoryMmap, rx_queue: Queue, irq_signaler: IRQSignaler) {
        let old_state = mem::replace(&mut self.state, State::Starting);
        self.state = match old_state {
            State::Starting | State::Running {.. } => panic!("Already running!"),
            State::Stopped {input} => {
                let thread = thread::spawn(|| process_rx(mem, rx_queue, irq_signaler, input));
                State::Running {
                    thread
                }
            }
        };
    }

    pub fn notify(&self) {
        match &self.state {
            State::Running { thread, .. } => thread.thread().unpark(),
            State::Starting | State::Stopped { .. } => (),
        }
    }
}

fn process_rx(mem: GuestMemoryMmap, mut queue: Queue, irq_signaler: IRQSignaler, mut input: PortInput) {
    let mem = &mem;

    let mut poll_fds = [PollFd::new(input.as_raw_fd(), PollFlags::POLLIN)];
    let mut wait_for_input = || {
        poll(&mut poll_fds, -1).expect("Failed to poll");
    };

    loop {
        let head = loop {
            match queue.pop(mem) {
                Some(chain) => break chain,
                None => {
                    irq_signaler.signal_used_queue();
                    thread::park();
                    log::trace!("Rx unparked, queue len {}", queue.len(mem))
                }
            }
        };

        let result = mem
            .try_access(head.len as usize, head.addr, |_, len, addr, region| {
                let mut target = region.get_slice(addr, len).unwrap();
                let result = input.read_volatile(&mut target);
                match result {
                    Ok(n) => Ok(n),
                    // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                    Err(VolatileMemoryError::IOError(e))
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        Ok(0)
                    }
                    Err(e) => Err(e.into()),
                }
            });

        match result {
            Ok(0) => {
                log::trace!("Rx EOF/WouldBlock");
                queue.undo_pop();
                irq_signaler.signal_used_queue();
                wait_for_input();
            }
            Ok(len) => {
                log::trace!("Rx {len} bytes");
                queue.add_used(mem, head.index, len as u32);
            }
            Err(e) => {
                log::error!("Failed to read: {e:?}")
            }
        }
    }
}
