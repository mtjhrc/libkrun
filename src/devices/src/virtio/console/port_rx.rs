use crate::virtio::console::irq_signaler::IRQSignaler;

use crate::virtio::{PortInput, Queue};

use crate::virtio::console::console_control::ConsoleControl;
use nix::poll::{poll, PollFd, PollFlags};
use polly::event_manager::Error::Poll;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use std::{io, mem, thread};
use vm_memory::{
    GuestMemory, GuestMemoryMmap, GuestMemoryRegion, ReadVolatile, VolatileMemoryError,
};

enum State {
    Stopped { input: PortInput },
    Starting,
    Running { thread: JoinHandle<()> },
}

pub struct PortRx {
    state: State,
}

impl PortRx {
    pub fn new(input: PortInput) -> Self {
        Self {
            state: State::Stopped { input },
        }
    }

    pub fn start(
        &mut self,
        mem: GuestMemoryMmap,
        rx_queue: Queue,
        irq_signaler: IRQSignaler,
        control: Arc<ConsoleControl>,
    ) {
        let old_state = mem::replace(&mut self.state, State::Starting);
        self.state = match old_state {
            State::Starting | State::Running { .. } => panic!("Already running!"),
            State::Stopped { input } => {
                let thread =
                    thread::spawn(|| process_rx(mem, rx_queue, irq_signaler, input, control));
                State::Running { thread }
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

fn process_rx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    irq_signaler: IRQSignaler,
    mut input: PortInput,
    control: Arc<ConsoleControl>,
) {
    let mem = &mem;

    let mut poll_fds = [PollFd::new(input.as_raw_fd(), PollFlags::POLLIN)];
    let mut wait_for_input = || {
        poll(&mut poll_fds, -1).expect("Failed to poll");
    };

    let mut eof = false;
    loop {
        let head2 = loop {
            match queue.pop(mem) {
                Some(chain) => break chain,
                None => {
                    irq_signaler.signal_used_queue("rx popped all heads");
                    thread::park();
                    log::trace!("Rx unparked, queue len {}", queue.len(mem))
                }
            }
        };

        let head_index = head2.index;
        let mut bytes_read = 0;
        for chain in head2.into_iter().writable() {
            let result = mem.try_access(chain.len as usize, chain.addr, |_, len, addr, region| {
                let mut target = region.get_slice(addr, len).unwrap();
                let result = input.read_volatile(&mut target);
                match result {
                    Ok(n) => {
                        if n == 0 {
                            eof = true;
                        }
                        Ok(n)
                    }
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
                    break;
                }
                Ok(len) => {
                    bytes_read += len;
                }
                Err(e) => {
                    log::error!("Failed to read: {e:?}")
                }
            }
        }


        if bytes_read != 0 {
            log::trace!("Rx {bytes_read} bytes queue len{}", queue.len(mem));
            queue.add_used(mem, head_index, bytes_read as u32);
            //irq_signaler.signal_used_queue("rx queue used");
        } else if bytes_read == 0 {
            if eof {
                log::trace!("RX eof stopping!!!!!!");
                return;
            }

            log::trace!("Rx EOF/WouldBlock");
            irq_signaler.signal_used_queue("rx eof/wouldblock");
            // raise irq here?
            queue.undo_pop();
            wait_for_input();
        }
    }
}
