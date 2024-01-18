use crate::virtio::console::irq_signaler::IRQSignaler;

use crate::virtio::{PortInput, PortOutput, Queue};



use std::thread::{JoinHandle};
use std::{io, mem, thread};
use std::os::fd::AsRawFd;
use nix::poll::{poll, PollFd, PollFlags};
use vm_memory::{Bytes, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, ReadVolatile, VolatileMemoryError, WriteVolatile};

enum State {
    Stopped {
        output: PortOutput,
    },
    Starting,
    Running {
        thread: JoinHandle<()>,
    },
}

pub struct PortTx {
    state: State,
}

impl PortTx {
    pub fn new(output: PortOutput) -> Self {
        Self {
            state: State::Stopped { output }
        }
    }

    pub fn start(&mut self, mem: GuestMemoryMmap, tx_queue: Queue, irq_signaler: IRQSignaler) {
        let old_state = mem::replace(&mut self.state, State::Starting);
        self.state = match old_state {
            State::Starting | State::Running {.. } => panic!("Already running!"),
            State::Stopped {output} => {
                let thread = thread::spawn(|| process_tx(mem, tx_queue, irq_signaler, output));
                State::Running {
                    thread
                }
            }
        };
    }

    pub fn notify(&self) {
        match &self.state {
            State::Running { thread, .. } => {
                thread.thread().unpark()
            },
            State::Starting | State::Stopped { .. } => (),
        }
    }
}

fn process_tx(mem: GuestMemoryMmap, mut queue: Queue, irq: IRQSignaler, mut output: PortOutput) {
    let mem = &mem;
    let mut poll_fds = [PollFd::new(output.as_raw_fd(), PollFlags::POLLOUT)];
    let mut wait_for_output = || {
        poll(&mut poll_fds, -1).expect("Failed to poll");
    };

    loop {
        let head = loop {
            match queue.pop(mem) {
                Some(chain) => break chain,
                None => {
                    irq.signal_used_queue();
                    log::trace!("Tx parking (queue empty)");
                    thread::park()
                }
            }
        };

        let result = mem.try_access(head.len as usize, head.addr, |_, len, addr, region| {
            let src = region.get_slice(addr, len).unwrap();

            /*{
                let mut buf = Vec::new();
                buf.write_volatile(&src).unwrap();
                log::trace!("Tx '{}'", String::from_utf8_lossy(&buf))
            }*/

            loop {
                match output.write_volatile(&src) {
                    // try_access seem to handle partial write for us (we will be invoked again with an offset)
                    Ok(n) => break Ok(n),
                    // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                    Err(VolatileMemoryError::IOError(e))
                    if e.kind() == io::ErrorKind::WouldBlock => {
                        log::trace!("Tx wait for output (would block)");
                        wait_for_output()
                    }
                    Err(e) => break Err(e.into()),
                }
            }
        });

        match result {
            Ok(0) => {
                log::trace!("Tx EOF/WouldBlock");
                queue.undo_pop();
            }
            Ok(n) => {
                assert_eq!(n, head.len as usize);
                log::trace!("Tx {n}/{len}", len = head.len);
                queue.add_used(mem, head.index, head.len)
            }
            Err(e) => {
                log::error!("Failed to write output: {e}");
            }
        }
    }
}
