use crate::virtio::console::irq_signaler::IRQSignaler;
use crate::virtio::console::port::PortStatus;
use crate::virtio::{PortInput, Queue};
use polly::event_manager::{EventManager, Subscriber};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{JoinHandle, Thread};
use std::{io, thread};
use vm_memory::{
    GuestMemory, GuestMemoryMmap, GuestMemoryRegion, ReadVolatile, VolatileMemoryError,
};

pub struct PortRxArgs {
    pub mem: GuestMemoryMmap,
    pub queue: Queue,
    pub input: PortInput,
    pub irq_signaler: IRQSignaler,
}

pub(crate) enum PortRx {
    Running {
        input_fd: RawFd,
        thread: JoinHandle<()>,
    },
    Stopped {
        args: PortRxArgs,
    },
}

impl PortRx {
    pub fn new(args: PortRxArgs) -> Self {
        Self::Stopped { args }
    }

    pub fn input_raw_fd(&self) -> RawFd {
        match self {
            PortRx::Running { input_fd, .. } => *input_fd,
            PortRx::Stopped { args } => args.input.as_raw_fd(),
        }
    }

    pub fn start(&mut self) {
        match *self {
            Self::Running { .. } => panic!("Already running!"),
            Self::Stopped { args } => {
                let input_fd = args.input.as_raw_fd();
                let thread = thread::spawn(|| run(args));
                *self = Self::Running { input_fd, thread }
            }
        }
    }

    pub fn notify(&self) {
        match self {
            Self::Running { thread, .. } => thread.thread().unpark(),
            Self::Stopped { .. } => (),
        }
    }
}

fn run(args: PortRxArgs) {
    let PortRxArgs {
        ref mem,
        mut queue,
        mut input,
        irq_signaler,
    } = args;

    loop {
        let head = loop {
            match queue.pop(mem) {
                Some(chain) => break chain,
                None => {
                    irq_signaler.signal_used_queue();
                    thread::park()
                }
            }
        };

        let result = self
            .mem
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
                thread::park();
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
