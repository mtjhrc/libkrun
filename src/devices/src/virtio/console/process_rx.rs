use nix::poll::{poll, PollFd, PollFlags};
use polly::event_manager::Error::Poll;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use std::{io, mem, thread};
use vm_memory::{GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion, ReadVolatile, VolatileMemoryError, VolatileSlice};

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::irq_signaler::IRQSignaler;
use crate::virtio::{PortInputFd, Queue};
use crate::virtio::console::port_io::PortInput;

pub(crate) fn process_rx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    irq_signaler: IRQSignaler,
    mut input: Box<dyn PortInput>,
    control: Arc<ConsoleControl>,
    port_id: u32,
) {
    let mem = &mem;

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
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        Ok(0)
                    }
                    Err(e) => Err(GuestMemoryError::IOError(e)),
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
                control.set_port_open(port_id, false);
                log::trace!("RX eof stopping!!!!!!");
                return;
            }

            log::trace!("Rx EOF/WouldBlock");
            irq_signaler.signal_used_queue("rx eof/wouldblock");
            queue.undo_pop();
            input.wait_until_readable();
        }
    }
}
