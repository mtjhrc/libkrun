use nix::poll::{poll, PollFd, PollFlags};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::{io, mem, thread};
use std::sync::atomic::{AtomicBool, Ordering};
use vm_memory::{Bytes, GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion, ReadVolatile, VolatileMemoryError, VolatileSlice, WriteVolatile};

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::irq_signaler::IRQSignaler;
use crate::virtio::{PortInputFd, PortOutputFd, Queue};
use crate::virtio::console::port_io::PortOutput;

pub(crate) fn process_tx(
    stop: Arc<AtomicBool>,
    mem: GuestMemoryMmap,
    mut queue: Queue,
    irq: IRQSignaler,
    mut output: Box<dyn PortOutput>,
    control: Arc<ConsoleControl>,
) {
    let mem = &mem;

    loop {
        let head = loop {
            match queue.pop(mem) {
                Some(chain) => break chain,
                None => {
                    irq.signal_used_queue("tx popped all heads");
                    log::trace!("Tx parking (queue empty)");
                    thread::park();
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    log::trace!("Tx unparked, queue len {}", queue.len(mem))
                }
            }
        };

        let head_index = head.index;
        let mut bytes_written = 0;

        'chain_loop: for chain in head.into_iter().readable() {
            log::trace!(
                "tx chain: [{}] {:?} {:?}",
                head_index,
                chain.addr,
                chain.len
            );
            let result = mem.try_access(chain.len as usize, chain.addr, |_, len, addr, region| {
                let src = region.get_slice(addr, len).unwrap();

                loop {
                    log::trace!("Tx write_volatile {len} bytes");
                    match output.write_volatile(&src) {
                        // try_access seem to handle partial write for us (we will be invoked again with an offset)
                        Ok(n) => break Ok(n),
                        // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                        Err(e)
                            if e.kind() == io::ErrorKind::WouldBlock =>
                        {
                            log::trace!("Tx wait for output (would block)");
                            irq.signal_used_queue("tx waiting for output");
                            output.wait_until_writable();
                        }
                        Err(e) => break Err(GuestMemoryError::IOError(e)),
                    }
                }
            });

            match result {
                Ok(0) => {
                    break 'chain_loop;
                }
                Ok(n) => {
                    assert_eq!(n, chain.len as usize);
                    log::trace!("Tx {n}/{len}", len = chain.len);
                    bytes_written += n;
                }
                Err(e) => {
                    log::error!("Failed to write output: {e}");
                }
            }
        }

        log::trace!("Tx Add used [{}] {bytes_written}", head_index);
        if bytes_written == 0 {
            queue.undo_pop();
        } else {
            queue.add_used(mem, head_index, bytes_written as u32);
        }
    }
}
