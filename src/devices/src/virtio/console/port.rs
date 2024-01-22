//! See https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-2920002
//! for port <-> virtio queue index mapping

use std::borrow::Cow;


use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use crate::virtio::console::device::PortDescription;

use crate::virtio::Queue;
use vm_memory::{
    GuestMemoryMmap,
};
use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::irq_signaler::IRQSignaler;
use crate::virtio::console::port_rx::{PortRx};
use crate::virtio::console::port_tx::PortTx;

#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum PortStatus {
    NotReady,
    Ready { opened: bool },
}

pub(crate) struct Port {
    /// Empty if no name given
    name: Cow<'static, str>,
    status: PortStatus,
    represents_console: bool,
    input_fd: Option<RawFd>,
    output_fd: Option<RawFd>,
    rx: Option<PortRx>,
    tx: Option<PortTx>,
}

impl Port {
    pub(crate) fn new(description: PortDescription) -> Self {
        match description {
            PortDescription::Console { input, output } => Self {
                name: "".into(),
                represents_console: true,
                status: PortStatus::NotReady,
                input_fd: input.as_ref().map(AsRawFd::as_raw_fd),
                output_fd: output.as_ref().map(AsRawFd::as_raw_fd),
                rx: input.map(PortRx::new),
                tx: output.map(PortTx::new),
            },
            PortDescription::InputPipe { name, input } => Self {
                name,
                represents_console: false,
                status: PortStatus::NotReady,
                input_fd: Some(input.as_raw_fd()),
                output_fd: None,
                rx: Some(PortRx::new(input)),
                tx: None
            },
            PortDescription::OutputPipe { name, output } => Self {
                name,
                represents_console: false,
                status: PortStatus::NotReady,
                input_fd: None,
                output_fd: Some(output.as_raw_fd()),
                rx: None,
                tx: Some(PortTx::new(output))
            },
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_console(&self) -> bool {
        self.represents_console
    }

    pub fn input_fd(&self) -> Option<RawFd> {
        self.input_fd
    }

    pub fn output_fd(&self) -> Option<RawFd> {
        self.output_fd
    }

    pub fn notify_rx(&self) {
        if let Some(rx) = &self.rx {
            rx.notify();
        }
    }

    pub fn notify_tx(&self) {
        if let Some(tx) = &self.tx {
            tx.notify();
        }
    }

    pub fn on_ready(&mut self) {
        self.status = PortStatus::Ready { opened: false }
    }

    pub fn on_open(&mut self, mem: GuestMemoryMmap, rx_queue: Queue, tx_queue: Queue, irq_signaler: IRQSignaler, control: Arc<ConsoleControl>) {
        self.status = PortStatus::Ready { opened: true };
        if let Some(rx) = &mut self.rx {
            rx.start(mem.clone(), rx_queue, irq_signaler.clone(), control.clone());
        }

        if let Some(tx) = &mut self.tx {
            tx.start(mem, tx_queue, irq_signaler, control);
        }
    }
    /*
    pub fn process_rx(&mut self, mem: &GuestMemoryMmap, queue: &mut Queue) -> bool {
        let mut raise_irq = false;

        let Some(input) = &mut self.input else {
            return raise_irq;
        };

        while let Some(head) = queue.pop(mem) {
            let result = mem.try_access(head.len as usize, head.addr, |_, len, addr, region| {
                let mut target = region.get_slice(addr, len).unwrap();
                log::trace!("read {{");
                let result = input.read_volatile(&mut target);
                log::trace!("}} read");
                match result {
                    Ok(n) => {
                        if n == 0 {
                            self.pending_input = false;
                        }
                        Ok(n)
                    }
                    // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                    Err(VolatileMemoryError::IOError(e))
                        if e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        self.pending_input = false;
                        Ok(0)
                    }
                    Err(e) => Err(e.into()),
                }
            });
            raise_irq = true;
            match result {
                Ok(0) => {
                    log::trace!("Rx EOF/WouldBlock");
                    queue.undo_pop();
                    break;
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

        raise_irq
    }

    pub fn process_tx(&mut self, mem: &GuestMemoryMmap, queue: &mut Queue) -> bool {
        let mut raise_irq = false;

        let Some(output) = &mut self.output else {
            return raise_irq;
        };

        loop {
            let (addr, len, index) = if let Some(out) = &self.unfinished_output {
                (out.addr, out.len, out.index)
            } else if let Some(head) = queue.pop(mem) {
                (head.addr, head.len, head.index)
            } else {
                break;
            };

            let result = mem.try_access(len as usize, addr, |_, len, addr, region| {
                let src = region.get_slice(addr, len).unwrap();
                let result = output.write_volatile(&src);

                match result {
                    // try_access seem to handle partial write for us (we will be invoked again with an offset)
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
                    log::trace!("Tx EOF/WouldBlock");
                    queue.undo_pop();
                    break;
                }
                Ok(n) => {
                    if n == len as usize {
                        self.unfinished_output = None;
                        queue.add_used(mem, index, n as u32)
                    } else {
                        assert!(n < len as usize);
                        self.unfinished_output = Some(UnfinishedDescriptorChain {
                            addr: addr.checked_add(n as u64).expect("Guest address overflow!"),
                            len: len - n as u32,
                            index,
                        })
                    }
                }
                Err(e) => {
                    log::error!("Failed to write output: {e}");
                }
            }
            raise_irq = true;
        }

        raise_irq
    }*/
}
