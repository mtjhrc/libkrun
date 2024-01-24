//! See https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-2920002
//! for port <-> virtio queue index mapping

use std::borrow::Cow;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::{mem, thread};
use std::sync::atomic::{AtomicBool, Ordering};
use vm_memory::GuestMemoryMmap;

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::device::PortDescription;
use crate::virtio::console::irq_signaler::IRQSignaler;
use crate::virtio::console::process_rx::process_rx;
use crate::virtio::console::process_tx::process_tx;
use crate::virtio::{PortInputFd, PortOutputFd, Queue};
use crate::virtio::console::port_io::{PortInput, PortOutput};

#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum PortStatus {
    NotReady,
    Ready { opened: bool },
}

enum PortState {
    Inactive {
        input: Option<Box<dyn PortInput + Send>>,
        output: Option<Box<dyn PortOutput + Send>>,
    },
    Active {
        stop: Arc<AtomicBool>,
        rx_thread: Option<JoinHandle<()>>,
        tx_thread: Option<JoinHandle<()>>,
    },
}

pub(crate) struct Port {
    port_id: u32,
    /// Empty if no name given
    name: Cow<'static, str>,
    status: PortStatus,
    represents_console: bool,
    state: PortState,
}

impl Port {
    pub(crate) fn new(port_id: u32, description: PortDescription) -> Self {
        match description {
            PortDescription::Console { input, output } => Self {
                port_id,
                name: "".into(),
                represents_console: true,
                status: PortStatus::NotReady,
                state: PortState::Inactive { input, output },
            },
            PortDescription::InputPipe { name, input } => Self {
                port_id,
                name,
                represents_console: false,
                status: PortStatus::NotReady,
                state: PortState::Inactive {
                    input: Some(input),
                    output: None,
                },
            },
            PortDescription::OutputPipe { name, output } => Self {
                port_id,
                name,
                represents_console: false,
                status: PortStatus::NotReady,
                state: PortState::Inactive {
                    input: None,
                    output: Some(output),
                },
            },
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_console(&self) -> bool {
        self.represents_console
    }

    pub fn notify_rx(&self) {
        if let PortState::Active { rx_thread, .. } = &self.state {
            if let Some(rx_thread) = rx_thread {
                rx_thread.thread().unpark()
            }
        }
    }

    pub fn notify_tx(&self) {
        if let PortState::Active { tx_thread, .. } = &self.state {
            if let Some(rx_thread) = tx_thread {
                rx_thread.thread().unpark()
            }
        }
    }

    pub fn on_ready(&mut self) {
        self.status = PortStatus::Ready { opened: false }
    }

    pub fn on_open(
        &mut self,
        mem: GuestMemoryMmap,
        rx_queue: Queue,
        tx_queue: Queue,
        irq_signaler: IRQSignaler,
        control: Arc<ConsoleControl>,
    ) {
        match self.status {
            PortStatus::NotReady => {
                log::warn!("attempted to open port that is not ready, assuming the port is ready")
            }
            PortStatus::Ready { .. } => {}
        }

        self.status = PortStatus::Ready { opened: true };

        let (input, output) = if let PortState::Inactive { input, output } = &mut self.state {
            (mem::take(input), mem::take(output))
        } else {
            // The threads are already started
            return;
        };

        let rx_thread = input.map(|input| {
            let mem = mem.clone();
            let irq_signaler = irq_signaler.clone();
            let control = control.clone();
            let port_id = self.port_id;
            thread::spawn(move || process_rx(mem, rx_queue, irq_signaler, input, control, port_id))
        });

        let stop = Arc::new(AtomicBool::new(false));

        let tx_thread = output.map(|output| {
            let stop = stop.clone();
            thread::spawn(move || process_tx(stop, mem, tx_queue, irq_signaler, output, control))
        });

        self.state = PortState::Active {
            stop,
            rx_thread,
            tx_thread,
        }
    }

    pub fn flush(&mut self) {
        if let PortState::Active { stop, tx_thread, rx_thread: _} = &mut self.state {
            stop.store(true, Ordering::Release);
            if let Some(tx_thread) = mem::take(tx_thread) {
                tx_thread.thread().unpark();
                if let Err(e) = tx_thread.join() {
                    log::error!("Failed to flush tx for port {port_id}, thread panicked: {e:?}", port_id = self.port_id)
                }
            }
        };
    }
}
