//! See https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-2920002
//! for port <-> virtio queue index mapping

use std::borrow::Cow;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::{mem, thread};
use vm_memory::GuestMemoryMmap;

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::device::PortDescription;
use crate::virtio::console::irq_signaler::IRQSignaler;
use crate::virtio::console::process_rx::process_rx;
use crate::virtio::console::process_tx::process_tx;
use crate::virtio::{PortInput, PortOutput, Queue};

#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum PortStatus {
    NotReady,
    Ready { opened: bool },
}

enum PortState {
    Inactive {
        input: Option<PortInput>,
        output: Option<PortOutput>,
    },
    Active {
        rx_thread: Option<JoinHandle<()>>,
        tx_thread: Option<JoinHandle<()>>,
    },
}

pub(crate) struct Port {
    /// Empty if no name given
    name: Cow<'static, str>,
    status: PortStatus,
    represents_console: bool,
    state: PortState,
}

impl Port {
    pub(crate) fn new(description: PortDescription) -> Self {
        match description {
            PortDescription::Console { input, output } => Self {
                name: "".into(),
                represents_console: true,
                status: PortStatus::NotReady,
                state: PortState::Inactive { input, output },
            },
            PortDescription::InputPipe { name, input } => Self {
                name,
                represents_console: false,
                status: PortStatus::NotReady,
                state: PortState::Inactive {
                    input: Some(input),
                    output: None,
                },
            },
            PortDescription::OutputPipe { name, output } => Self {
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
            thread::spawn(|| process_rx(mem, rx_queue, irq_signaler, input, control))
        });

        let tx_thread = output.map(|output| {
            thread::spawn(move || process_tx(mem, tx_queue, irq_signaler, output, control))
        });

        self.state = PortState::Active {
            rx_thread,
            tx_thread,
        }
    }
}
