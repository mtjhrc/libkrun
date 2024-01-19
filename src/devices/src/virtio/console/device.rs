use std::cmp;
use std::io::Write;
use std::mem::{size_of, size_of_val};
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use libc::{raise, TIOCGWINSZ};
use utils::eventfd::EventFd;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, ConsoleError, DeviceState, Queue as VirtQueue, VirtioDevice,
};
use super::{defs, defs::control_event, defs::uapi};
use crate::legacy::Gic;
use crate::virtio::console::console_control::{ConsoleControl, VirtioConsoleControl};
use crate::virtio::console::defs::QUEUE_SIZE;
use crate::virtio::console::port::Port;
use crate::virtio::console::port_queue_mapping::{
    num_queues, port_id_to_queue_idx, QueueDirection,
};
use crate::virtio::{PortInput, PortOutput};

use crate::virtio::console::irq_signaler::IRQSignaler;

pub(crate) const CONTROL_RXQ_INDEX: usize = 2;
pub(crate) const CONTROL_TXQ_INDEX: usize = 3;

pub(crate) const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_CONSOLE_F_SIZE as u64
    | 1 << uapi::VIRTIO_CONSOLE_F_MULTIPORT as u64
    | 1 << uapi::VIRTIO_F_VERSION_1 as u64;

pub(crate) fn get_win_size() -> (u16, u16) {
    #[repr(C)]
    #[derive(Default)]
    struct WS {
        rows: u16,
        cols: u16,
        xpixel: u16,
        ypixel: u16,
    }
    let ws: WS = WS::default();

    unsafe {
        libc::ioctl(0, TIOCGWINSZ, &ws);
    }

    (ws.cols, ws.rows)
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioConsoleConfig {
    cols: u16,
    rows: u16,
    max_nr_ports: u32,
    emerg_wr: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioConsoleConfig {}

impl VirtioConsoleConfig {
    pub fn new(cols: u16, rows: u16, max_nr_ports: u32) -> Self {
        VirtioConsoleConfig {
            cols,
            rows,
            max_nr_ports,
            emerg_wr: 0u32,
        }
    }

    pub fn update_console_size(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
    }
}

pub struct Console {
    pub(crate) device_state: DeviceState,
    pub(crate) irq: IRQSignaler,
    pub(crate) control: Arc<ConsoleControl>,
    pub(crate) ports: Vec<Port>,

    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) activate_evt: EventFd,
    pub(crate) sigwinch_evt: EventFd,

    config: VirtioConsoleConfig,
}

pub enum PortDescription {
    Console {
        input: Option<PortInput>,
        output: Option<PortOutput>,
    },
    /*InputPipe {
        name: Cow<'static, str>,
        input: PortInput,
    },
    OutputPipe {
        name: Cow<'static, str>,
        output: PortOutput,
    },*/
}

impl Console {
    pub fn new(ports: Vec<PortDescription>) -> super::Result<Console> {
        let num_queues = num_queues(ports.len());
        let queues = vec![VirtQueue::new(QUEUE_SIZE); num_queues];

        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events
                .push(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(ConsoleError::EventFd)?);
        }

        let (cols, rows) = get_win_size();
        let config = VirtioConsoleConfig::new(cols, rows, ports.len() as u32);
        let ports = ports.into_iter().map(Port::new).collect();
        Ok(Console {
            irq: IRQSignaler::new(),
            control: ConsoleControl::new(),
            ports,
            queues,
            queue_events,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(ConsoleError::EventFd)?,
            sigwinch_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(ConsoleError::EventFd)?,
            device_state: DeviceState::Inactive,
            config,
        })
    }
    /*
    pub fn handle_input(&mut self, port_id: usize, has_input: bool, has_eof: bool) -> bool {
        let mut raise_irq = false;

        match self.ports[port_id].status {
            PortStatus::NotReady => {
                log::trace!(
                    "handle_input on port {port_id} but port is not ready: has_input={has_input} has_eof={has_eof}"
                );
                if has_input {
                    self.ports[port_id].pending_input = true;
                }
                if has_eof {
                    self.ports[port_id].pending_eof = true;
                }
            }
            PortStatus::Ready { opened: false } => {
                log::trace!(
                    "handle_input on port {port_id} but port is closed: has_input={has_input} has_eof={has_eof}",
                );
            }
            PortStatus::Ready { opened: true } => {
                log::trace!("handle_input on opened port {port_id}");
                if has_input {
                    raise_irq |= self.ports[port_id].process_rx(
                        get_mem!(self),
                        &mut self.queues[port_id_to_queue_idx(QueueDirection::Rx, port_id)],
                    );
                }
                if has_eof {
                    // We need to make sure not not close the port until input is fully processed
                    if self.ports[port_id].pending_input {
                        self.ports[port_id].pending_eof = true
                    } else {
                        self.close_port(port_id);
                        raise_irq |= true;
                    }
                }
            }
        }

        raise_irq
    }

    pub fn resume_rx(&mut self, port_id: usize) -> bool {
        self.handle_input(
            port_id,
            self.ports[port_id].pending_input,
            self.ports[port_id].pending_eof,
        )
    }

    fn close_port(&mut self, port_id: usize) {
        self.ports[port_id].status = PortStatus::Ready { opened: false };
        ConsoleControlSender::new(&mut self.queues[CONTROL_RXQ_INDEX]).send_port_open(
            get_mem!(self),
            port_id as u32,
            false,
        );
        self.ports[port_id].input = None;
        self.ports[port_id].output = None;
    }


    pub fn handle_output(&mut self, port_id: usize, has_eof: bool) -> bool {
        let mut raise_irq = false;
        match self.ports[port_id].status {
            PortStatus::Ready { opened: true } => {
                raise_irq |= self.ports[port_id].process_tx(
                    get_mem!(self),
                    &mut self.queues[port_id_to_queue_idx(QueueDirection::Tx, port_id)],
                );

                if has_eof {
                    // We only close the port if the output is written
                    if self.ports[port_id].has_pending_output() {
                        self.ports[port_id].pending_eof = true;
                    } else {
                        self.close_port(port_id);
                        raise_irq |= true;
                    }
                }
            }
            PortStatus::NotReady | PortStatus::Ready { opened: false } => {
                log::trace!("Port {port_id} is not ready to accept input")
            }
        }

        raise_irq
    }

    pub fn resume_tx(&mut self, port_id: usize) -> bool {
        self.handle_output(port_id, self.ports[port_id].pending_eof)
    }
    */

    pub fn id(&self) -> &str {
        defs::CONSOLE_DEV_ID
    }

    pub fn set_intc(&mut self, intc: Arc<Mutex<Gic>>) {
        self.irq.set_intc(intc)
    }

    pub fn get_sigwinch_fd(&self) -> RawFd {
        self.sigwinch_evt.as_raw_fd()
    }

    pub fn update_console_size(&mut self, cols: u16, rows: u16) {
        debug!("update_console_size: {} {}", cols, rows);
        self.config.update_console_size(cols, rows);
        /*ConsoleControlSender::new(&mut self.queues[CONTROL_RXQ_INDEX]).send_console_resize(
            get_mem!(self),
            0,
            &VirtioConsoleResize { rows, cols },
        );*/
        self.irq.signal_config_update()
    }

    pub(crate) fn process_control_rx(&mut self) -> bool {
        log::trace!("process_control_rx");
        let DeviceState::Activated(ref mem) = self.device_state else {
            unreachable!()
        };
        let mut raise_irq = false;

        while let Some(head) = self.queues[CONTROL_RXQ_INDEX].pop(mem) {
            if let Some(buf)  = self.control.queue_pop() {
                match mem.write(&buf, head.addr) {
                    Ok(n) => {
                        if n != buf.len() {
                            log::error!("process_control_rx: partial write");
                        }
                        raise_irq = true;
                        log::trace!("process_control_rx wrote {n}");
                        self.queues[CONTROL_RXQ_INDEX].add_used(mem, head.index, n as u32);
                    }
                    Err(e) => {
                        log::error!("process_control_rx failed to write: {e}");
                    }
                }
            } else {
                self.queues[CONTROL_RXQ_INDEX].undo_pop();
                break;
            }
        }
        raise_irq
    }

    pub(crate) fn process_control_tx(&mut self) -> bool {
        log::trace!("process_control_tx");
        let DeviceState::Activated(ref mem) = self.device_state else {
            unreachable!()
        };

        let tx_queue = &mut self.queues[CONTROL_TXQ_INDEX];
        //let mut control = ConsoleControlSender::new(rx_queue);
        let mut send_irq = false;

        let mut ports_to_resume = Vec::new();

        while let Some(head) = tx_queue.pop(mem) {
            send_irq = true;

            let cmd: VirtioConsoleControl = match mem.read_obj(head.addr) {
                Ok(cmd) => cmd,
                Err(e) => {
                    log::error!(
                    "Failed to read VirtioConsoleControl struct: {e:?}, struct len = {len}, head.len = {head_len}",
                    len = size_of::<VirtioConsoleControl>(),
                    head_len = head.len,
                );
                    continue;
                }
            };
            tx_queue.add_used(mem, head.index, size_of_val(&cmd) as u32);

            log::trace!("VirtioConsoleControl cmd: {cmd:?}");
            match cmd.event {
                control_event::VIRTIO_CONSOLE_DEVICE_READY => {
                    log::debug!(
                        "Device is ready: initialization {}",
                        if cmd.value == 1 { "ok" } else { "failed" }
                    );
                    for port_id in 0..self.ports.len() {
                        self.control.add_port(port_id as u32);
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_READY => {
                    if cmd.value != 1 {
                        log::error!("Port initialization failed: {:?}", cmd);
                        continue;
                    }
                    self.ports[cmd.id as usize].on_ready();
                    if self.ports[cmd.id as usize].is_console() {
                        self.control.send_mark_console_port(mem, cmd.id);
                    } else {
                        // lets start with all ports open for now
                        self.control.set_port_open(cmd.id, true)
                    }

                    let name = self.ports[cmd.id as usize].name();
                    if !name.is_empty() {
                        self.control.set_port_name(cmd.id, name)
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_OPEN => {
                    let opened = match cmd.value {
                        0 => false,
                        1 => true,
                        _ => {
                            log::error!(
                                "Invalid value ({}) for VIRTIO_CONSOLE_PORT_OPEN on port {}",
                                cmd.value,
                                cmd.id
                            );
                            continue;
                        }
                    };

                    if !opened {
                        log::trace!("Closed port not implemented!");
                        continue;
                    }

                    ports_to_resume.push(cmd.id as usize);

                    /*
                    if ports[cmd.id as usize].status == PortStatus::NotReady {
                        log::warn!("Driver signaled opened={} to port {} that was not ready, assuming the port is ready.",opened, cmd.id)
                    }*/
                    //self.ports[cmd.id as usize].status = PortStatus::Ready { opened };
                    // There could be pending input on the given port, so lets try to process it

                    /*
                    if opened {
                        ports_to_resume.push(cmd.id);
                    }*/
                }
                _ => log::warn!("Unknown console control event {:x}", cmd.event),
            }
        }

        for port_id in ports_to_resume {
            log::trace!("Starting port io for port {}", port_id);
            self.ports[port_id].on_open(
                mem.clone(),
                self.queues[port_id_to_queue_idx(QueueDirection::Rx, port_id)].clone(),
                self.queues[port_id_to_queue_idx(QueueDirection::Tx, port_id)].clone(),
                self.irq.clone(),
            );
        }

        send_irq
    }
}

impl VirtioDevice for Console {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_CONSOLE
    }

    fn queues(&self) -> &[VirtQueue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [VirtQueue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_evt(&self) -> &EventFd {
        self.irq.interrupt_evt()
    }

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.irq.interrupt_status()
    }

    fn set_irq_line(&mut self, irq: u32) {
        self.irq.set_irq_line(irq)
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "console: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt");
            return Err(ActivateError::BadActivate);
        }

        self.device_state = DeviceState::Activated(mem);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }
}
