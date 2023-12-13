use std::fmt::Debug;
use std::io::{stderr, stdin, stdout, Write};
use std::io::IsTerminal;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::{cmp, io};
use std::mem::size_of;

use libc::TIOCGWINSZ;
use utils::epoll::EventSet;
use utils::eventfd::EventFd;
use vm_memory::{
    ByteValued, Bytes, GuestMemoryError, GuestMemoryMmap, VolatileMemory,
};

use super::super::{
    ActivateError, ActivateResult, ConsoleError, DeviceState, Queue as VirtQueue, VirtioDevice,
    VIRTIO_MMIO_INT_CONFIG, VIRTIO_MMIO_INT_VRING,
};
use super::{defs, defs::control_event, defs::uapi};
use crate::legacy::{Gic};
use crate::virtio::console::defs::control_event::{
    VIRTIO_CONSOLE_CONSOLE_PORT, VIRTIO_CONSOLE_PORT_ADD, VIRTIO_CONSOLE_PORT_NAME,
    VIRTIO_CONSOLE_PORT_OPEN,
};
use crate::virtio::console::port::{port_id_to_queue_idx, Port, PortStatus, QueueDirection};
use crate::virtio::PortDescription;
use crate::Error as DeviceError;

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

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed(4))]
pub struct VirtioConsoleControl {
    /// Port number
    pub(crate) id: u32,
    /// The kind of control event
    pub(crate) event: u16,
    /// Extra information for the event
    pub(crate) value: u16,
}

// Safe because it only has data and has no implicit padding.
// but NOTE, that we rely on CPU being little endian, for the values to be correct
unsafe impl ByteValued for VirtioConsoleControl {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioConsoleResize {
    // The order of these fields in the kernel and in the spec do not match,
    // the kernel does not follow the spec!
    // So lets use
    rows: u16,
    cols: u16,
}

// Safe because it only has data and has no implicit padding.
// but NOTE, that we rely on CPU being little endian, for the values to be correct
unsafe impl ByteValued for VirtioConsoleResize {}

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
    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,
    pub(crate) ports: Vec<Port>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    pub(crate) interrupt_evt: EventFd,
    pub(crate) activate_evt: EventFd,
    pub(crate) sigwinch_evt: EventFd,
    pub(crate) device_state: DeviceState,
    config: VirtioConsoleConfig,
    configured: bool,
    pub(crate) interactive: bool,
    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,
}

//pub trait ReadableWritableFd = ReadableFd + io::Write;

impl Console {
    pub fn new(ports: Vec<PortDescription>) -> super::Result<Console> {
        log::trace!(
            "isatty? stdin={} stdout={} stderr={}",
            stdin().is_terminal(),
            stdout().is_terminal(),
            stderr().is_terminal()
        );

        assert!(
            !ports.is_empty(),
            "Creating console device without any ports is currently not supported!"
        );
        // 2 control queues, 2 queues for each port (each port always has an input and output queue)
        let num_queues: usize = 2 + ports.len() * 2;
        let queues: Vec<VirtQueue> = vec![VirtQueue::new(defs::QUEUE_SIZE); num_queues];

        let queue_events: Vec<EventFd> = (0..num_queues)
            .map(|_| EventFd::new(utils::eventfd::EFD_NONBLOCK))
            .collect::<Result<_, _>>()
            .map_err(ConsoleError::EventFd)?;

        let (cols, rows) = get_win_size();
        let config = VirtioConsoleConfig::new(cols, rows, ports.len() as u32);

        let ports: Vec<Port> = ports.into_iter().map(Port::new).collect();

        Ok(Console {
            queues,
            queue_events,
            ports,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(ConsoleError::EventFd)?,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(ConsoleError::EventFd)?,
            sigwinch_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(ConsoleError::EventFd)?,
            device_state: DeviceState::Inactive,
            config,
            configured: false,
            interactive: true,
            intc: None,
            irq_line: None,
        })
    }

    pub fn id(&self) -> &str {
        defs::CONSOLE_DEV_ID
    }

    pub fn set_intc(&mut self, intc: Arc<Mutex<Gic>>) {
        self.intc = Some(intc);
    }

    pub fn get_sigwinch_fd(&self) -> RawFd {
        self.sigwinch_evt.as_raw_fd()
    }

    pub fn set_interactive(&mut self, interactive: bool) {
        self.interactive = interactive;
    }

    /// Signal the guest driver that we've used some virtio buffers that it had previously made
    /// available.
    pub fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        debug!("console: raising IRQ");
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        if let Some(intc) = &self.intc {
            intc.lock().unwrap().set_irq(self.irq_line.unwrap());
            Ok(())
        } else {
            self.interrupt_evt.write(1).map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                DeviceError::FailedSignalingUsedQueue(e)
            })
        }
    }

    pub fn signal_config_update(&self) -> result::Result<(), DeviceError> {
        debug!("console: raising IRQ for config update");
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_CONFIG as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            DeviceError::FailedSignalingUsedQueue(e)
        })
    }

    pub fn update_console_size(&mut self, cols: u16, rows: u16) {
        debug!("update_console_size: {} {}", cols, rows);
        self.config.update_console_size(cols, rows);

        for port_id in 0..self.ports.len() {
            if self.ports[port_id].console {
                self.send_control_tx_resize(port_id as u32, &VirtioConsoleResize { cols, rows })
            }
            self.signal_used_queue().unwrap_or_default();
        }
    }

    pub(crate) fn send_control_tx_data(&mut self, data: &[u8]) {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        let queue = &mut self.queues[CONTROL_RXQ_INDEX];

        if let Some(head) = queue.pop(mem) {
            if let Err(e) = mem.write_slice(data, head.addr) {
                log::error!("Failed to write to tq_queue: {}", e);
            }
            queue.add_used(mem, head.index, data.len() as u32);
        } else {
            log::error!("Failed to write to tx_queue: no space in queue");
        }
    }

    pub(crate) fn send_control_tx_cmd(&mut self, msg: &VirtioConsoleControl) {
        self.send_control_tx_data(msg.as_slice());
    }

    pub(crate) fn send_control_tx_resize(&mut self, port_id: u32, new_size: &VirtioConsoleResize) {
        let resize_cmd = VirtioConsoleControl {
            id: port_id,
            event: control_event::VIRTIO_CONSOLE_RESIZE,
            value: 0,
        };

        const SIZE_1: usize = size_of::<VirtioConsoleControl>();
        const SIZE_2: usize = size_of::<VirtioConsoleResize>();
        let mut data = [0u8; SIZE_1 + SIZE_2];
        data[..SIZE_1].copy_from_slice(resize_cmd.as_slice());
        data[SIZE_1..].copy_from_slice(new_size.as_slice());
        self.send_control_tx_data(data.as_slice());
    }

    pub(crate) fn process_control_rx(&mut self) -> bool {
        false
    }

    pub(crate) fn process_control_tx(&mut self) -> bool {
        macro_rules! get_mem {
            () => {
                match self.device_state {
                    DeviceState::Activated(ref mem) => mem,
                    // This should never happen, it's been already validated in the event handler.
                    DeviceState::Inactive => unreachable!(),
                }
            };
        }
        let mut used_any = false;

        let mut ports_to_resume = Vec::new();

        while let Some(head) = self.queues[CONTROL_TXQ_INDEX].pop(get_mem!()) {
            let mut cmd = VirtioConsoleControl::default();
            used_any = true;
            let read_result = get_mem!().read_slice(cmd.as_mut_slice(), head.addr);
            self.queues[CONTROL_TXQ_INDEX].add_used(get_mem!(), head.index, head.len);

            if let Err(e) = read_result {
                log::error!(
                    "Failed to read VirtioConsoleControl struct: {}, struct len = {}, head.len = {}",
                    e,
                    size_of::<VirtioConsoleControl>(),
                    head.len,
                );
                continue;
            }

            log::trace!("Read VirtioConsoleControl: {cmd:?}");
            match cmd.event {
                control_event::VIRTIO_CONSOLE_DEVICE_READY => {
                    log::debug!(
                        "Device is ready: initialization {}",
                        if cmd.value == 1 { "ok" } else { "failed" }
                    );

                    for port_id in 0..self.ports.len() {
                        self.send_control_tx_cmd(&VirtioConsoleControl {
                            id: port_id as u32,
                            event: VIRTIO_CONSOLE_PORT_ADD,
                            value: 0,
                        });
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_READY => {
                    if cmd.value != 1 {
                        log::error!("Port initialization failed: {:?}", cmd);
                        continue;
                    }
                    self.ports[cmd.id as usize].status = PortStatus::Ready { opened: false };

                    if self.ports[cmd.id as usize].console {
                        self.send_control_tx_cmd(&VirtioConsoleControl {
                            id: cmd.id,
                            event: VIRTIO_CONSOLE_CONSOLE_PORT,
                            value: 1,
                        });
                    } else {
                        // lets start with all ports open for now
                        self.send_control_tx_cmd(&VirtioConsoleControl {
                            id: cmd.id,
                            event: VIRTIO_CONSOLE_PORT_OPEN,
                            value: 1,
                        });
                    }

                    if !self.ports[cmd.id as usize].name.is_empty() {
                        let mut msg: Vec<u8> = Vec::new();

                        msg.extend_from_slice(
                            VirtioConsoleControl {
                                id: cmd.id,
                                event: VIRTIO_CONSOLE_PORT_NAME,
                                value: 1, // Unspecified/unused in the spec, lets use the same value as QEMU.
                            }
                                .as_slice(),
                        );

                        // The spec says the name shouldn't be NUL terminated.
                        // QEMU seems to NUL-terminate it, anyway.
                        // The guest kernel works either way, but we don't NUL-terminate it and follow
                        // the spec.
                        msg.extend(self.ports[cmd.id as usize].name.as_bytes());
                        self.send_control_tx_data(&msg)
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

                    if self.ports[cmd.id as usize].status == PortStatus::NotReady {
                        log::warn!("Driver signaled opened={} to port {} that was not ready, assuming the port is ready.",opened, cmd.id)
                    }
                    self.ports[cmd.id as usize].status = PortStatus::Ready { opened };

                    // There could be pending input for this port...
                    if opened {
                        ports_to_resume.push(cmd.id);
                    }
                }
                _ => log::warn!("Unknown console control event {:x}", cmd.event),
            }
        }

        for port_id in ports_to_resume {
            self.resume_rx(port_id as usize);
        }

        used_any
    }

    //TODO: split between event_handler and device, and have more specific callbacks for example: handle_port_hang_up
    pub(crate) fn handle_input(&mut self, event_set: &EventSet, port_id: usize) -> bool {
        let mut raise_irq = false;

        if !event_set
            .difference(EventSet::IN | EventSet::HANG_UP | EventSet::READ_HANG_UP)
            .is_empty()
        {
            warn!("console: input unexpected event {:?}", event_set);
        }

        match self.ports[port_id].status {
            PortStatus::NotReady => {
                log::trace!(
                    "Input event on port {port_id} but port is not ready: {:?}",
                    event_set
                );
                if event_set.contains(EventSet::IN) {
                    self.ports[port_id].pending_rx = true;
                }
                if event_set.intersects(EventSet::HANG_UP | EventSet::READ_HANG_UP) {
                    self.ports[port_id].pending_eof = true;
                }
            }
            PortStatus::Ready { opened: false } => {
                log::trace!(
                    "Input event on port {port_id} but port is closed: {:?}",
                    event_set
                );
            }
            PortStatus::Ready { opened: true } => {
                log::trace!("Event on opened port {port_id}");
                if event_set.contains(EventSet::IN) {
                    raise_irq |= self.process_rx(port_id);
                }

                if event_set.intersects(EventSet::HANG_UP | EventSet::READ_HANG_UP) {
                    self.ports[port_id].status = PortStatus::Ready { opened: false };
                    self.send_control_tx_cmd(&VirtioConsoleControl {
                        id: port_id as u32,
                        event: VIRTIO_CONSOLE_PORT_OPEN,
                        value: 0,
                    });
                    // why not process tx here?
                    raise_irq = true;
                }
            }
        }

        raise_irq
    }

    pub(crate) fn resume_rx(&mut self, port_id: usize) -> bool {
        let mut raise_irq = false;

        if let PortStatus::Ready { opened: true } = self.ports[port_id].status {
            if self.ports[port_id].pending_rx {
                log::trace!("Resuming rx for port {port_id}");
                raise_irq |= self.process_rx(port_id);
            }

            if self.ports[port_id].pending_eof {
                log::trace!("Resuming rx, got EOF for port {port_id}");
                self.send_control_tx_cmd(&VirtioConsoleControl {
                    id: port_id as u32,
                    event: VIRTIO_CONSOLE_PORT_OPEN,
                    value: 0,
                });
                self.ports[port_id].pending_eof = false;
                raise_irq |= self.process_control_tx();
            }
        }

        raise_irq
    }

    pub(crate) fn process_rx(&mut self, port_id: usize) -> bool {
        //debug!("console: RXQ queue event");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        self.ports[port_id].pending_rx = true;

        let queue = &mut self.queues[port_id_to_queue_idx(QueueDirection::Rx, port_id)];
        let mut used_any = false;
        while let Some(head) = queue.pop(mem) {
            let result =
                self.ports[port_id].read_until_would_block(mem, head.addr, head.len as usize);
            match result {
                Ok(0) => {
                    self.ports[port_id].pending_rx = false;
                    queue.undo_pop();
                    break;
                }
                Err(GuestMemoryError::IOError(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.ports[port_id].pending_rx = false;
                    queue.undo_pop();
                    break;
                }
                Ok(len) => {
                    log::trace!("Rx {len} bytes to port {port_id}");
                    queue.add_used(mem, head.index, len as u32);
                    used_any = true;
                }
                Err(e) => {
                    log::error!("Failed to process_rx: {e:?}");
                }
            }
        }

        used_any
    }

    pub(crate) fn process_tx(&mut self, port_id: usize) -> bool {
        //debug!("console: TXQ queue event");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        // This won't be needed once we support multiport
        if !self.configured {
            self.configured = true;
            self.signal_config_update().unwrap();
        }

        let queue = &mut self.queues[port_id_to_queue_idx(QueueDirection::Tx, port_id)];
        let mut used_any = false;
        while let Some(head) = queue.pop(mem) {
            // TODO: figure out what to do if the port doesn't have output
            let output = &mut self.ports[port_id].output.as_mut().unwrap();
            let num_bytes = mem.write_to(head.addr, output, head.len as usize).unwrap();
            log::trace!("Tx from port {port_id} {num_bytes} bytes");
            output.flush().unwrap();

            queue.add_used(mem, head.index, head.len);
            used_any = true;
        }

        used_any
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
        &self.interrupt_evt
    }

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
    }

    fn set_irq_line(&mut self, irq: u32) {
        self.irq_line = Some(irq);
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
            error!("Cannot write to activate_evt",);
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
