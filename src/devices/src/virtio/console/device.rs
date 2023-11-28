use std::cmp;
use std::collections::VecDeque;
use std::io;
use std::io::Write;
use std::mem::size_of;
use std::ops::DerefMut;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use libc::TIOCGWINSZ;
use utils::eventfd::EventFd;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap, VolatileMemory};

use super::super::super::legacy::ReadableFd;
use super::super::{
    ActivateError, ActivateResult, ConsoleError, DeviceState, Queue as VirtQueue, VirtioDevice,
    VIRTIO_MMIO_INT_CONFIG, VIRTIO_MMIO_INT_VRING,
};
use super::{defs, defs::control_event, defs::uapi};
use crate::legacy::Gic;
use crate::virtio::console::defs::control_event::{
    VIRTIO_CONSOLE_CONSOLE_PORT, VIRTIO_CONSOLE_PORT_ADD,
};
use crate::virtio::console::defs::NUM_PORTS;
use crate::Error as DeviceError;

pub(crate) const RXQ_INDEX: usize = 0;
pub(crate) const TXQ_INDEX: usize = 1;

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

impl VirtioConsoleConfig {
    pub fn new(cols: u16, rows: u16) -> Self {
        VirtioConsoleConfig {
            cols,
            rows,
            max_nr_ports: NUM_PORTS as u32,
            emerg_wr: 0u32,
        }
    }

    pub fn update_console_size(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum PortStatus {
    NotReady,
    Ready { opened: bool },
}

pub struct Console {
    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,
    pub(crate) port_statuses: Vec<PortStatus>,
    pub(crate) cmd_queue: VecDeque<VirtioConsoleControl>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    pub(crate) interrupt_evt: EventFd,
    pub(crate) activate_evt: EventFd,
    pub(crate) sigwinch_evt: EventFd,
    pub(crate) device_state: DeviceState,
    pub(crate) in_buffer: VecDeque<u8>,
    config: VirtioConsoleConfig,
    pub(crate) input: Box<dyn ReadableFd + Send>,
    output: Box<dyn io::Write + Send>,
    configured: bool,
    pub(crate) interactive: bool,
    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,
}

impl Console {
    pub(crate) fn with_queues(
        input: Box<dyn ReadableFd + Send>,
        output: Box<dyn io::Write + Send>,
        queues: Vec<VirtQueue>,
    ) -> super::Result<Console> {
        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events
                .push(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(ConsoleError::EventFd)?);
        }

        let (cols, rows) = get_win_size();
        let config = VirtioConsoleConfig::new(cols, rows);

        Ok(Console {
            queues,
            queue_events,
            port_statuses: vec![PortStatus::NotReady; NUM_PORTS],
            cmd_queue: Default::default(),
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
            in_buffer: VecDeque::new(),
            config,
            input,
            output,
            configured: false,
            interactive: true,
            intc: None,
            irq_line: None,
        })
    }

    pub fn new(
        input: Box<dyn ReadableFd + Send>,
        output: Box<dyn io::Write + Send>,
    ) -> super::Result<Console> {
        let queues: Vec<VirtQueue> = defs::QUEUE_SIZES
            .iter()
            .map(|&max_size| VirtQueue::new(max_size))
            .collect();
        Self::with_queues(input, output, queues)
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
        self.signal_config_update().unwrap();
    }

    pub(crate) fn process_control_rx(&mut self) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        let queue = &mut self.queues[CONTROL_RXQ_INDEX];
        let mut used_any = false;

        while let Some(cmd) = self.cmd_queue.front() {
            if let Some(head) = queue.pop(mem) {
                if let Err(e) = mem.write_slice(cmd.as_slice(), head.addr) {
                    log::error!("Failed to write VirtioConsoleControl cmd: {}", e);
                    continue;
                }
                used_any = true;
                queue.add_used(mem, head.index, head.len);
                log::error!("Wrote {cmd:?} to guest");
                self.cmd_queue.pop_front();
            } else {
                log::error!("Failed to write {cmd:?} to guest");
            }
        }

        used_any
    }

    pub(crate) fn process_control_tx(&mut self) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        let queue = &mut self.queues[CONTROL_TXQ_INDEX];
        let mut used_any = false;

        while let Some(head) = queue.pop(mem) {
            let mut cmd = VirtioConsoleControl::default();
            used_any = true;
            let read_result = mem.read_slice(cmd.as_mut_slice(), head.addr);
            queue.add_used(mem, head.index, head.len);

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
                    self.cmd_queue.push_back(VirtioConsoleControl {
                        id: 0,
                        event: VIRTIO_CONSOLE_PORT_ADD,
                        value: 1,
                    });
                }
                control_event::VIRTIO_CONSOLE_PORT_READY => {
                    if cmd.value != 1 {
                        log::error!("Port initialization failed: {:?}", cmd);
                        continue;
                    }
                    self.port_statuses[cmd.id as usize] = PortStatus::Ready { opened: false };
                    if cmd.id == 0 {
                        //TODO: unhardcode console port
                        self.cmd_queue.push_back(VirtioConsoleControl {
                            id: 0,
                            event: VIRTIO_CONSOLE_CONSOLE_PORT,
                            value: 1,
                        });
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

                    if self.port_statuses[cmd.id as usize] == PortStatus::NotReady {
                        log::warn!("Driver signaled opened={} to port {} that was not ready, assuming the port is ready.",opened, cmd.id)
                    }
                    self.port_statuses[cmd.id as usize] = PortStatus::Ready { opened };
                }
                _ => log::warn!("Unknown console control event {:x}", cmd.event),
            }
        }

        if !self.cmd_queue.is_empty() {
            let control_processed = self.process_control_rx();
            if !control_processed {
                log::trace!("process_control_rx doesn't need interupt?");
            }
            used_any |= control_processed;
        }

        used_any
    }

    pub(crate) fn process_rx(&mut self) -> bool {
        //debug!("console: RXQ queue event");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        if self.in_buffer.is_empty() {
            return false;
        }

        let queue = &mut self.queues[RXQ_INDEX];
        let mut used_any = false;
        while let Some(head) = queue.pop(mem) {
            let len = cmp::min(head.len, self.in_buffer.len() as u32);
            let source_slice = self.in_buffer.drain(..len as usize).collect::<Vec<u8>>();
            if let Err(e) = mem.write_slice(&source_slice[..], head.addr) {
                error!("Failed to write slice: {:?}", e);
                queue.go_to_previous_position();
                break;
            }

            queue.add_used(mem, head.index, len);
            used_any = true;

            if self.in_buffer.is_empty() {
                break;
            }
        }

        used_any
    }

    pub(crate) fn process_tx(&mut self) -> bool {
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

        let queue = &mut self.queues[TXQ_INDEX];
        let mut used_any = false;
        while let Some(head) = queue.pop(mem) {
            //let mut out = self.output.lock().unwrap();
            mem.write_to(head.addr, &mut self.output.deref_mut(), head.len as usize)
                .unwrap();
            self.output.flush().unwrap();

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
        if self.queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                self.queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

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
