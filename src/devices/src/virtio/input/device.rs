use std::cmp::max;
use std::thread::JoinHandle;

use log::{debug, error};
use utils::eventfd::EventFd;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap};

use super::super::{ActivateError, ActivateResult, DeviceState, Queue as VirtQueue, VirtioDevice};
use super::worker::InputWorker;
use super::{defs, defs::uapi, InputError};
use crate::legacy::IrqChip;

use crate::virtio::InterruptTransport;
use krun_input::{
    InputAbsInfo, InputBackendWrapper, InputConfigImpl, InputConfigInstance, InputDeviceIds,
};

// Simple struct for VirtIO input device configuration
#[derive(Debug, Clone, Copy)]
pub struct virtio_input_config {
    pub select: u8,
    pub subsel: u8,
    pub size: u8,
    pub reserved: [u8; 5],
    pub payload: [u8; 128],
}

/*
union VirtioInputConfig {
    cfg: virtio_input_config,
    raw_bytes: virtio_input_config,
}*/

unsafe impl ByteValued for virtio_input_config {}

impl virtio_input_config {
    pub fn new() -> Self {
        Self {
            select: 0,
            subsel: 0,
            size: 0,
            reserved: [0u8; 5],
            payload: [0u8; 128],
        }
    }
}

// Simple struct for device IDs
#[derive(Debug, Clone)]
pub struct virtio_input_device_ids {
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

impl virtio_input_device_ids {
    pub fn new(bustype: u16, product: u16, vendor: u16, version: u16) -> Self {
        Self {
            bustype,
            vendor,
            product,
            version,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

// Simple struct for absolute axis info
#[derive(Debug, Clone)]
pub struct virtio_input_absinfo {
    pub min: u32,
    pub max: u32,
    pub fuzz: u32,
    pub flat: u32,
    pub res: u32,
}

impl virtio_input_absinfo {
    pub fn new(min: u32, max: u32, fuzz: u32, flat: u32) -> Self {
        Self {
            min,
            max,
            fuzz,
            flat,
            res: 0,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

// Request queue.
pub(crate) const REQ_INDEX: usize = 0;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

const EV_SYN: u8 = 0x00;
const EV_KEY: u8 = 0x01;
const EV_REL: u8 = 0x02;
const EV_ABS: u8 = 0x03;
const EV_MSC: u8 = 0x04;
const EV_SW: u8 = 0x05;

const SYN_REPORT: u8 = 0x00;

pub struct Input {
    queues: Vec<VirtQueue>,
    queue_events: Vec<EventFd>,
    avail_features: u64,
    acked_features: u64,
    device_state: DeviceState,
    cfg: virtio_input_config,
    backend: InputBackendWrapper<'static>,
    config_instance: InputConfigInstance,

    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
}

impl Input {
    pub(crate) fn with_queues(
        queues: Vec<VirtQueue>,
        backend_wrapper: InputBackendWrapper<'static>,
    ) -> super::Result<Input> {
        debug!("input: with_queues");
        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events
                .push(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(InputError::EventFd)?);
        }

        // Create initial config with default values
        let cfg = virtio_input_config::new();

        Ok(Input {
            queues,
            queue_events,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            backend: backend_wrapper,
            device_state: DeviceState::Inactive,
            cfg,
            config_instance: backend_wrapper.create_config_instance().expect("TODO"),
            worker_thread: None,
            worker_stopfd: EventFd::new(libc::EFD_NONBLOCK).map_err(InputError::EventFd)?,
        })
    }

    pub fn new(backend_wrapper: InputBackendWrapper<'static>) -> super::Result<Input> {
        let queues: Vec<VirtQueue> = defs::QUEUE_SIZES
            .iter()
            .map(|&max_size| VirtQueue::new(max_size))
            .collect();
        Self::with_queues(queues, backend_wrapper)
    }

    pub fn id(&self) -> &str {
        defs::INPUT_DEV_ID
    }

    fn update_config(&mut self, select: u8, subsel: u8) -> virtio_input_config {
        use crate::virtio::input::defs::config_select;

        self.cfg.select = select;
        self.cfg.subsel = subsel;

        match select {
            config_select::VIRTIO_INPUT_CFG_ID_NAME => {
                if let Ok(len) = self
                    .config_instance
                    .write_device_name(&mut self.cfg.payload)
                {
                    self.cfg.size = len as u8;
                }
            }
            config_select::VIRTIO_INPUT_CFG_ID_SERIAL => {
                if let Ok(len) = self
                    .config_instance
                    .write_device_serial(&mut self.cfg.payload)
                {
                    self.cfg.size = len as u8;
                }
            }
            config_select::VIRTIO_INPUT_CFG_ID_DEVIDS => {
                let mut device_ids = InputDeviceIds {
                    bustype: 0,
                    vendor: 0,
                    product: 0,
                    version: 0,
                };
                if self
                    .config_instance
                    .write_device_ids(&mut device_ids)
                    .is_ok()
                {
                    // Convert to byte representation for VirtIO config
                    let device_ids_bytes = unsafe {
                        std::slice::from_raw_parts(
                            &device_ids as *const _ as *const u8,
                            std::mem::size_of::<InputDeviceIds>(),
                        )
                    };
                    self.cfg.payload[..device_ids_bytes.len()].copy_from_slice(device_ids_bytes);
                    self.cfg.size = device_ids_bytes.len() as u8;
                }
            }
            config_select::VIRTIO_INPUT_CFG_PROP_BITS => {
                if let Ok(len) = self
                    .config_instance
                    .write_property_bits(&mut self.cfg.payload)
                {
                    // Find the minimum size needed by finding the last non-zero byte
                    self.cfg.size = self.cfg.payload[..len]
                        .iter()
                        .rposition(|&v| v != 0)
                        .map_or(0, |i| i + 1) as u8;
                }
            }
            config_select::VIRTIO_INPUT_CFG_EV_BITS => {
                if let Ok(len) = self
                    .config_instance
                    .write_event_bits(subsel as u16, &mut self.cfg.payload)
                {
                    // Find the minimum size needed by finding the last non-zero byte
                    self.cfg.size = self.cfg.payload[..len]
                        .iter()
                        .rposition(|&v| v != 0)
                        .map_or(0, |i| i + 1) as u8;
                }
            }
            config_select::VIRTIO_INPUT_CFG_ABS_INFO => {
                let mut abs_info = InputAbsInfo {
                    min: 0,
                    max: 0,
                    fuzz: 0,
                    flat: 0,
                    res: 0,
                };
                if self
                    .config_instance
                    .write_abs_info(subsel as u16, &mut abs_info)
                    .is_ok()
                {
                    // Convert to byte representation for VirtIO config
                    let abs_info_bytes = unsafe {
                        std::slice::from_raw_parts(
                            &abs_info as *const _ as *const u8,
                            std::mem::size_of::<InputAbsInfo>(),
                        )
                    };
                    self.cfg.payload[..abs_info_bytes.len()].copy_from_slice(abs_info_bytes);
                    self.cfg.size = abs_info_bytes.len() as u8;
                }
            }
            config_select::VIRTIO_INPUT_CFG_UNSET => {
                // No action required per the spec
            }
            _ => {
                warn!("Unsupported virtio input config selection: {}", select);
            }
        }
        dbg!(self.cfg);

        self.cfg
    }
}

impl VirtioDevice for Input {
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
        uapi::VIRTIO_ID_INPUT
    }

    fn device_name(&self) -> &str {
        "input"
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

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let cfg = self.cfg.as_slice();
        let cfg_len = cfg.len();
        let offset = offset as usize;
        let data_len = data.len();

        let read_len = std::cmp::min(cfg_len - offset, data_len);
        if read_len > 0 {
            data[..read_len].copy_from_slice(&cfg[offset..offset + read_len]);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        debug!("input: write_config: offset={offset}");
        let old_select = self.cfg.select;
        let old_subsel = self.cfg.subsel;
        let offset = offset as usize;

        // TODO: don't panic here, on out-of-bounds
        // We only allow overriding the first 2 bytes - the select and subsel!
        if offset == 0 {
            if data.len() >= 1 {
                self.cfg.select = data[0];
            }
            if data.len() >= 2 {
                self.cfg.subsel = data[1];
            }
        } else if offset == 1 {
            if data.len() >= 1 {
                self.cfg.select = data[0];
            }
        }

        /*let cfg_slice = self.cfg.as_bytes();
        // FIXME make this more robust
        cfg_slice.write_slice(data, offset).unwrap();*/

        //cfg_slice[offset..offset + data.len()].copy_from_slice(&data);
        //dbg!(&cfg_slice[offset..offset + data.len()]);
        dbg!(old_select, self.cfg.select, old_subsel, self.cfg.subsel, offset, data);
        if old_select != self.cfg.select || old_subsel != self.cfg.subsel {
            // Build config using the backend
            self.cfg = self.update_config(self.cfg.select, self.cfg.subsel);
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> ActivateResult {
        if self.queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                self.queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        let worker = InputWorker::new(
            self.queues[0].clone(), // Event queue (device -> guest)
            self.queue_events[0].try_clone().unwrap(),
            self.queues[1].clone(), // Status queue (guest -> device)
            self.queue_events[1].try_clone().unwrap(),
            interrupt.clone(),
            mem.clone(),
            self.backend,
            self.worker_stopfd.try_clone().unwrap(),
        );

        self.worker_thread = Some(worker.run());
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        if let Some(worker_thread) = self.worker_thread.take() {
            self.worker_stopfd.write(1).unwrap();

            match worker_thread.join() {
                Ok(()) => debug!("Input worker thread stopped"),
                Err(e) => {
                    error!("Failed to join worker thread: {e:?}");
                }
            }
        }
        true
    }
}
