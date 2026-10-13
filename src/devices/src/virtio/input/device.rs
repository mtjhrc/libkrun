use std::cmp;
use std::io::Write;
use std::thread::JoinHandle;

use log::{debug, error};
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use vm_memory::GuestMemoryMmap;

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, QueueConfig, VirtioDevice,
};
use super::worker::InputWorker;
use super::{InputError, defs, defs::uapi};

use crate::virtio::InterruptTransport;
use crate::virtio::input::defs::config_select;
use krun_input::{InputAbsInfo, InputDeviceIds, InputEventsImpl, InputQueryConfig};

#[derive(Clone, Copy)]
union InputConfig {
    bytes: [u8; size_of::<InputConfigRepr>()],
    repr: InputConfigRepr,
}

impl InputConfig {
    pub fn new() -> Self {
        Self {
            bytes: [0u8; size_of::<Self>()],
        }
    }

    pub fn select(&self) -> u8 {
        unsafe { self.repr.select }
    }

    pub fn subsel(&self) -> u8 {
        unsafe { self.repr.subsel }
    }

    pub fn bytes(&self) -> &[u8; size_of::<Self>()] {
        unsafe { &self.bytes }
    }

    pub fn invalidate(&mut self) {
        self.repr.size = 0;
        unsafe {
            self.repr.payload.bytes.fill(0);
        }
    }

    fn update_select(&mut self, cfg: &dyn InputQueryConfig, select: u8, subsel: u8) {
        if select == self.select() && subsel == self.subsel() {
            return;
        }

        self.repr.select = select;
        self.repr.subsel = subsel;
        self.invalidate();

        let result = match select {
            config_select::VIRTIO_INPUT_CFG_UNSET => return,
            config_select::VIRTIO_INPUT_CFG_ID_NAME => {
                cfg.query_device_name(unsafe { &mut self.repr.payload.bytes })
            }
            config_select::VIRTIO_INPUT_CFG_ID_SERIAL => {
                cfg.query_serial_name(unsafe { &mut self.repr.payload.bytes })
            }
            config_select::VIRTIO_INPUT_CFG_ID_DEVIDS => cfg
                .query_device_ids(unsafe { &mut self.repr.payload.ids })
                .map(|_| size_of::<InputDeviceIds>() as u8),
            config_select::VIRTIO_INPUT_CFG_PROP_BITS => {
                cfg.query_properties(unsafe { &mut self.repr.payload.bytes })
            }
            config_select::VIRTIO_INPUT_CFG_EV_BITS => {
                cfg.query_event_capabilities(subsel, unsafe { &mut self.repr.payload.bytes })
            }
            config_select::VIRTIO_INPUT_CFG_ABS_INFO => cfg
                .query_abs_info(subsel, unsafe { &mut self.repr.payload.abs })
                .map(|_| size_of::<InputAbsInfo>() as u8),
            select => {
                error!("Invalid config selection select = {select}");
                self.invalidate();
                return;
            }
        };

        match result {
            Ok(len) => {
                self.repr.size = len;
            }
            // The driver writes select and subsel separately, so a failed
            // query can pair a new select with a stale subsel. Keep both, so
            // the write that follows queries the intended pair.
            Err(e) => {
                debug!("Failed to query config select={select}, subsel={subsel}: {e:?}");
                self.invalidate();
            }
        };
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct InputConfigRepr {
    select: u8,
    subsel: u8,
    size: u8,
    reserved: [u8; 5],
    payload: ConfigPayload,
}

#[derive(Clone, Copy)]
#[repr(C)]
union ConfigPayload {
    bytes: [u8; 128],
    abs: InputAbsInfo,
    ids: InputDeviceIds,
}

/// VirtIO Input device state
pub struct Input {
    avail_features: u64,
    acked_features: u64,
    device_state: DeviceState,
    cfg: InputConfig,
    config_backend: Box<dyn InputQueryConfig>,
    events_backend: Option<Box<dyn InputEventsImpl>>,

    worker_thread: Option<JoinHandle<Box<dyn InputEventsImpl>>>,
    worker_stopfd: EventFd,
}

impl Input {
    pub fn new(
        config_backend: Box<dyn InputQueryConfig>,
        events_backend: Box<dyn InputEventsImpl>,
    ) -> super::Result<Input> {
        Ok(Input {
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            events_backend: Some(events_backend),
            config_backend,
            device_state: DeviceState::Inactive,
            cfg: InputConfig::new(),
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(InputError::EventFd)?,
        })
    }

    pub fn id(&self) -> &str {
        defs::INPUT_DEV_ID
    }

    fn stop_worker(&mut self) -> bool {
        if let Some(worker_thread) = self.worker_thread.take() {
            if let Err(e) = self.worker_stopfd.write(1) {
                error!("Failed to stop input worker: {e}");
            }

            match worker_thread.join() {
                Ok(backend) => {
                    self.events_backend = Some(backend);
                    debug!("Input worker thread stopped");
                }
                Err(e) => {
                    error!("Failed to join input worker: {e:?}");
                    return false;
                }
            }
            let _ = self.worker_stopfd.read();
        }
        true
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        self.stop_worker();
    }
}

const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1;

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

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let cfg_slice = self.cfg.bytes();
        let cfg_len = cfg_slice.len() as u64;

        if offset >= cfg_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&cfg_slice[offset as usize..cmp::min(end, cfg_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let len = data.len() as u64;

        let mut select = self.cfg.select();
        let mut subsel = self.cfg.subsel();

        if offset == 0 && len >= 1 {
            select = data[0];
            if len >= 2 {
                subsel = data[1]
            }
        } else if offset == 1 && len >= 1 {
            subsel = data[0]
        }

        self.cfg
            .update_select(self.config_backend.as_ref(), select, subsel);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        let [event_q, status_q]: [_; defs::NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!(
                "Cannot perform activate. Expected {} queue(s)",
                defs::NUM_QUEUES
            );
            ActivateError::BadActivate
        })?;

        let worker = InputWorker::new(
            event_q,
            status_q,
            interrupt.clone(),
            mem.clone(),
            self.events_backend
                .take()
                .ok_or(ActivateError::BadActivate)?,
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
        let stopped = self.stop_worker();
        self.device_state = DeviceState::Inactive;
        stopped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::Queue;
    use krun_input::{InputBackendError, InputEvent, InputEventType};
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::time::Duration;
    use vm_memory::GuestAddress;

    struct TestConfig;

    impl InputQueryConfig for TestConfig {
        fn query_device_name(&self, name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
            name_buf[..5].copy_from_slice(b"input");
            Ok(5)
        }

        fn query_serial_name(&self, _name_buf: &mut [u8]) -> Result<u8, InputBackendError> {
            Err(InputBackendError::MethodNotSupported)
        }

        fn query_device_ids(&self, ids: &mut InputDeviceIds) -> Result<(), InputBackendError> {
            *ids = InputDeviceIds {
                bustype: 3,
                vendor: 0x1af4,
                product: 18,
                version: 1,
            };
            Ok(())
        }

        fn query_event_capabilities(
            &self,
            event_type: u8,
            bitmap_buf: &mut [u8],
        ) -> Result<u8, InputBackendError> {
            bitmap_buf[0] = event_type;
            Ok(1)
        }

        fn query_abs_info(
            &self,
            abs_axis: u8,
            abs_info: &mut InputAbsInfo,
        ) -> Result<(), InputBackendError> {
            if !matches!(abs_axis, 0 | 7) {
                return Err(InputBackendError::InvalidParam);
            }
            *abs_info = InputAbsInfo {
                min: -100,
                max: 100,
                fuzz: 2,
                flat: 3,
                res: abs_axis.into(),
            };
            Ok(())
        }

        fn query_properties(&self, properties: &mut [u8]) -> Result<u8, InputBackendError> {
            properties[0] = 1;
            Ok(1)
        }
    }

    struct TestEvents {
        fd: EventFd,
        ready: Sender<()>,
        fail_ready: AtomicBool,
        drops: Arc<AtomicUsize>,
    }

    impl InputEventsImpl for TestEvents {
        fn get_read_notify_fd(&self) -> Result<BorrowedFd<'_>, InputBackendError> {
            self.ready.send(()).unwrap();
            if self.fail_ready.swap(false, Ordering::SeqCst) {
                Err(InputBackendError::InternalError)
            } else {
                Ok(unsafe { BorrowedFd::borrow_raw(self.fd.as_raw_fd()) })
            }
        }

        fn next_event(&mut self) -> Result<Option<InputEvent>, InputBackendError> {
            Ok(None)
        }
    }

    impl Drop for TestEvents {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn test_input(fail_ready: bool) -> (Input, Receiver<()>, Arc<AtomicUsize>) {
        let (ready, rx) = mpsc::channel();
        let drops = Arc::new(AtomicUsize::new(0));
        let events = TestEvents {
            fd: EventFd::new(EFD_NONBLOCK).unwrap(),
            ready,
            fail_ready: AtomicBool::new(fail_ready),
            drops: drops.clone(),
        };
        let input = Input::new(Box::new(TestConfig), Box::new(events)).unwrap();
        (input, rx, drops)
    }

    fn activate(input: &mut Input) {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let interrupt =
            InterruptTransport::new(DummyIrqChip::new().into(), "input-test".into()).unwrap();
        let queues = defs::QUEUE_CONFIG
            .iter()
            .map(|cfg| {
                DeviceQueue::new(
                    Queue::new(cfg.size),
                    Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                )
            })
            .collect();
        input.activate(mem, interrupt, queues).unwrap();
    }

    #[test]
    fn config_queries_report_full_payload_and_invalidate_payload_on_error() {
        let (mut input, _, _) = test_input(false);
        input.write_config(0, &[config_select::VIRTIO_INPUT_CFG_ID_NAME]);
        let mut config = [0; size_of::<InputConfigRepr>()];
        input.read_config(0, &mut config);
        assert_eq!(config[2], 5);
        assert_eq!(&config[8..13], b"input");

        input.write_config(0, &[config_select::VIRTIO_INPUT_CFG_ABS_INFO, 7]);
        input.read_config(0, &mut config);
        assert_eq!(config[2] as usize, size_of::<InputAbsInfo>());
        let values = config[8..28]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|bytes| i32::from_ne_bytes(*bytes))
            .collect::<Vec<_>>();
        assert_eq!(values, [-100, 100, 2, 3, 7]);

        input.write_config(0, &[config_select::VIRTIO_INPUT_CFG_ID_SERIAL]);
        input.read_config(0, &mut config);
        assert_eq!(
            &config[..3],
            &[config_select::VIRTIO_INPUT_CFG_ID_SERIAL, 7, 0]
        );
        assert!(config[8..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn separate_selection_writes_recover_from_an_unsupported_intermediate_axis() {
        for event_type in [InputEventType::Abs, InputEventType::Snd] {
            let (mut input, _, _) = test_input(false);
            input.write_config(0, &[config_select::VIRTIO_INPUT_CFG_EV_BITS]);
            input.write_config(1, &[event_type as u8]);
            input.write_config(0, &[config_select::VIRTIO_INPUT_CFG_ABS_INFO]);
            let mut config = [0; size_of::<InputConfigRepr>()];
            input.read_config(0, &mut config);
            assert_eq!(
                &config[..3],
                &[
                    config_select::VIRTIO_INPUT_CFG_ABS_INFO,
                    event_type as u8,
                    0
                ]
            );
            assert!(config[8..].iter().all(|byte| *byte == 0));

            input.write_config(1, &[0]);
            input.read_config(0, &mut config);
            assert_eq!(
                &config[..3],
                &[
                    config_select::VIRTIO_INPUT_CFG_ABS_INFO,
                    0,
                    size_of::<InputAbsInfo>() as u8,
                ]
            );
            let values = config[8..28]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|bytes| i32::from_ne_bytes(*bytes))
                .collect::<Vec<_>>();
            assert_eq!(values, [-100, 100, 2, 3, 0]);
        }
    }

    #[test]
    fn reset_returns_owned_backend_for_reactivation() {
        let (mut input, ready, drops) = test_input(false);
        for _ in 0..2 {
            activate(&mut input);
            ready.recv_timeout(Duration::from_secs(1)).unwrap();
            assert!(input.is_activated());
            assert!(input.reset());
            assert!(!input.is_activated());
            assert_eq!(drops.load(Ordering::SeqCst), 0);
        }
        drop(input);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn startup_error_preserves_backend_and_drop_joins_active_worker() {
        let (mut input, ready, drops) = test_input(true);
        activate(&mut input);
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(input.reset());
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        activate(&mut input);
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(input);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
