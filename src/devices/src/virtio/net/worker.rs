use crate::virtio::net::backend::ConnectError;
#[cfg(target_os = "linux")]
use crate::virtio::net::tap::Tap;
use crate::virtio::net::unixgram::Unixgram;
use crate::virtio::net::unixstream::Unixstream;
use crate::virtio::net::{RX_INDEX, TX_INDEX};
use crate::virtio::{InterruptTransport, Queue};

use super::backend::{NetBackend, ReadError, WriteError};
use super::device::VirtioNetBackend;

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::thread;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

pub struct NetWorker {
    queue_evts: Vec<EventFd>,
    backend: Box<dyn NetBackend + Send>,
}

impl NetWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        _vnet_features: u64,
        include_vnet_header: bool,
        cfg_backend: VirtioNetBackend,
    ) -> Result<Self, ConnectError> {
        // Extract TX and RX queues
        let mut queues = queues;
        let rx_queue = queues.remove(RX_INDEX);
        let tx_queue = queues.remove(0); // TX is now at index 0 after removing RX

        let backend: Box<dyn NetBackend + Send> = match cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) => {
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixstream::new(
                    owned_fd,
                    include_vnet_header,
                    tx_queue,
                    rx_queue,
                    mem,
                    interrupt,
                ))
            }
            VirtioNetBackend::UnixstreamPath(path) => Box::new(Unixstream::open(
                path,
                include_vnet_header,
                tx_queue,
                rx_queue,
                mem,
                interrupt,
            )?),
            VirtioNetBackend::UnixgramFd(fd) => {
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixgram::new(
                    owned_fd,
                    include_vnet_header,
                    tx_queue,
                    rx_queue,
                    mem,
                    interrupt,
                ))
            }
            VirtioNetBackend::UnixgramPath(path, vfkit_magic) => Box::new(Unixgram::open(
                path,
                vfkit_magic,
                include_vnet_header,
                tx_queue,
                rx_queue,
                mem,
                interrupt,
            )?),
            #[cfg(target_os = "linux")]
            VirtioNetBackend::Tap(tap_name) => Box::new(Tap::new(
                tap_name,
                _vnet_features,
                tx_queue,
                rx_queue,
                mem,
                interrupt,
            )?),
        };

        Ok(Self { queue_evts, backend })
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("virtio-net worker".into())
            .spawn(|| self.work())
            .unwrap();
    }

    fn work(mut self) {
        log::info!("virtio-net worker starting");
        let virtq_rx_ev_fd = self.queue_evts[RX_INDEX].as_raw_fd();
        let virtq_tx_ev_fd = self.queue_evts[TX_INDEX].as_raw_fd();
        let backend_socket = self.backend.raw_socket_fd();

        let epoll = Epoll::new().unwrap();

        if let Err(e) = epoll.ctl(
            ControlOperation::Add,
            virtq_rx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_rx_ev_fd as u64),
        ) {
            log::error!("Failed to add rx_ev fd {} to epoll: {:?}", virtq_rx_ev_fd, e);
        }
        if let Err(e) = epoll.ctl(
            ControlOperation::Add,
            virtq_tx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_tx_ev_fd as u64),
        ) {
            log::error!("Failed to add tx_ev fd {} to epoll: {:?}", virtq_tx_ev_fd, e);
        }
        if let Err(e) = epoll.ctl(
            ControlOperation::Add,
            backend_socket,
            &EpollEvent::new(
                // TODO: Switch back to EDGE_TRIGGERED once the implementation is verified
                EventSet::IN | EventSet::OUT | EventSet::READ_HANG_UP,
                backend_socket as u64,
            ),
        ) {
            log::error!("Failed to add backend fd {} to epoll: {:?}", backend_socket, e);
        }

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        log::trace!("virtio-net epoll event: fd={} event_set={:?}", source, event_set);

                        // Match by source fd first, then check event flags
                        if source == virtq_rx_ev_fd && event_set.contains(EventSet::IN) {
                            log::trace!("virtio-net: rx queue event");
                            self.process_rx_queue_event();
                        } else if source == virtq_tx_ev_fd && event_set.contains(EventSet::IN) {
                            log::trace!("virtio-net: tx queue event");
                            self.process_tx_queue_event();
                        } else if source == backend_socket {
                            if event_set.contains(EventSet::HANG_UP)
                                || event_set.contains(EventSet::READ_HANG_UP)
                            {
                                log::error!("Got {event_set:?} on backend fd, virtio-net will stop working");
                                eprintln!("LIBKRUN VIRTIO-NET FATAL: Backend process seems to have quit or crashed! Networking is now disabled!");
                            } else {
                                if event_set.contains(EventSet::IN) {
                                    self.process_rx();
                                }

                                if event_set.contains(EventSet::OUT) {
                                    self.process_tx();
                                }
                            }
                        } else {
                            log::warn!(
                                "Received unknown event: {event_set:?} from fd: {source:?}"
                            );
                        }
                    }
                }
                Err(e) => {
                    debug!("virtio-net: failed to consume epoll event: {e}");
                }
            }
        }
    }

    fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[RX_INDEX].read() {
            log::error!("Failed to get rx event from queue: {e:?}");
        }
        self.process_rx();
    }

    fn process_tx_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[TX_INDEX].read() {
            log::error!("Failed to get tx queue event from queue: {e:?}");
        }
        self.process_tx();
    }

    fn process_rx(&mut self) {
        match self.backend.recv() {
            Ok(()) => {}
            Err(ReadError::ProcessNotRunning) => {
                log::error!("RX error: backend process not running");
            }
            Err(ReadError::Internal(e)) => {
                log::error!("RX error: {e:?}");
            }
        }
    }

    fn process_tx(&mut self) {
        match self.backend.send() {
            Ok(()) => {}
            Err(WriteError::ProcessNotRunning) => {
                log::error!("TX error: backend process not running");
            }
            Err(WriteError::Internal(e)) => {
                log::error!("TX error: {e:?}");
            }
        }
    }
}
