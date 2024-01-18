use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;


use crate::virtio::console::device::{CONTROL_RXQ_INDEX, CONTROL_TXQ_INDEX};
use crate::virtio::console::port_queue_mapping::{queue_idx_to_port_id, QueueDirection};
use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use super::device::{get_win_size, Console};
use crate::virtio::device::VirtioDevice;

impl Console {
    pub(crate) fn read_queue_event(&self, queue_index: usize, event: &EpollEvent) -> bool {
        log::trace!("Event on queue {queue_index}: {:?}", event.event_set());

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("Unexpected event from queue index {queue_index}: {event_set:?}");
            return false;
        }

        if let Err(e) = self.queue_events[queue_index].read() {
            error!("Failed to read event from queue index {queue_index}: {e:?}");
            return false;
        }

        true
    }

    fn notify_port_queue_event(&mut self, queue_index: usize) {
        let (direction, port_id) = queue_idx_to_port_id(queue_index);
        match direction {
            QueueDirection::Rx => {
                log::trace!("Notify rx (queue event)");
                self.ports[port_id].notify_rx()
            },
            QueueDirection::Tx => {
                log::trace!("Notify tx (queue event)");
                self.ports[port_id].notify_tx()
            },
        }
    }

    fn handle_activate_event(&self, event_manager: &mut EventManager) {
        debug!("console: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume console activate event: {:?}", e);
        }

        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = event_manager
            .subscriber(self.activate_evt.as_raw_fd())
            .unwrap();

        for queue_index in 0..self.queues.len() {
            event_manager
                .register(
                    self.queue_events[queue_index].as_raw_fd(),
                    EpollEvent::new(
                        EventSet::IN,
                        self.queue_events[queue_index].as_raw_fd() as u64,
                    ),
                    self_subscriber.clone(),
                )
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to register queue index {queue_index} with event manager: {e:?}"
                    );
                });
        }

        event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .unwrap_or_else(|e| {
                error!("Failed to unregister fs activate evt: {:?}", e);
            })
    }

    fn handle_sigwinch_event(&mut self, event: &EpollEvent) {
        debug!("console: SIGWINCH event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("console: sigwinch unexpected event {:?}", event_set);
        }

        if let Err(e) = self.sigwinch_evt.read() {
            error!("Failed to read the sigwinch event: {:?}", e);
        }

        let (cols, rows) = get_win_size();
        self.update_console_size(cols, rows);
    }

    fn port_id_of_input(&self, source: RawFd) -> Option<usize> {
        self.ports
            .iter()
            .enumerate()
            .find(|(_port_id, port)| port.input_fd() == Some(source))
            .map(|(port_id, _)| port_id)
    }

    fn port_id_of_output(&self, source: RawFd) -> Option<usize> {
        self.ports
            .iter()
            .enumerate()
            .find(|(_port_id, port)| port.output_fd() == Some(source))
            .map(|(port_id, _)| port_id)
    }
}

impl Subscriber for Console {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();

        let control_rxq = self.queue_events[CONTROL_RXQ_INDEX].as_raw_fd();
        let control_txq = self.queue_events[CONTROL_TXQ_INDEX].as_raw_fd();

        let activate_evt = self.activate_evt.as_raw_fd();
        let sigwinch_evt = self.sigwinch_evt.as_raw_fd();

        let mut raise_irq = false;

        if self.is_activated() {
            if let Some(port_id) = self.port_id_of_input(source) {
                log::trace!("Notify rx (source)");
                self.ports[port_id].notify_rx();
            } else if let Some(port_id) = self.port_id_of_output(source) {
                log::trace!("Notify tx (source)");
                self.ports[port_id].notify_tx();
            } else if source == control_txq {
                raise_irq |=
                    self.read_queue_event(CONTROL_TXQ_INDEX, event) && self.process_control_tx()
            } else if source == control_rxq {
                raise_irq |= self.read_queue_event(CONTROL_RXQ_INDEX, event)
            }
            // Guest signaled input/output on port
            else if let Some(queue_index) = self
                .queue_events
                .iter()
                .position(|fd| fd.as_raw_fd() == source)
            {
                raise_irq |= self.read_queue_event(queue_index, event);
                self.notify_port_queue_event(queue_index);
            } else if source == activate_evt {
                self.handle_activate_event(event_manager);
            } else if source == sigwinch_evt {
                self.handle_sigwinch_event(event);
            } else {
                log::warn!("Unexpected console event received: {:?}", source)
            }
        } else {
            warn!(
                "console: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
        if raise_irq {
            self.irq.signal_used_queue();
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        let static_events = [
            EpollEvent::new(EventSet::IN, self.activate_evt.as_raw_fd() as u64),
            EpollEvent::new(EventSet::IN, self.sigwinch_evt.as_raw_fd() as u64),
        ];

        let in_port_events = self
            .ports
            .iter()
            .filter_map(|port| port.input_fd())
            .map(|fd| EpollEvent::new(EventSet::IN, fd as u64));

        let out_port_events = self
            .ports
            .iter()
            .filter_map(|port| port.output_fd())
            .map(|fd| EpollEvent::new(EventSet::OUT | EventSet::EDGE_TRIGGERED, fd as u64));

        static_events
            .into_iter()
            .chain(in_port_events)
            .chain(out_port_events)
            .collect()
    }
}
