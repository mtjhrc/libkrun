use std::os::unix::io::AsRawFd;


use crate::virtio::console::device::{CONTROL_RXQ_INDEX, CONTROL_TXQ_INDEX};
use crate::virtio::console::port::{queue_idx_to_port_id, QueueDirection};
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
}

impl Subscriber for Console {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        //let rxq = self.queue_events[RXQ_INDEX].as_raw_fd();
        //let txq = self.queue_events[TXQ_INDEX].as_raw_fd();

        let control_rxq = self.queue_events[CONTROL_RXQ_INDEX].as_raw_fd();
        let control_txq = self.queue_events[CONTROL_TXQ_INDEX].as_raw_fd();

        let activate_evt = self.activate_evt.as_raw_fd();
        let sigwinch_evt = self.sigwinch_evt.as_raw_fd();

        let mut raise_irq = false;

        //TODO: where is the resume_tx net equivalent?
        if let Some((port_id, _)) = self.ports.iter().enumerate().find(|(_id, port)| {
            port.input
                .as_ref()
                .is_some_and(|port| port.as_raw_fd() == source)
        }) {
            log::trace!("Input on port {port_id}");
            raise_irq = self.handle_input(&event.event_set(), port_id);
        } else if self.is_activated() {
            if source == control_txq {
                raise_irq |=
                    self.read_queue_event(CONTROL_TXQ_INDEX, event) && self.process_control_tx()
            } else if source == control_rxq {
                raise_irq |=
                    self.read_queue_event(CONTROL_RXQ_INDEX, event) && self.process_control_rx()
            } else if source == activate_evt {
                self.handle_activate_event(event_manager);
            } else if source == sigwinch_evt {
                self.handle_sigwinch_event(event);
            } else if let Some(queue_index) = self
                .queue_events
                .iter()
                .position(|fd| fd.as_raw_fd() == source)
            {
                let (direction, port_id) = queue_idx_to_port_id(queue_index);
                self.read_queue_event(queue_index, event);
                match direction {
                    QueueDirection::Rx => raise_irq |= self.resume_rx(port_id),
                    QueueDirection::Tx => raise_irq |= self.process_tx(port_id),
                };
            } else {
                warn!("Unexpected console event received: {:?}", source);
            }
        } else {
            warn!(
                "console: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }

        if raise_irq {
            self.signal_used_queue().unwrap_or_default();
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        let static_events = [
            EpollEvent::new(EventSet::IN, self.activate_evt.as_raw_fd() as u64),
            EpollEvent::new(EventSet::IN, self.sigwinch_evt.as_raw_fd() as u64),
        ];

        // TODO: pass in `interactive` flag for each port input?
        // Another alternative, lets have a trait with get_polling_fd() -> Option<Fd> implemented for each input?

        let port_events = self.ports.iter().flat_map(|port| &port.input).map(|input| {
            EpollEvent::new(
                EventSet::IN
                    | EventSet::EDGE_TRIGGERED
                    | EventSet::READ_HANG_UP
                    | EventSet::HANG_UP,
                input.as_raw_fd() as u64,
            )
        });

        static_events.into_iter().chain(port_events).collect()
    }
}
