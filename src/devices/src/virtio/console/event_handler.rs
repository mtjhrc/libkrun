use std::io::Read;
use std::os::unix::io::AsRawFd;

use crate::virtio::console::device::{VirtioConsoleControl, CONTROL_RXQ_INDEX, CONTROL_TXQ_INDEX, PortStatus};
use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};
use crate::virtio::console::defs::control_event::VIRTIO_CONSOLE_PORT_OPEN;

use super::device::{get_win_size, Console, RXQ_INDEX, TXQ_INDEX};
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

    fn push_control_cmd(&mut self, cmd: VirtioConsoleControl) {
        self.cmd_queue.push_back(cmd);
        if self.process_control_rx() {
            self.signal_used_queue().unwrap();
        }
    }

    pub(crate) fn handle_input(&mut self, event: &EpollEvent) {
      //  debug!("console: input event");
        let event_set = event.event_set();

        match self.port_statuses[0] {
            PortStatus::NotReady => {
                log::trace!("Is this even a valid/reachable state?")
            }
            PortStatus::Ready { opened: true } => {
                if event_set.contains(EventSet::IN) {
                    let mut out = [0u8; 64];
                    let count = self.input.read(&mut out).unwrap();
                    self.in_buffer.extend(&out[..count]);

                    if self.process_rx() {
                        self.signal_used_queue().unwrap();
                    }
                }

                if event_set.contains(EventSet::HANG_UP) {
                    self.port_statuses[0] = PortStatus::Ready { opened: false };
                    self.push_control_cmd(VirtioConsoleControl {
                        id: 0,
                        event: VIRTIO_CONSOLE_PORT_OPEN,
                        value: 0,
                    })
                }
            }
            PortStatus::Ready { opened: false } => {
                // We don't have to do anything here I assume
            }
        }


        if !event_set.difference(EventSet::IN | EventSet::HANG_UP).is_empty() {
            warn!("console: input unexpected event {:?}", event_set);
            return;
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

        for queue_index in [RXQ_INDEX, TXQ_INDEX, CONTROL_RXQ_INDEX, CONTROL_TXQ_INDEX] {
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
        let rxq = self.queue_events[RXQ_INDEX].as_raw_fd();
        let txq = self.queue_events[TXQ_INDEX].as_raw_fd();

        let control_rxq = self.queue_events[CONTROL_RXQ_INDEX].as_raw_fd();
        let control_txq = self.queue_events[CONTROL_TXQ_INDEX].as_raw_fd();

        let activate_evt = self.activate_evt.as_raw_fd();
        let sigwinch_evt = self.sigwinch_evt.as_raw_fd();
        let input = self.input.as_raw_fd();

        if self.is_activated() {
            let mut raise_irq = false;
            match source {
                _ if source == rxq => {
                    raise_irq = self.read_queue_event(RXQ_INDEX, event) && self.process_rx()
                }
                _ if source == txq => {
                    raise_irq = self.read_queue_event(TXQ_INDEX, event) && self.process_tx()
                }
                _ if source == control_txq => {
                    raise_irq =
                        self.read_queue_event(CONTROL_TXQ_INDEX, event) && self.process_control_tx()
                }
                _ if source == control_rxq => {
                    raise_irq =
                        self.read_queue_event(CONTROL_RXQ_INDEX, event) && self.process_control_rx()
                }
                _ if source == input => self.handle_input(event),
                _ if source == activate_evt => {
                    self.handle_activate_event(event_manager);
                }
                _ if source == sigwinch_evt => {
                    self.handle_sigwinch_event(event);
                }
                _ => warn!("Unexpected console event received: {:?}", source),
            }
            if raise_irq {
                self.signal_used_queue().unwrap_or_default();
            }
        } else {
            warn!(
                "console: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        if self.interactive {
            vec![
                EpollEvent::new(EventSet::IN, self.activate_evt.as_raw_fd() as u64),
                EpollEvent::new(EventSet::IN, self.sigwinch_evt.as_raw_fd() as u64),
                EpollEvent::new(EventSet::IN, self.input.as_raw_fd() as u64),
            ]
        } else {
            vec![
                EpollEvent::new(EventSet::IN, self.activate_evt.as_raw_fd() as u64),
                EpollEvent::new(EventSet::IN, self.sigwinch_evt.as_raw_fd() as u64),
            ]
        }
    }
}

