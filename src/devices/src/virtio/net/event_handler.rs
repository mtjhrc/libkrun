// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::net::device::Net;
use crate::virtio::{VirtioDevice};
use crate::virtio::net::{RX_INDEX, TX_INDEX};

impl Net {
    fn process_activate_event(&self, event_manager: &mut EventManager) {
        debug!("net: activate event");
        if let Err(e) = self.activate_evt.read() {
            log::error!("Failed to consume net activate event: {:?}", e);
        }
        let activate_fd = self.activate_evt.as_raw_fd();
        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = match event_manager.subscriber(activate_fd) {
            Ok(subscriber) => subscriber,
            Err(e) => {
                log::error!("Failed to process block activate evt: {:?}", e);
                return;
            }
        };

        // Interest list changes when the device is activated.
        let interest_list = self.interest_list();
        for event in interest_list {
            event_manager
                .register(event.data() as i32, event, self_subscriber.clone())
                .unwrap_or_else(|e| {
                    log::error!("Failed to register net events: {:?}", e);
                });
        }

        event_manager.unregister(activate_fd).unwrap_or_else(|e| {
            log::error!("Failed to unregister net activate evt: {:?}", e);
        });
    }
}

impl Subscriber for Net {
    fn process(&mut self, event: &EpollEvent, evmgr: &mut EventManager) {
        let source = event.fd();
        let event_set = event.event_set();

        // TODO: also check for errors. Pending high level discussions on how we want
        // to handle errors in devices.
        let supported_events = EventSet::IN;

        if !supported_events.contains(event_set) {
            log::warn!(
                "Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if self.is_activated() {
            let virtq_rx_ev_fd = self.queue_evts[RX_INDEX].as_raw_fd();
            let virtq_tx_ev_fd = self.queue_evts[TX_INDEX].as_raw_fd();
            let passt_socket = self.raw_passt_socket_fd();
            let activate_fd = self.activate_evt.as_raw_fd();

            // Looks better than C style if/else if/else.
            match source {
                _ if source == virtq_rx_ev_fd => self.process_rx_queue_event(),
                _ if source == passt_socket => self.process_passt_rx_event(),
                _ if source == virtq_tx_ev_fd => self.process_tx_queue_event(),
                _ if activate_fd == source => self.process_activate_event(evmgr),
                _ => {
                    log::warn!("Net: Spurious event received: {:?}", source);
                }
            }
        } else {
            log::warn!(
                "Net: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        // This function can be called during different points in the device lifetime:
        //  - shortly after device creation,
        //  - on device activation (is-activated already true at this point),
        //  - on device restore from snapshot.
        if self.is_activated() {
            vec![
                EpollEvent::new(EventSet::IN, self.queue_evts[RX_INDEX].as_raw_fd() as u64),
                EpollEvent::new(EventSet::IN, self.queue_evts[TX_INDEX].as_raw_fd() as u64),
                EpollEvent::new(
                    EventSet::IN, //| EventSet::EDGE_TRIGGERED,
                    self.raw_passt_socket_fd() as u64,
                ),
            ]
        } else {
            vec![EpollEvent::new(
                EventSet::IN,
                self.activate_evt.as_raw_fd() as u64,
            )]
        }
    }
}