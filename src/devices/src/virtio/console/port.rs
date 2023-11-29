//! See https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-2920002
//! for port <-> virtio queue index mapping

use crate::legacy::ReadableFd;
use std::io;

#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum PortStatus {
    NotReady,
    Ready { opened: bool },
}

pub struct PortDescription {
    /// If the value is true, port represents a console in the guest
    pub console: bool,
    pub input: Option<Box<dyn ReadableFd + Send>>,
    pub output: Option<Box<dyn io::Write + Send>>,
}

pub(crate) struct Port {
    pub(crate) status: PortStatus,
    pub(crate) console: bool,
    // It doesn't make sense for both of these to be None, so encode it better
    pub(crate) input: Option<Box<dyn ReadableFd + Send>>,
    pub(crate) output: Option<Box<dyn io::Write + Send>>,
}

impl Port {
    pub(crate) fn new(description: PortDescription) -> Self {
        Self {
            status: PortStatus::NotReady,
            console: description.console,
            output: description.output,
            input: description.input,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum QueueDirection {
    Rx,
    Tx,
}

#[must_use]
pub(crate) fn port_id_to_queue_idx(queue_direction: QueueDirection, port_id: usize) -> usize {
    match queue_direction {
        QueueDirection::Rx if port_id == 0 => 0,
        QueueDirection::Rx => 2 + 2 * port_id,
        QueueDirection::Tx if port_id == 0 => 1,
        QueueDirection::Tx => 2 + 2 * port_id + 1,
    }
}

#[must_use]
pub(crate) fn queue_idx_to_port_id(queue_index: usize) -> (QueueDirection, usize) {
    let port_id = match queue_index {
        0 | 1 => 0,
        2 | 3 => panic!("Invalid argument: {queue_index} is not a valid receiveq nor transmitq index!"),
        _ => queue_index / 2 - 1,
    };

    let direction = if queue_index % 2 == 0 {
        QueueDirection::Rx
    } else {
        QueueDirection::Tx
    };

    (direction, port_id)
}

#[cfg(test)]
mod test {
    use crate::virtio::console::port::*;

    #[test]
    fn test_queue_idx_to_port_id_ok() {
        assert_eq!(queue_idx_to_port_id(0), (QueueDirection::Rx, 0));
        assert_eq!(queue_idx_to_port_id(1), (QueueDirection::Tx, 0));
        assert_eq!(queue_idx_to_port_id(4), (QueueDirection::Rx, 1));
        assert_eq!(queue_idx_to_port_id(5), (QueueDirection::Tx, 1));
        assert_eq!(queue_idx_to_port_id(6), (QueueDirection::Rx, 2));
        assert_eq!(queue_idx_to_port_id(7), (QueueDirection::Tx, 2));
    }

    #[test]
    #[should_panic]
    fn test_queue_idx_to_port_id_panic_rx_control() {
        let _ = queue_idx_to_port_id(2);
    }

    #[test]
    #[should_panic]
    fn test_queue_idx_to_port_id_panic_tx_control() {
        let _ = queue_idx_to_port_id(3);
    }
}
