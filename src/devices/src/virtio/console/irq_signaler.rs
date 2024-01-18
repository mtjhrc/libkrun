use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use utils::eventfd::EventFd;
use crate::legacy::Gic;
use crate::virtio::VIRTIO_MMIO_INT_VRING;

struct IRQSignaler {
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    intc: Option<Arc<Mutex<Gic>>>,
    irq_line: Option<u32>,
}

impl IRQSignaler {
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        if let Some(intc) = &self.intc {
            intc.lock().unwrap().set_irq(self.irq_line.unwrap());
            Ok(())
        } else  if let Err(e) = self.interrupt_evt.write(1) {
            error!("Failed to signal used queue: {:?}", e);
        }
    }
}