use std::io::{Write};

// Utility to relay log from the VM (the kernel boot log and messages from init)
// to the rust log
#[derive(Default)]
pub struct VMLog {
    buf: Vec<u8>,
}

impl VMLog {
    pub fn new() -> Self {
        Self::default()
    }

    fn force_flush(&mut self) {
        log::debug!(
            "[guest; (missing newline)]: {}",
            String::from_utf8_lossy(&self.buf)
        );
        self.buf.clear();
    }
}

const FORCE_FLUSH_TRESHOLD: usize = 512;

impl Write for VMLog {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(input);

        let mut start = 0;
        for (i, ch) in self.buf.iter().cloned().enumerate() {
            if ch == b'\n' {
                log::debug!("[guest]: {}", String::from_utf8_lossy(&self.buf[start..i]));
                start = i + 1;
            }
        }
        self.buf.drain(0..start);
        if self.buf.len() > FORCE_FLUSH_TRESHOLD {
            self.force_flush()
        }
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // We don't really flush here because current implementation of console uses flush too often
        Ok(())
    }
}

impl Drop for VMLog {
    fn drop(&mut self) {
        self.force_flush();
    }
}
