//! Logging backends: stdout, file, and syslog.

use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

use syslog::{Facility, Formatter3164, Logger, LoggerBackend};

/// Wrapper around a `syslog::Logger` so it can be used as a `tracing-subscriber`
/// writer. Each completed line is sent as an INFO-level syslog message; the
/// real level is encoded inside the JSON payload.
#[derive(Clone)]
pub struct SyslogWriter {
    inner: Arc<Mutex<Logger<LoggerBackend, Formatter3164>>>,
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl SyslogWriter {
    pub fn new(process: &str) -> io::Result<Self> {
        let formatter = Formatter3164 {
            facility: Facility::LOG_DAEMON,
            hostname: None,
            process: process.into(),
            pid: std::process::id(),
        };
        let logger = syslog::unix(formatter)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("syslog: {e}")))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(logger)),
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }
}

impl Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.extend_from_slice(buf);

        // Flush complete lines to syslog.
        while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
            let line = buffer.drain(..pos).collect::<Vec<u8>>();
            // Drop the newline itself.
            if buffer.first() == Some(&b'\n') {
                buffer.remove(0);
            }

            let msg = String::from_utf8_lossy(&line);
            if !msg.is_empty() {
                let mut logger = self.inner.lock().unwrap();
                // Send everything as INFO; the JSON body carries the real level.
                let _ = logger.info(&msg);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut buffer = self.buffer.lock().unwrap();
        if !buffer.is_empty() {
            let msg = String::from_utf8_lossy(&buffer);
            let mut logger = self.inner.lock().unwrap();
            let _ = logger.info(&msg);
            buffer.clear();
        }
        Ok(())
    }
}
