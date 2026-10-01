//! Syslog output sinks. A single sink thread owns all writers so a
//! stalled collector never blocks the dissection worker — it fills the
//! bounded queue, which drops with accounting instead.

use crate::stats::Stats;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use syslog::{Facility, Formatter3164, Logger, LoggerBackend};

fn formatter() -> Formatter3164 {
    Formatter3164 {
        facility: Facility::LOG_LOCAL0,
        hostname: None,
        process: "nflog2syslog".to_string(),
        pid: std::process::id(),
    }
}

/// The sink configuration derived from CLI flags.
#[derive(Debug, Default, Clone)]
pub struct SinkConfig {
    /// ip:port of the remote syslog server
    pub dest: Option<String>,
    /// udp / tcp; None means local syslog socket
    pub proto: Option<String>,
    /// copy every message to stdout as well
    pub stdout: bool,
    /// copy every message to the local syslog socket as well
    pub local_syslog: bool,
}

pub struct Sinks {
    remote: Option<Logger<LoggerBackend, Formatter3164>>,
    local: Option<Logger<LoggerBackend, Formatter3164>>,
    stdout: bool,
}

impl Sinks {
    pub fn open(cfg: &SinkConfig) -> Result<Sinks, String> {
        let mut sinks = Sinks {
            remote: None,
            local: None,
            stdout: cfg.stdout,
        };
        if let Some(dest) = &cfg.dest {
            let logger = match cfg.proto.as_deref() {
                Some("udp") => syslog::udp(formatter(), ("0.0.0.0", 0), (dest.as_str(), 0))
                    .map_err(|e| format!("udp syslog to {dest}: {e}"))?,
                Some("tcp") => syslog::tcp(formatter(), dest.as_str())
                    .map_err(|e| format!("tcp syslog to {dest}: {e}"))?,
                _ => syslog::unix(formatter()).map_err(|e| format!("local syslog: {e}"))?,
            };
            sinks.remote = Some(logger);
        }
        if cfg.local_syslog {
            sinks.local =
                Some(syslog::unix(formatter()).map_err(|e| format!("local syslog: {e}"))?);
        }
        Ok(sinks)
    }

    /// Send one formatted message to all configured sinks. Errors are
    /// counted and reported on stderr; a failing sink never stops the
    /// pipeline.
    pub fn send(&mut self, msg: &str, stats: &Stats) {
        if self.stdout {
            println!("{msg}");
        }
        if let Some(logger) = self.local.as_mut() {
            if let Err(e) = logger.info(msg) {
                stats.add(&stats.sink_errors, 1);
                eprintln!("local syslog write failed: {e}");
            }
        }
        if let Some(logger) = self.remote.as_mut() {
            if let Err(e) = logger.info(msg) {
                stats.add(&stats.sink_errors, 1);
                eprintln!("remote syslog write failed: {e}");
            }
        }
    }
}

/// Sink thread: drain the formatted-message queue until it closes.
pub fn run_sink_thread(
    cfg: SinkConfig,
    queue: Receiver<String>,
    stats: Arc<Stats>,
    shutdown: &AtomicBool,
) {
    let mut sinks = match Sinks::open(&cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    loop {
        match queue.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(msg) => {
                sinks.send(&msg, &stats);
                stats.add(&stats.processed, 1);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    // final drain
    while let Ok(msg) = queue.try_recv() {
        sinks.send(&msg, &stats);
        stats.add(&stats.processed, 1);
    }
}
