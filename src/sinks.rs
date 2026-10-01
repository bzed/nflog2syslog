// Copyright 2026 Bernd Zeimetz <bernd@bzed.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Output sinks. A single sink thread owns the (optional) remote syslog
//! writer so a stalled collector never blocks the dissection worker —
//! it fills the bounded queue, which drops with accounting instead.

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
    /// remote syslog server: (protocol, ip:port)
    pub remote: Option<(String, String)>,
    /// log JSON messages to stdout
    pub stdout: bool,
}

pub struct Sinks {
    remote: Option<Logger<LoggerBackend, Formatter3164>>,
    stdout: bool,
}

impl Sinks {
    pub fn open(cfg: &SinkConfig) -> Result<Sinks, String> {
        let mut sinks = Sinks {
            remote: None,
            stdout: cfg.stdout,
        };
        if let Some((proto, dest)) = &cfg.remote {
            let logger = match proto.as_str() {
                "udp" => syslog::udp(formatter(), ("0.0.0.0", 0), (dest.as_str(), 0))
                    .map_err(|e| format!("udp syslog to {dest}: {e}"))?,
                // validated by Cli::validate()
                _ => syslog::tcp(formatter(), dest.as_str())
                    .map_err(|e| format!("tcp syslog to {dest}: {e}"))?,
            };
            sinks.remote = Some(logger);
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
        if let Some(logger) = self.remote.as_mut() {
            if let Err(e) = logger.info(msg) {
                stats.sink_errors.fetch_add(1, Ordering::Relaxed);
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
                stats.processed.fetch_add(1, Ordering::Relaxed);
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
        stats.processed.fetch_add(1, Ordering::Relaxed);
    }
}
