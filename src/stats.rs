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

//! Loss and throughput counters, shared across pipeline threads.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Default)]
pub struct Stats {
    /// packets dropped because queue q1 (recv -> worker) was full
    pub recv_dropped: AtomicU64,
    /// packets dropped because queue q2 (worker -> sink) was full
    pub worker_dropped: AtomicU64,
    /// packets the kernel dropped (ENOBUFS on the netlink socket)
    pub kernel_dropped: AtomicU64,
    /// packets successfully handed to a sink
    pub processed: AtomicU64,
    /// syslog write errors
    pub sink_errors: AtomicU64,
    /// netlink messages that failed to parse
    pub parse_errors: AtomicU64,
}

impl Stats {
    fn get(&self, counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Report all nonzero counters to stderr.
    pub fn report(&self) {
        let recv = self.get(&self.recv_dropped);
        let worker = self.get(&self.worker_dropped);
        let kernel = self.get(&self.kernel_dropped);
        let processed = self.get(&self.processed);
        let sink_errors = self.get(&self.sink_errors);
        let parse_errors = self.get(&self.parse_errors);
        if recv == 0 && worker == 0 && kernel == 0 && sink_errors == 0 && parse_errors == 0 {
            return;
        }
        eprintln!(
            "stats: processed={processed} dropped(queue_recv)={recv} \
dropped(queue_sink)={worker} dropped(kernel)={kernel} sink_errors={sink_errors} \
parse_errors={parse_errors}"
        );
    }
}

/// Run until `shutdown` becomes true, reporting `stats` every `interval`.
/// Used by the main thread. Sleeps in one-second steps so shutdown is
/// noticed promptly (the recv thread's poll(1000) dominates exit latency
/// anyway).
pub fn report_loop(stats: Arc<Stats>, interval: Duration, shutdown: &AtomicBool) {
    // a disabled interval (u64::MAX/2) still gives a functioning loop that
    // only checks the shutdown flag
    let ticks = interval.as_secs().max(1);
    loop {
        for _ in 0..ticks {
            if shutdown.load(Ordering::Relaxed) {
                stats.report();
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        stats.report();
    }
}
