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

//! Pipeline counters, shared across the pipeline threads and served as
//! Prometheus metrics when --metrics-addr is configured.

use prometheus::{IntCounter, IntCounterVec, Opts, Registry};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct Stats {
    registry: Registry,
    /// packets received from the kernel (parsed NFLOG messages)
    pub received: IntCounter,
    /// packets successfully handed to a sink
    pub processed: IntCounter,
    /// packets dropped, labeled by reason: queue_recv | queue_sink | kernel
    dropped: IntCounterVec,
    /// events where a pipeline queue rejected a packet because it was
    /// full, labeled by queue: recv | sink (each drop is one event)
    queue_full: IntCounterVec,
    /// syslog write errors
    pub sink_errors: IntCounter,
    /// netlink messages / packets that failed to parse
    pub parse_errors: IntCounter,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    pub fn new() -> Self {
        let registry = Registry::new();
        let received = IntCounter::new(
            "nflog2syslog_packets_received_total",
            "Packets received from the kernel (parsed NFLOG messages)",
        )
        .expect("valid metric");
        let processed = IntCounter::new(
            "nflog2syslog_packets_processed_total",
            "Packets handed to a configured sink",
        )
        .expect("valid metric");
        let dropped = IntCounterVec::new(
            Opts::new(
                "nflog2syslog_packets_dropped_total",
                "Packets dropped, labeled by reason: queue_recv (netlink->worker queue full), \
                 queue_sink (worker->sink queue full), kernel (netlink socket ENOBUFS)",
            ),
            &["reason"],
        )
        .expect("valid metric");
        let queue_full = IntCounterVec::new(
            Opts::new(
                "nflog2syslog_queue_full_events_total",
                "Events where a pipeline queue rejected a packet because it was full",
            ),
            &["queue"],
        )
        .expect("valid metric");
        let sink_errors = IntCounter::new(
            "nflog2syslog_errors_total",
            "Errors by kind: sink (remote syslog write failed)",
        )
        .expect("valid metric");
        let parse_errors = IntCounter::new(
            "nflog2syslog_parse_errors_total",
            "Netlink messages or packets that failed to parse",
        )
        .expect("valid metric");
        let collectors: Vec<Box<dyn prometheus::core::Collector>> = vec![
            Box::new(received.clone()),
            Box::new(processed.clone()),
            Box::new(dropped.clone()),
            Box::new(queue_full.clone()),
            Box::new(sink_errors.clone()),
            Box::new(parse_errors.clone()),
        ];
        for c in collectors {
            registry.register(c).expect("register metric");
        }
        Stats {
            registry,
            received,
            processed,
            dropped,
            queue_full,
            sink_errors,
            parse_errors,
        }
    }

    /// The registry holding all counters; the metrics endpoint serves it.
    pub fn registry(&self) -> Registry {
        self.registry.clone()
    }

    /// Drop because queue q1 (recv -> worker) was full.
    pub fn drop_queue_recv(&self) {
        self.dropped.with_label_values(&["queue_recv"]).inc();
        self.queue_full.with_label_values(&["recv"]).inc();
    }

    /// Drop because queue q2 (worker -> sink) was full.
    pub fn drop_queue_sink(&self) {
        self.dropped.with_label_values(&["queue_sink"]).inc();
        self.queue_full.with_label_values(&["sink"]).inc();
    }

    /// The kernel dropped queued packets (ENOBUFS on the netlink socket).
    pub fn drop_kernel(&self) {
        self.dropped.with_label_values(&["kernel"]).inc();
    }

    /// Current value of one dropped-packets label (tests, stderr report).
    pub fn dropped_with_label(&self, reason: &str) -> u64 {
        self.dropped.with_label_values(&[reason]).get()
    }

    /// Report all nonzero counters to stderr.
    pub fn report(&self) {
        let received = self.received.get();
        let processed = self.processed.get();
        let recv = self.dropped_with_label("queue_recv");
        let worker = self.dropped_with_label("queue_sink");
        let kernel = self.dropped_with_label("kernel");
        let sink_errors = self.sink_errors.get();
        let parse_errors = self.parse_errors.get();
        if received == 0
            && processed == 0
            && recv == 0
            && worker == 0
            && kernel == 0
            && sink_errors == 0
            && parse_errors == 0
        {
            return;
        }
        eprintln!(
            "stats: received={received} processed={processed} \
dropped(queue_recv)={recv} dropped(queue_sink)={worker} dropped(kernel)={kernel} \
sink_errors={sink_errors} parse_errors={parse_errors}"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment_and_read_back() {
        let stats = Stats::default();
        stats.received.inc_by(10);
        stats.processed.inc_by(8);
        stats.drop_queue_recv();
        stats.drop_queue_recv();
        stats.drop_queue_sink();
        stats.drop_kernel();
        stats.sink_errors.inc_by(4);
        stats.parse_errors.inc_by(6);
        assert_eq!(stats.received.get(), 10);
        assert_eq!(stats.processed.get(), 8);
        assert_eq!(stats.dropped_with_label("queue_recv"), 2);
        assert_eq!(stats.dropped_with_label("queue_sink"), 1);
        assert_eq!(stats.dropped_with_label("kernel"), 1);
        assert_eq!(stats.sink_errors.get(), 4);
        assert_eq!(stats.parse_errors.get(), 6);
    }

    #[test]
    fn registry_gathers_all_counters() {
        let stats = Stats::default();
        stats.received.inc();
        stats.drop_queue_recv();
        let families = stats.registry().gather();
        let names: Vec<String> = families.iter().map(|f| f.name().to_string()).collect();
        for expected in [
            "nflog2syslog_packets_received_total",
            "nflog2syslog_packets_processed_total",
            "nflog2syslog_packets_dropped_total",
            "nflog2syslog_queue_full_events_total",
            "nflog2syslog_errors_total",
            "nflog2syslog_parse_errors_total",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "metric {expected} missing from registry: {names:?}"
            );
        }
    }

    #[test]
    fn report_with_zero_counters_returns_silently() {
        let stats = Stats::default();
        // all counters zero: the early-return branch
        stats.report();
    }

    #[test]
    fn report_prints_nonzero_counters() {
        let stats = Stats::default();
        stats.received.inc_by(42);
        stats.drop_kernel();
        stats.parse_errors.inc_by(3);
        stats.report();
    }

    #[test]
    fn report_loop_returns_immediately_when_shutting_down() {
        let stats = Arc::new(Stats::default());
        let shutdown = AtomicBool::new(true);
        report_loop(stats, Duration::from_secs(60), &shutdown);
    }

    #[test]
    fn report_loop_checks_shutdown_each_second_and_reports() {
        let stats = Arc::new(Stats::default());
        stats.received.inc_by(7);
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = {
            let stats = Arc::clone(&stats);
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                report_loop(stats, Duration::from_secs(1), &shutdown);
            })
        };
        // let the first interval report, then request shutdown
        std::thread::sleep(Duration::from_millis(300));
        shutdown.store(true, Ordering::Relaxed);
        handle.join().expect("report loop exits");
    }
}
