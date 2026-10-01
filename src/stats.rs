//! Loss and throughput counters, shared across pipeline threads.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Stats {
    /// packets dropped because queue q1 (recv -> worker) was full
    pub recv_dropped: AtomicU64,
    /// packets dropped because queue q2 (worker -> sink) was full
    pub worker_dropped: AtomicU64,
    /// packets the kernel dropped (ENOBUFS on the netlink socket)
    pub kernel_dropped: AtomicU64,
    /// packets successfully handed to a syslog sink
    pub processed: AtomicU64,
    /// syslog write errors
    pub sink_errors: AtomicU64,
    /// netlink messages that failed to parse
    pub parse_errors: AtomicU64,
}

impl Stats {
    pub fn add(&self, counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    fn get(&self, counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Report all nonzero counters to stderr. Returns true if anything was
    /// reported.
    pub fn report(&self) -> bool {
        let recv = self.get(&self.recv_dropped);
        let worker = self.get(&self.worker_dropped);
        let kernel = self.get(&self.kernel_dropped);
        let processed = self.get(&self.processed);
        let sink_errors = self.get(&self.sink_errors);
        let parse_errors = self.get(&self.parse_errors);
        if recv == 0 && worker == 0 && kernel == 0 && sink_errors == 0 && parse_errors == 0 {
            return false;
        }
        eprintln!(
            "stats: processed={processed} dropped(queue_recv)={recv} \
dropped(queue_sink)={worker} dropped(kernel)={kernel} sink_errors={sink_errors} \
parse_errors={parse_errors}"
        );
        true
    }
}

/// Run until `shutdown` becomes true, reporting `stats` every `interval`.
/// Used by the main thread.
pub fn report_loop(stats: Arc<Stats>, interval: Duration, shutdown: &AtomicBool) {
    let mut next = Instant::now() + interval;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            let _ = stats.report();
            return;
        }
        let now = Instant::now();
        if now >= next {
            stats.report();
            next = now + interval;
        }
        std::thread::sleep(Duration::from_millis(200).min(next.saturating_duration_since(now)));
    }
}
