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

use clap::Parser;
use nflog2syslog::cli::Cli;
use nflog2syslog::format::Formatter;
use nflog2syslog::metrics;
use nflog2syslog::receiver::{Receiver, ReceiverConfig};
use nflog2syslog::sinks::SinkConfig;
use nflog2syslog::stats::Stats;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    // SAFETY: sigaction with a handler installed for our own process; the
    // sa_sigaction cast matches the sa_flags we set (no SA_SIGINFO).
    unsafe {
        let act = libc::sigaction {
            sa_sigaction: on_signal as *const () as usize,
            sa_mask: std::mem::zeroed(),
            sa_flags: libc::SA_RESTART,
            sa_restorer: None,
        };
        libc::sigaction(libc::SIGINT, &act, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &act, std::ptr::null_mut());
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = cli.validate() {
        eprintln!("Error: {e}");
        std::process::exit(2);
    }

    let stats = Arc::new(Stats::default());

    // optional Prometheus metrics endpoint (validated by Cli::validate)
    if let Some(addr) = cli
        .metrics_addr
        .clone()
        .filter(|a| !a.is_empty())
        .and_then(|a| a.parse::<SocketAddr>().ok())
    {
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let gauges: &[metrics::Gauge] = &[
            (
                "nflog2syslog_nflog_group",
                "NFLOG group this instance listens on",
                cli.nflog_group as i64,
            ),
            (
                "nflog2syslog_queue_capacity",
                "Capacity of each internal pipeline queue",
                cli.queue_size.max(1) as i64,
            ),
            (
                "nflog2syslog_copy_range",
                "Maximum packet bytes the kernel copies per packet",
                cli.copy_range as i64,
            ),
            (
                "nflog2syslog_rcvbuf",
                "Netlink socket receive buffer size in bytes",
                cli.rcvbuf as i64,
            ),
            (
                "process_start_time_seconds",
                "Unix timestamp of process start",
                start,
            ),
        ];
        if let Err(e) = metrics::serve(&stats, addr, gauges) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        eprintln!("nflog2syslog: metrics endpoint on http://{addr}/metrics");
    }

    let (q1, rx1) = sync_channel(cli.queue_size.max(1));
    let (q2, rx2) = sync_channel(cli.queue_size.max(1));

    // sink thread
    let sink_cfg = SinkConfig {
        // an empty --dest counts as unconfigured (systemd units expand
        // empty variables, so we treat "" like absent)
        remote: cli
            .dest
            .clone()
            .filter(|d| !d.is_empty())
            .map(|d| (cli.proto.clone(), d)),
        stdout: cli.stdout,
    };
    let sink_stats = Arc::clone(&stats);
    let sink_handle = std::thread::spawn(move || {
        nflog2syslog::sinks::run_sink_thread(sink_cfg, rx2, sink_stats, &SHUTDOWN);
    });

    // dissection/format worker thread
    let worker_stats = Arc::clone(&stats);
    let worker_handle = std::thread::spawn(move || {
        let mut formatter = Formatter::new();
        while let Ok(pkt) = rx1.recv() {
            let msg = formatter.format(&pkt, &worker_stats.parse_errors);
            match q2.try_send(msg) {
                Ok(()) => {}
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    worker_stats.drop_queue_sink();
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
            }
        }
    });

    // netlink receiver thread
    let recv_stats = Arc::clone(&stats);
    let recv_cfg = ReceiverConfig {
        nflog_group: cli.nflog_group,
        copy_range: cli.copy_range,
        rcvbuf: cli.rcvbuf,
    };
    let group = cli.nflog_group;
    let queue_size = cli.queue_size;
    let rcvbuf = cli.rcvbuf;
    let recv_handle = std::thread::spawn(move || {
        let mut recv = match Receiver::open(rcvbuf, Arc::clone(&recv_stats)) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        };
        if let Err(e) = recv.configure(&recv_cfg) {
            eprintln!("Error: nflog configuration failed: {e}");
            std::process::exit(1);
        }
        eprintln!(
            "nflog2syslog: listening on nflog group {group} (rxbuf {rcvbuf} bytes, queue capacity {queue_size})"
        );
        recv.run(q1, &SHUTDOWN);
        recv.unbind(group);
        eprintln!("nflog2syslog: unbound from group {group}");
    });

    install_signal_handlers();

    let interval = if cli.stats_interval == 0 {
        Duration::from_secs(u64::MAX / 2)
    } else {
        Duration::from_secs(cli.stats_interval)
    };
    nflog2syslog::stats::report_loop(Arc::clone(&stats), interval, &SHUTDOWN);

    // Shutdown order: receiver exits (drops q1) -> worker drains and exits
    // (drops q2) -> sink drains and exits.
    let _ = recv_handle.join();
    let _ = worker_handle.join();
    let _ = sink_handle.join();
    eprintln!("nflog2syslog stopped.");
}
