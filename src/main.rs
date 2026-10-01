use clap::Parser;
use nflog2syslog::cli::Cli;
use nflog2syslog::format::Formatter;
use nflog2syslog::receiver::{Receiver, ReceiverConfig};
use nflog2syslog::sinks::SinkConfig;
use nflog2syslog::stats::Stats;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::time::Duration;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
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

    let stats = Arc::new(Stats::default());
    let (q1, rx1) = sync_channel(cli.queue_size.max(1));
    let (q2, rx2) = sync_channel(cli.queue_size.max(1));

    // sink thread
    let sink_cfg = SinkConfig {
        dest: match cli.dest.as_deref() {
            None | Some("none") => None,
            Some(d) => Some(d.to_string()),
        },
        proto: cli.proto.clone().filter(|p| !p.is_empty()),
        stdout: cli.stdout,
        local_syslog: cli.local_syslog,
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
                    worker_stats.add(&worker_stats.worker_dropped, 1);
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

#[cfg(test)]
mod tests {
    use nflog2syslog::wire::round_up;

    #[test]
    fn round_up_alignment() {
        assert_eq!(round_up(0, 4), 0);
        assert_eq!(round_up(1, 4), 4);
        assert_eq!(round_up(6, 4), 8);
        assert_eq!(round_up(8, 4), 8);
    }
}
