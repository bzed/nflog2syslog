//! Command line interface.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "nflog2syslog",
    version,
    about = "Read kernel NFLOG packets via netlink, dissect them, forward them as JSON to syslog"
)]
pub struct Cli {
    /// NFLOG group to listen on (iptables ... -j NFLOG --nflog-group N)
    #[arg(long, default_value_t = 0)]
    pub nflog_group: u16,

    /// Remote syslog destination, e.g. 192.0.2.1:514. Empty = local syslog socket.
    #[arg(long)]
    pub dest: Option<String>,

    /// Protocol for the remote syslog server: udp, tcp. Ignored without --dest.
    #[arg(long)]
    pub proto: Option<String>,

    /// Maximum number of packet bytes copied by the kernel per packet.
    #[arg(long, default_value_t = 1024)]
    pub copy_range: u32,

    /// Netlink socket receive buffer in bytes (SO_RCVBUFFORCE).
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub rcvbuf: usize,

    /// Capacity of the pipeline queues (recv->worker, worker->sink).
    #[arg(long, default_value_t = 8192)]
    pub queue_size: usize,

    /// Copy every message to stdout as well.
    #[arg(long, default_value_t = false)]
    pub stdout: bool,

    /// Copy every message to the local syslog socket as well.
    #[arg(long, default_value_t = false)]
    pub local_syslog: bool,

    /// Seconds between stderr statistics reports (0 disables).
    #[arg(long, default_value_t = 10)]
    pub stats_interval: u64,
}
