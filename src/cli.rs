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

    /// Remote syslog destination, e.g. 192.0.2.1:514. Absent: no remote sink.
    #[arg(long)]
    pub dest: Option<String>,

    /// Protocol for the remote syslog server (udp or tcp)
    #[arg(long, default_value = "udp")]
    pub proto: String,

    /// Maximum number of packet bytes copied by the kernel per packet.
    #[arg(long, default_value_t = 1024)]
    pub copy_range: u32,

    /// Netlink socket receive buffer in bytes (SO_RCVBUFFORCE).
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub rcvbuf: usize,

    /// Capacity of the pipeline queues (recv->worker, worker->sink).
    #[arg(long, default_value_t = 8192)]
    pub queue_size: usize,

    /// Log every JSON message to stdout (status messages always go to stderr).
    /// --stdout=false disables JSON output on stdout.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub stdout: bool,

    /// Seconds between stderr statistics reports (0 disables).
    #[arg(long, default_value_t = 10)]
    pub stats_interval: u64,
}

impl Cli {
    /// Fail fast on configurations that would drop everything on the floor.
    pub fn validate(&self) -> Result<(), String> {
        if !self.stdout && self.dest.as_deref().map(str::is_empty).unwrap_or(true) {
            return Err(
                "no output sink configured: stdout logging is disabled (--stdout=false) \
                 and no remote syslog destination (--dest) is set"
                    .into(),
            );
        }
        match self.proto.as_str() {
            "udp" | "tcp" => Ok(()),
            other => Err(format!(
                "unsupported syslog protocol {other:?} (use udp or tcp)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("nflog2syslog").chain(args.iter().copied()))
    }

    #[test]
    fn defaults() {
        let c = cli(&[]);
        assert!(c.stdout);
        assert!(c.dest.is_none());
        assert_eq!(c.proto, "udp");
        assert!(c.validate().is_ok());
    }

    #[test]
    fn stdout_off_without_dest_fails() {
        let c = cli(&["--stdout=false"]);
        assert!(c.validate().is_err());
        let c = cli(&["--stdout", "false"]);
        assert!(!c.stdout);
        assert!(c.validate().is_err());
    }

    #[test]
    fn stdout_off_with_dest_is_ok() {
        let c = cli(&["--stdout=false", "--dest", "192.0.2.1:514"]);
        assert!(!c.stdout);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn empty_dest_counts_as_unconfigured() {
        let c = cli(&["--dest", "", "--stdout=false"]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn bad_proto_fails() {
        let c = cli(&["--dest", "192.0.2.1:514", "--proto", "carrier-pigeon"]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn tcp_proto_is_ok() {
        let c = cli(&["--dest", "192.0.2.1:514", "--proto", "tcp"]);
        assert!(c.validate().is_ok());
    }
}
