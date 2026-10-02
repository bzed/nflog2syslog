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

//! Prometheus metrics endpoint (served by prometheus-hyper on /metrics,
//! only when --metrics-addr is configured).

use crate::stats::Stats;
use prometheus::IntGauge;
use std::net::SocketAddr;

/// A static gauge: (metric name, help text, value).
pub type Gauge = (&'static str, &'static str, i64);

/// Serve `stats` plus static `gauges` on http://addr/metrics until
/// process exit. The address is checked synchronously so configuration
/// errors fail fast; a later failure inside the server thread exits the
/// process like the other pipeline threads do.
pub fn serve(stats: &Stats, addr: SocketAddr, gauges: &[Gauge]) -> Result<(), String> {
    // bind and drop: fail fast on an unusable address; the short race
    // until the real server binds does not matter at startup
    std::net::TcpListener::bind(addr).map_err(|e| format!("metrics listen on {addr}: {e}"))?;
    let registry = stats.registry();
    for &(name, help, value) in gauges {
        let gauge = IntGauge::new(name, help).expect("valid gauge");
        gauge.set(value);
        registry.register(Box::new(gauge)).expect("register gauge");
    }
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        // std::future::pending() = serve until process exit
        if let Err(e) = rt.block_on(prometheus_hyper::Server::run(
            std::sync::Arc::new(registry),
            addr,
            std::future::pending(),
        )) {
            eprintln!("Error: metrics server on {addr} failed: {e}");
            std::process::exit(1);
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::Stats;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    fn test_gauges() -> Vec<Gauge> {
        vec![
            ("nflog2syslog_nflog_group", "NFLOG group", 5),
            ("nflog2syslog_queue_capacity", "Queue capacity", 8192),
        ]
    }

    fn free_addr() -> SocketAddr {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
        let addr = probe.local_addr().expect("probe addr");
        drop(probe);
        addr
    }

    fn start_server() -> SocketAddr {
        let addr = free_addr();
        let stats = Stats::default();
        stats.received.inc_by(3);
        stats.drop_queue_recv();
        stats.drop_kernel();
        serve(&stats, addr, &test_gauges()).expect("serve metrics");
        addr
    }

    fn get(addr: SocketAddr, request: &str) -> String {
        // the server thread needs a moment to bind
        for _ in 0..100 {
            if let Ok(mut s) = TcpStream::connect(addr) {
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                s.write_all(request.as_bytes()).expect("send request");
                let mut resp = String::new();
                s.read_to_string(&mut resp).expect("read response");
                return resp;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("could not connect to metrics server on {addr}");
    }

    #[test]
    fn scrape_returns_all_metrics() {
        let addr = start_server();
        let resp = get(
            addr,
            "GET /metrics HTTP/1.1\r\nHost: scrape\r\nConnection: close\r\n\r\n",
        );
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        let body = resp.split("\r\n\r\n").nth(1).expect("body");
        for expected in [
            "nflog2syslog_packets_received_total 3\n",
            "nflog2syslog_packets_dropped_total{reason=\"queue_recv\"} 1\n",
            "nflog2syslog_packets_dropped_total{reason=\"kernel\"} 1\n",
            "nflog2syslog_queue_full_events_total{queue=\"recv\"} 1\n",
            "nflog2syslog_nflog_group 5\n",
            "nflog2syslog_queue_capacity 8192\n",
        ] {
            assert!(body.contains(expected), "missing {expected} in:\n{body}");
        }
    }

    #[test]
    fn other_paths_are_404() {
        let addr = start_server();
        let resp = get(
            addr,
            "GET /nope HTTP/1.1\r\nHost: scrape\r\nConnection: close\r\n\r\n",
        );
        assert!(resp.starts_with("HTTP/1.1 404 Not Found\r\n"), "{resp}");
    }

    #[test]
    fn occupied_port_returns_error() {
        let guard = std::net::TcpListener::bind("127.0.0.1:0").expect("guard bind");
        let addr = guard.local_addr().expect("guard addr");
        let err = serve(&Stats::default(), addr, &[]).expect_err("bind must fail");
        assert!(err.contains("metrics listen"), "{err}");
    }
}
