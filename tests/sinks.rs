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

//! Sink tests: udp/tcp remote sinks deliver to a local collector, bad
//! destinations are rejected at open time, and the sink thread drains its
//! queue and counts processed messages.

use nflog2syslog::sinks::{run_sink_thread, SinkConfig, Sinks};
use nflog2syslog::stats::Stats;
use std::io::Read;
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::time::Duration;

fn udp_collector() -> (UdpSocket, String) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind local udp collector");
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let addr = sock.local_addr().unwrap().to_string();
    (sock, addr)
}

#[test]
fn stdout_only_sink_sends_nowhere() {
    let cfg = SinkConfig {
        remote: None,
        stdout: true,
    };
    let mut sinks = Sinks::open(&cfg).expect("open without remote");
    let stats = Stats::default();
    sinks.send("message", &stats);
    assert_eq!(stats.sink_errors.load(Ordering::Relaxed), 0);
}

#[test]
fn udp_sink_delivers_to_collector() {
    let (collector, addr) = udp_collector();
    let cfg = SinkConfig {
        remote: Some(("udp".to_string(), addr)),
        stdout: false,
    };
    let mut sinks = Sinks::open(&cfg).expect("udp sink opens");
    let stats = Stats::default();
    sinks.send("hello-udp", &stats);
    let mut buf = [0u8; 2048];
    let (n, _) = collector.recv_from(&mut buf).expect("datagram arrives");
    let line = String::from_utf8_lossy(&buf[..n]);
    assert!(line.contains("hello-udp"), "received: {line}");
    assert_eq!(stats.sink_errors.load(Ordering::Relaxed), 0);
}

#[test]
fn tcp_sink_delivers_to_collector() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().unwrap().to_string();
    let reader = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        // the syslog crate does not append a newline on TCP, so read raw
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).expect("read message");
        String::from_utf8_lossy(&buf[..n]).into_owned()
    });
    let cfg = SinkConfig {
        remote: Some(("tcp".to_string(), addr)),
        stdout: false,
    };
    let mut sinks = Sinks::open(&cfg).expect("tcp sink opens");
    sinks.send("hello-tcp", &Stats::default());
    let line = reader.join().expect("reader thread");
    assert!(line.contains("hello-tcp"), "received: {line}");
}

#[test]
fn invalid_dest_is_rejected_at_open() {
    let cfg = SinkConfig {
        remote: Some(("udp".to_string(), "not-an-address".to_string())),
        stdout: false,
    };
    let Err(err) = Sinks::open(&cfg) else {
        panic!("invalid dest must fail");
    };
    assert!(err.contains("invalid syslog destination"), "err: {err}");
}

#[test]
fn tcp_to_closed_port_fails_at_open() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);
    let cfg = SinkConfig {
        remote: Some(("tcp".to_string(), addr)),
        stdout: false,
    };
    assert!(Sinks::open(&cfg).is_err());
}

#[test]
fn run_sink_thread_drains_queue_and_counts() {
    let (collector, addr) = udp_collector();
    let cfg = SinkConfig {
        remote: Some(("udp".to_string(), addr)),
        stdout: false,
    };
    let (tx, queue) = sync_channel(8);
    let stats = Arc::new(Stats::default());
    let shutdown = Arc::new(AtomicBool::new(false));
    let sink = {
        let stats = Arc::clone(&stats);
        let shutdown = Arc::clone(&shutdown);
        std::thread::spawn(move || {
            run_sink_thread(cfg, queue, stats, &shutdown);
        })
    };
    for i in 0..3 {
        tx.send(format!("drain-{i}")).expect("queue accepts");
    }
    // dropping the sender disconnects the queue: the thread drains and exits
    drop(tx);
    sink.join().expect("sink thread exits");
    assert_eq!(stats.processed.load(Ordering::Relaxed), 3);
    assert_eq!(stats.sink_errors.load(Ordering::Relaxed), 0);

    let mut received = 0;
    let mut buf = [0u8; 2048];
    while received < 3 {
        let (n, _) = collector.recv_from(&mut buf).expect("datagram arrives");
        assert!(String::from_utf8_lossy(&buf[..n]).contains("drain-"));
        received += 1;
    }
}

#[test]
fn run_sink_thread_stops_on_shutdown_flag() {
    let cfg = SinkConfig {
        remote: None,
        stdout: false,
    };
    let (tx, queue) = sync_channel(4);
    let stats = Arc::new(Stats::default());
    let shutdown = Arc::new(AtomicBool::new(false));
    let sink = {
        let stats = Arc::clone(&stats);
        let shutdown = Arc::clone(&shutdown);
        std::thread::spawn(move || {
            run_sink_thread(cfg, queue, stats, &shutdown);
        })
    };
    tx.send("one".to_string()).expect("queue accepts");
    shutdown.store(true, Ordering::Relaxed);
    // the loop wakes at its 500ms recv_timeout and exits
    sink.join().expect("sink thread exits");
    assert_eq!(stats.processed.load(Ordering::Relaxed), 1);
}
