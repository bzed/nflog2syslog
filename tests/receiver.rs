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

//! Receiver tests that run in any environment: opening a netlink socket
//! and enlarging the buffer works for everyone (SO_RCVBUFFORCE falls back
//! to SO_RCVBUF), the run loop honors the shutdown flag, and unbind
//! terminates.
//!
//! The handshake outcome depends on the environment, not just the uid:
//! it succeeds only with CAP_NET_ADMIN *and* the nfnetlink_log module
//! loaded (GitHub's packaging containers run as root but drop the
//! capability). The test asserts the documented outcome for whichever case
//! applies; what must never happen is a panic, a hang, or a malformed
//! error.

use nflog2syslog::receiver::{Receiver, ReceiverConfig};
use nflog2syslog::stats::Stats;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::sync_channel;
use std::sync::Arc;

fn receiver() -> Receiver {
    let stats = Arc::new(Stats::default());
    Receiver::open(64 * 1024, stats).expect("netlink socket opens without privileges")
}

#[test]
fn open_enlarges_rcvbuf_with_or_without_caps() {
    // with CAP_NET_ADMIN the SO_RCVBUFFORCE path applies; unprivileged the
    // SO_RCVBUF fallback (capped by net.core.rmem_max) must succeed
    receiver();
}

#[test]
fn configure_handshake_outcome_matches_privileges() {
    let mut recv = receiver();
    let cfg = ReceiverConfig {
        nflog_group: 42,
        copy_range: 256,
        rcvbuf: 64 * 1024,
    };
    match recv.configure(&cfg) {
        // fully privileged with nfnetlink_log loaded: clean handshake
        Ok(()) => recv.unbind(42),
        // no CAP_NET_ADMIN or module not loaded: the kernel NACKs with EPERM
        Err(e) => assert!(
            e.contains("NACK") || e.contains("not permitted"),
            "unexpected handshake error: {e}"
        ),
    }
}

#[test]
fn run_honors_shutdown_and_unbind_returns() {
    let mut recv = receiver();
    let (tx, queue) = sync_channel(1);
    drop(queue);
    let shutdown = AtomicBool::new(true);
    // immediate return without touching the (already dropped) queue
    recv.run(tx, &shutdown);
    // best-effort unbind: NACK unprivileged, ACK as root; must not hang
    recv.unbind(42);
}
