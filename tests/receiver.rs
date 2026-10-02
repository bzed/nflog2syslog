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

//! Receiver tests that run without privileges: opening a netlink socket
//! and enlarging the buffer works for everyone (SO_RCVBUFFORCE falls back
//! to SO_RCVBUF), the NFLOG group handshake needs CAP_NET_ADMIN, the run
//! loop honors the shutdown flag, and unbind terminates.
//!
//! As root the handshake succeeds; the tests assert the privileged variant
//! then.

use nflog2syslog::receiver::{Receiver, ReceiverConfig};
use nflog2syslog::stats::Stats;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::sync_channel;
use std::sync::Arc;

fn is_root() -> bool {
    // SAFETY: geteuid has no failure mode.
    unsafe { libc::geteuid() == 0 }
}

fn receiver() -> Receiver {
    let stats = Arc::new(Stats::default());
    Receiver::open(64 * 1024, stats).expect("netlink socket opens without privileges")
}

#[test]
fn open_enlarges_rcvbuf_with_or_without_caps() {
    // as root SO_RCVBUFFORCE applies; unprivileged it fails and the
    // SO_RCVBUF fallback (capped by net.core.rmem_max) must succeed
    receiver();
}

#[test]
fn configure_handshake_respects_privileges() {
    let mut recv = receiver();
    let cfg = ReceiverConfig {
        nflog_group: 42,
        copy_range: 256,
        rcvbuf: 64 * 1024,
    };
    if is_root() {
        recv.configure(&cfg).expect("handshake succeeds as root");
        recv.unbind(42);
    } else {
        let err = recv
            .configure(&cfg)
            .expect_err("bind must fail without CAP_NET_ADMIN");
        assert!(
            err.contains("NACK") || err.contains("not permitted"),
            "unexpected error: {err}"
        );
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
