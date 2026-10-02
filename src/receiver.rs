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

//! Netlink receiver: socket setup, NFLOG group handshake, and the
//! receive loop that feeds the bounded pipeline queue.

use crate::stats::Stats;
use crate::wire::{self, ConfigRequest, NflogPacket};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_sys::{protocols::NETLINK_NETFILTER, Socket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

pub struct ReceiverConfig {
    pub nflog_group: u16,
    pub copy_range: u32,
    pub rcvbuf: usize,
}

pub struct Receiver {
    socket: Socket,
    next_seq: u32,
    stats: Arc<Stats>,
}

impl Receiver {
    /// Open the netlink socket and enlarge its receive buffer.
    /// SO_RCVBUFFORCE bypasses net.core.rmem_max but needs CAP_NET_ADMIN —
    /// which the NFLOG bind needs anyway. Falls back to plain SO_RCVBUF.
    pub fn open(rcvbuf: usize, stats: Arc<Stats>) -> Result<Receiver, String> {
        let mut socket =
            Socket::new(NETLINK_NETFILTER).map_err(|e| format!("netlink socket: {e}"))?;
        socket
            .bind_auto()
            .map_err(|e| format!("netlink bind: {e}"))?;
        set_receive_buffer(socket.as_raw_fd(), rcvbuf)?;
        Ok(Receiver {
            socket,
            next_seq: 1,
            stats,
        })
    }

    /// Bind to the NFLOG group and set copy mode. Mirrors the sequence
    /// every NFLOG consumer uses (ulogd2, libnetfilter_log, go-nflog):
    /// unbind any existing handler, bind to the protocol family, bind to
    /// the group, then set copy mode and range.
    pub fn configure(&mut self, cfg: &ReceiverConfig) -> Result<(), String> {
        for request in [
            ConfigRequest::unbind_pf(),
            ConfigRequest::bind_pf(),
            ConfigRequest::bind_group(cfg.nflog_group),
            ConfigRequest::copy_packet(cfg.nflog_group, cfg.copy_range),
        ] {
            self.request_ack(&request)?;
        }
        Ok(())
    }

    /// Send one config request and wait for its ACK.
    fn request_ack(&mut self, request: &ConfigRequest) -> Result<(), String> {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let mut msg = request.to_netlink_message(seq);
        msg.finalize();
        let mut buf = vec![0u8; msg.buffer_len()];
        msg.serialize(&mut buf);
        self.socket
            .send(&buf, 0)
            .map_err(|e| format!("netlink send: {e}"))?;

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        // netlink_sys::Socket::recv expects a bytes::BufMut: it writes into
        // the spare capacity past len, so the buffer must start empty.
        let mut buf: Vec<u8> = Vec::with_capacity(8192);
        loop {
            if std::time::Instant::now() > deadline {
                return Err(format!("timeout waiting for ACK (seq {seq})"));
            }
            buf.clear();
            if let Err(e) = self.socket.recv(&mut buf, 0) {
                if e.raw_os_error() == Some(libc::ENOBUFS) {
                    self.stats.drop_kernel();
                    continue;
                }
                return Err(format!("netlink recv: {e}"));
            }
            if let Some(result) = matching_ack(&buf, seq) {
                return result;
            }
        }
    }

    /// Receive loop: parse NFLOG packets off the socket and hand them to
    /// the pipeline queue. Never blocks on downstream work — a full queue
    /// drops with accounting.
    pub fn run(&mut self, queue: SyncSender<NflogPacket>, shutdown: &AtomicBool) {
        let mut buf: Vec<u8> = Vec::with_capacity(1024 * 1024);
        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            // poll so shutdown is noticed promptly even without traffic
            let poll = libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let mut poll = poll;
            // SAFETY: poll is a valid libc::pollfd pointing at one element;
            // poll only mutates it and never retains the pointer.
            let r = unsafe { libc::poll(&mut poll, 1, 1000) };
            if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                eprintln!("poll failed: {}", std::io::Error::last_os_error());
                break;
            }
            if poll.revents & libc::POLLIN == 0 {
                continue;
            }
            buf.clear();
            if let Err(e) = self.socket.recv(&mut buf, 0) {
                if e.raw_os_error() == Some(libc::ENOBUFS) {
                    // kernel dropped queued packets; the count is
                    // per-overflow-event, not per-packet
                    self.stats.drop_kernel();
                } else {
                    self.stats.parse_errors.inc();
                    eprintln!("netlink recv error: {e}");
                }
                continue;
            }
            if !dispatch_datagram(&self.stats, &buf, &queue) {
                return;
            }
        }
    }

    /// Best-effort unbind on shutdown so the kernel instance is released.
    pub fn unbind(&mut self, group: u16) {
        let _ = self.request_ack(&ConfigRequest::unbind_group(group));
    }
}

/// Feed one received datagram into the pipeline queue. Returns false when
/// the queue is disconnected, telling the run loop to return.
fn dispatch_datagram(stats: &Stats, buf: &[u8], queue: &SyncSender<NflogPacket>) -> bool {
    for range in wire::message_ranges(buf) {
        let Ok(msg) = NetlinkMessage::<NflogPacket>::deserialize(&buf[range]) else {
            stats.parse_errors.inc();
            continue;
        };
        match &msg.payload {
            NetlinkPayload::InnerMessage(pkt) => {
                stats.received.inc();
                match queue.try_send(pkt.clone()) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        stats.drop_queue_recv();
                    }
                    Err(TrySendError::Disconnected(_)) => return false,
                }
            }
            // ACKs and errors can only appear while we are in the
            // handshake, not in the receive loop.
            _ => continue,
        }
    }
    true
}

/// Find the ACK/NACK answering `seq` in one received datagram.
/// Some(Ok(())) is the ACK, Some(Err(..)) the NACK, None means no
/// matching message: keep waiting.
fn matching_ack(buf: &[u8], seq: u32) -> Option<Result<(), String>> {
    for range in wire::message_ranges(buf) {
        let Ok(msg) = NetlinkMessage::<ConfigRequest>::deserialize(&buf[range]) else {
            continue;
        };
        if msg.header.sequence_number != seq {
            continue;
        }
        return Some(wire::check_ack(&msg).map_err(|e| e.to_string()));
    }
    None
}

fn set_receive_buffer(fd: i32, size: usize) -> Result<(), String> {
    let sz = size as libc::c_uint;
    // SAFETY: fd is an open socket (owned by Receiver), sz is a valid
    // c-sized option value of the size passed as optlen.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    // EPERM without CAP_NET_ADMIN: fall back to the capped variant
    // SAFETY: same fd and option-value shape as SO_RCVBUFFORCE above.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        eprintln!(
            "Warning: SO_RCVBUFFORCE not permitted (no CAP_NET_ADMIN?), \
used SO_RCVBUF: size is capped by net.core.rmem_max"
        );
        return Ok(());
    }
    Err(format!(
        "setsockopt SO_RCVBUF: {}",
        std::io::Error::last_os_error()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::NLMSG_ERROR;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::sync_channel;

    /// One NFLOG attribute (NLA) with 4-byte alignment padding.
    fn nla(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = (4 + payload.len() as u16).to_le_bytes().to_vec();
        v.extend_from_slice(&kind.to_le_bytes());
        v.extend_from_slice(payload);
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        v
    }

    /// A NFULNL_MSG_PACKET netlink message carrying prefix + payload.
    fn packet_msg(prefix: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut attrs = nla(10, prefix); // ATTR_PREFIX
        attrs.extend(nla(9, payload)); // ATTR_PAYLOAD
        let mut msg = Vec::new();
        let len = 20 + attrs.len();
        msg.extend_from_slice(&(len as u32).to_le_bytes());
        msg.extend_from_slice(&wire::packet_msg_type().to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes()); // seq
        msg.extend_from_slice(&0u32.to_le_bytes()); // pid
        msg.extend_from_slice(&[0, 0, 0, 0]); // nfgenmsg
        msg.extend_from_slice(&attrs);
        msg
    }

    /// An NLMSG_ERROR message (ACK for code 0, NACK for nonzero codes).
    fn error_msg(seq: u32, code: i32) -> Vec<u8> {
        let mut msg = Vec::new();
        let len = 16 + 4 + 16; // nlmsghdr + error code + orig header
        msg.extend_from_slice(&(len as u32).to_le_bytes());
        msg.extend_from_slice(&NLMSG_ERROR.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&seq.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        msg.extend_from_slice(&code.to_le_bytes()); // 0 = ACK, -errno = NACK
        msg.extend_from_slice(&[0u8; 16]); // original request header
        msg
    }

    fn counter(stats: &Stats) -> u64 {
        stats.dropped_with_label("queue_recv")
    }

    #[test]
    fn set_receive_buffer_on_bad_fd_fails() {
        // fd -1 is never a valid descriptor: both setsockopts must fail
        let err = set_receive_buffer(-1, 64 * 1024).unwrap_err();
        assert!(err.contains("setsockopt"), "err: {err}");
    }

    #[test]
    fn dispatch_delivers_parsed_packets() {
        let stats = Stats::default();
        let (tx, rx) = sync_channel(4);
        assert!(dispatch_datagram(
            &stats,
            &packet_msg(b"fw-drop\0", b"\xde\xad\xbe\xef"),
            &tx
        ));
        let pkt = rx.try_recv().expect("packet queued");
        assert_eq!(pkt.prefix.as_deref(), Some("fw-drop"));
        assert_eq!(pkt.payload.as_deref(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
        assert_eq!(stats.parse_errors.get(), 0);
    }

    #[test]
    fn dispatch_skips_unparseable_messages_and_counts_them() {
        let stats = Stats::default();
        let (tx, rx) = sync_channel(4);
        // an unparsable message (valid length, foreign type) followed
        // by a valid packet in the same datagram
        let mut datagram = vec![0u8; 20];
        datagram[0] = 20; // valid nlmsg_len
        datagram[5] = 0x05; // type 0x0500: not NFULNL_MSG_PACKET
        datagram.extend_from_slice(&packet_msg(b"x\0", b"p"));
        assert!(dispatch_datagram(&stats, &datagram, &tx));
        assert_eq!(stats.parse_errors.get(), 1);
        assert!(rx.try_recv().is_ok(), "valid packet still delivered");
    }

    #[test]
    fn dispatch_ignores_non_packet_messages() {
        let stats = Stats::default();
        let (tx, rx) = sync_channel(4);
        assert!(dispatch_datagram(&stats, &error_msg(7, 0), &tx));
        assert!(rx.try_recv().is_err(), "ACK is not a packet");
        assert_eq!(stats.parse_errors.get(), 0);
    }

    #[test]
    fn dispatch_counts_drops_when_queue_is_full() {
        let stats = Stats::default();
        let (tx, rx) = sync_channel(1);
        tx.send(NflogPacket::default()).expect("fill the queue");
        assert!(dispatch_datagram(&stats, &packet_msg(b"x\0", b"p"), &tx));
        assert_eq!(counter(&stats), 1);
        drop(rx); // silence unused warnings for the receiver end
    }

    #[test]
    fn dispatch_stops_when_queue_is_disconnected() {
        let stats = Stats::default();
        let (tx, rx) = sync_channel(1);
        drop(rx);
        assert!(!dispatch_datagram(&stats, &packet_msg(b"x\0", b"p"), &tx));
    }

    #[test]
    fn matching_ack_accepts_the_ack_for_our_sequence() {
        let datagram = error_msg(5, 0);
        assert_eq!(matching_ack(&datagram, 5), Some(Ok(())));
        // a different sequence number: not ours, keep waiting
        assert_eq!(matching_ack(&datagram, 6), None);
    }

    #[test]
    fn matching_ack_reports_nacks() {
        let datagram = error_msg(3, -1); // -EPERM
        let result = matching_ack(&datagram, 3).expect("NACK matches our seq");
        let err = result.expect_err("NACK is an error");
        assert!(err.contains("not permitted"), "err: {err}");
    }

    #[test]
    fn matching_ack_skips_garbage_and_non_matching_messages() {
        // a non-ACK message (valid length, foreign type) followed by an ACK
        let mut datagram = vec![0u8; 20];
        datagram[0] = 20; // valid nlmsg_len
        datagram[5] = 0x05; // type 0x0500: not NLMSG_ERROR
        datagram.extend_from_slice(&error_msg(8, 0));
        assert_eq!(matching_ack(&datagram, 8), Some(Ok(())));
        assert_eq!(matching_ack(&datagram, 9), None);
    }

    /// The real run() loop against the kernel: sending a config request
    /// makes the kernel answer with an NLMSG_ERROR NACK (EPERM without
    /// CAP_NET_ADMIN; an ACK as root), which run() must receive and
    /// ignore, then exit on shutdown.
    #[test]
    fn run_receives_and_ignores_kernel_nack() {
        let stats = Arc::new(Stats::default());
        let mut recv = Receiver::open(64 * 1024, Arc::clone(&stats)).expect("open");
        let (tx, queue) = sync_channel(1);
        // NACK the kernel is about to send is not for us to queue
        drop(queue);

        let mut msg = ConfigRequest::bind_group(42).to_netlink_message(99);
        msg.finalize();
        let mut buf = vec![0u8; msg.buffer_len()];
        msg.serialize(&mut buf);
        recv.socket.send(&buf, 0).expect("send request");

        let shutdown = Arc::new(AtomicBool::new(false));
        let run_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            recv.run(tx, &run_shutdown);
        });
        // the NACK arrives while the loop is polling; give it a moment
        std::thread::sleep(Duration::from_millis(300));
        shutdown.store(true, Ordering::Relaxed);
        handle.join().expect("run loop exits");

        // the NACK is not a packet: nothing was parsed, dropped or queued
        assert_eq!(stats.parse_errors.get(), 0);
        assert_eq!(stats.dropped_with_label("queue_recv"), 0);
    }
}
