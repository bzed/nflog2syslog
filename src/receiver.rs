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
                    self.stats.kernel_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                return Err(format!("netlink recv: {e}"));
            }
            for range in wire::message_ranges(&buf) {
                let Ok(msg) = NetlinkMessage::<ConfigRequest>::deserialize(&buf[range]) else {
                    continue;
                };
                if msg.header.sequence_number != seq {
                    continue;
                }
                return wire::check_ack(&msg).map_err(|e| e.to_string());
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
                    self.stats.kernel_dropped.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!("netlink recv error: {e}");
                }
                continue;
            }
            for range in wire::message_ranges(&buf) {
                let Ok(msg) = NetlinkMessage::<NflogPacket>::deserialize(&buf[range]) else {
                    self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                match &msg.payload {
                    NetlinkPayload::InnerMessage(pkt) => match queue.try_send(pkt.clone()) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            self.stats.recv_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(TrySendError::Disconnected(_)) => return,
                    },
                    // ACKs and errors can only appear while we are in the
                    // handshake, not in the receive loop.
                    _ => continue,
                }
            }
        }
    }

    /// Best-effort unbind on shutdown so the kernel instance is released.
    pub fn unbind(&mut self, group: u16) {
        let _ = self.request_ack(&ConfigRequest::unbind_group(group));
    }
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
