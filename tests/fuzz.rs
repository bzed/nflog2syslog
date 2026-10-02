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

//! Fuzz-style tests: garbage in, no panics out.
//!
//! A deterministic, seeded PRNG (splitmix64) generates garbage packets,
//! so every failure reproduces by rerunning the test. No fuzzing
//! dependency; it runs as part of the normal test suite.
//!
//! Three strategies:
//! 1. `dissectors_survive_garbage_payloads`: wraps random bytes for every
//!    enabled dissector's entry vector (IP protocol, UDP port, link type)
//!    and pushes them through the full format() path.
//! 2. `dissectors_survive_mutations_of_valid_packets`: flips, truncates,
//!    splices and randomizes bytes of known-valid packets - deeper reach
//!    into the parsers than pure noise.
//! 3. `wire_parsing_survives_garbage`: random datagrams and random
//!    attribute streams through the NFLOG wire parser.
//!
//! The invariant under test: no panic, and the output is always valid
//! JSON. A parse failure is a *result* (an error layer or a parse-error
//! counter), never a crash.

use netlink_packet_core::NetlinkMessage;
use nflog2syslog::format::Formatter;
use nflog2syslog::wire::{message_ranges, packet_msg_type, NflogPacket};
use serde_json::Value;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::AtomicU64;

/// splitmix64: 6 lines, deterministic, good enough for byte noise.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Up to `max_len` random bytes (length itself random).
    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = (self.next() % max_len as u64) as usize;
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn below(&mut self, n: u64) -> usize {
        (self.next() % n) as usize
    }
}

// ---------------------------------------------------------------------------
// packet wrappers: valid transport headers around a garbage payload, so
// the chain reaches the target dissector which then meets the noise

fn ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut pkt = Vec::with_capacity(total);
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&(total.min(u16::MAX as usize) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // id, flags
    pkt.extend_from_slice(&[64, proto]);
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum (not verified)
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(payload);
    pkt
}

fn ipv4_udp(dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&40000u16.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&(udp_len.min(u16::MAX as usize) as u16).to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]);
    udp.extend_from_slice(payload);
    ipv4(17, &udp)
}

fn ipv4_tcp(dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&40000u16.to_be_bytes()); // sport
    tcp.extend_from_slice(&dport.to_be_bytes()); // dport
    tcp.extend_from_slice(&0u32.to_be_bytes()); // seq
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
    tcp.extend_from_slice(&[0x50, 0x18]); // data offset 5, flags PSH|ACK
    tcp.extend_from_slice(&0x1000u16.to_be_bytes()); // window
    tcp.extend_from_slice(&[0x00, 0x00]); // checksum
    tcp.extend_from_slice(&[0x00, 0x00]); // urgent ptr
    tcp.extend_from_slice(payload);
    ipv4(6, &tcp)
}

fn ipv6(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&(payload.len().min(u16::MAX as usize) as u16).to_be_bytes());
    pkt.extend_from_slice(&[next, 64]);
    pkt.extend_from_slice(&[0xfd; 16]);
    pkt.extend_from_slice(&[0x01; 16]);
    pkt.extend_from_slice(payload);
    pkt
}

fn ipv6_udp(dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::new();
    udp.extend_from_slice(&5353u16.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&(udp_len.min(u16::MAX as usize) as u16).to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]);
    udp.extend_from_slice(payload);
    ipv6(17, &udp)
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IPV6: u16 = 0x86dd;

/// One fuzz vector: a name, the hw_protocol it is entered with, and the
/// wrapper that packs garbage bytes into a valid transport around it.
type Vector = (&'static str, u16, fn(&[u8]) -> Vec<u8>);

/// The entry vector table. One entry per enabled dissector (see
/// Cargo.toml features and the registry in packet-dissector); the
/// wrapper guarantees the chain reaches it.
fn vectors() -> Vec<Vector> {
    vec![
        // link-type entries (raw IP dispatch, ARP direct entry)
        ("raw-ip-v4", ETH_P_IP, |p| p.to_vec()),
        ("raw-ip-v6", ETH_P_IPV6, |p| p.to_vec()),
        ("arp", ETH_P_ARP, |p| p.to_vec()),
        // IP protocol entries via IPv4
        ("icmp", ETH_P_IP, |p| ipv4(1, p)),
        ("tcp", ETH_P_IP, |p| ipv4(6, p)),
        ("udp", ETH_P_IP, |p| ipv4(17, p)),
        ("gre", ETH_P_IP, |p| ipv4(47, p)),
        ("esp", ETH_P_IP, |p| ipv4(50, p)),
        ("ah", ETH_P_IP, |p| ipv4(51, p)),
        // ICMPv6 via IPv6
        ("icmpv6", ETH_P_IPV6, |p| ipv6(58, p)),
        // UDP-port entries
        ("dns", ETH_P_IP, |p| ipv4_udp(53, p)),
        ("mdns", ETH_P_IP, |p| ipv4_udp(5353, p)),
        ("llmnr", ETH_P_IP, |p| ipv4_udp(5355, p)),
        ("ntp", ETH_P_IP, |p| ipv4_udp(123, p)),
        ("dhcp-67", ETH_P_IP, |p| ipv4_udp(67, p)),
        ("dhcp-68", ETH_P_IP, |p| ipv4_udp(68, p)),
        ("dhcpv6-546", ETH_P_IP, |p| ipv4_udp(546, p)),
        ("dhcpv6-547", ETH_P_IP, |p| ipv4_udp(547, p)),
        ("snmp-161", ETH_P_IP, |p| ipv4_udp(161, p)),
        ("snmp-162", ETH_P_IP, |p| ipv4_udp(162, p)),
        ("l2tp-1701", ETH_P_IP, |p| ipv4_udp(1701, p)),
        ("vxlan-4789", ETH_P_IP, |p| ipv4_udp(4789, p)),
        // TCP-port entries (DNS over TCP, LLMNR over TCP)
        ("dns-tcp", ETH_P_IP, |p| ipv4_tcp(53, p)),
        ("llmnr-tcp", ETH_P_IP, |p| ipv4_tcp(5355, p)),
        // IPv6 + UDP (UDP dispatch on v6 too)
        ("ipv6-udp", ETH_P_IPV6, |p| ipv6_udp(53, p)),
    ]
}

/// One packet through the full format() path; panics are caught so the
/// failure message contains the offending bytes.
fn format_one(fmt: &mut Formatter, pkt: &NflogPacket, errors: &AtomicU64) -> String {
    let result = catch_unwind(AssertUnwindSafe(|| fmt.format(pkt, errors)));
    match result {
        Ok(json) => json,
        Err(panic) => {
            let payload = pkt.payload.as_deref().unwrap_or(&[]);
            let hook = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            panic!("format() panicked ({hook}) on payload {payload:02x?}");
        }
    }
}

#[test]
fn dissectors_survive_garbage_payloads() {
    for (idx, (name, hw_proto, wrap)) in vectors().iter().enumerate() {
        let mut rng = Rng::new(0xfeed + idx as u64 * 997 + u64::from(*hw_proto));
        let mut fmt = Formatter::new();
        let errors = AtomicU64::new(0);
        for iteration in 0..150 {
            let payload = rng.bytes(512);
            let pkt = NflogPacket {
                hw_protocol: Some(*hw_proto),
                payload: Some(wrap(&payload)),
                hook: Some(2),
                prefix: Some("fuzz".to_string()),
                ..Default::default()
            };
            let json = format_one(&mut fmt, &pkt, &errors);
            let parsed: Value = serde_json::from_str(&json).unwrap_or_else(|_| {
                panic!("vector {name:?} iteration {iteration}: invalid JSON: {json}")
            });
            // either a layers object, an error layer, or null - all fine
            assert!(parsed["layers"].is_object() || parsed["layers"].is_null());
        }
    }
}

// ---------------------------------------------------------------------------
// valid seeds for the mutation strategy

/// IPv4 + UDP + DNS query for "example.com" (known good: golden test).
fn ipv4_udp_dns() -> Vec<u8> {
    let dns_len = 29;
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&((20 + 8 + dns_len) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[64, 17]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&40000u16.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&((8 + dns_len) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    pkt.extend_from_slice(&[7]);
    pkt.extend_from_slice(b"example");
    pkt.extend_from_slice(&[3]);
    pkt.extend_from_slice(b"com");
    pkt.extend_from_slice(&[0, 0, 1, 0, 1]);
    pkt
}

/// IPv4 + ICMP echo request (known good).
fn ipv4_icmp() -> Vec<u8> {
    let icmp = [8, 0, 0x00, 0x00, 0xab, 0xcd, 0x00, 0x01];
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&28u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[64, 1]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&icmp);
    pkt
}

/// ARP request (known good).
fn arp() -> Vec<u8> {
    let mut arp = Vec::new();
    arp.extend_from_slice(&[0x00, 0x01]);
    arp.extend_from_slice(&[0x08, 0x00]);
    arp.extend_from_slice(&[0x06, 0x04]);
    arp.extend_from_slice(&[0x00, 0x01]);
    arp.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    arp.extend_from_slice(&[192, 168, 1, 1]);
    arp.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    arp.extend_from_slice(&[192, 168, 1, 2]);
    arp
}

/// IPv4 + UDP + DHCP DISCOVER (known good: golden test).
fn ipv4_udp_dhcp() -> Vec<u8> {
    let mut dhcp = vec![0u8; 240];
    dhcp[0] = 1;
    dhcp[1] = 1;
    dhcp[2] = 6;
    dhcp[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
    dhcp[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    dhcp[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    dhcp[236..240].copy_from_slice(&[99, 130, 83, 99]);
    dhcp.extend_from_slice(&[53, 1, 1]);
    dhcp.extend_from_slice(&[2, 4, 0xff, 0xff, 0xf2, 0x30]);
    dhcp.extend_from_slice(&[12, 4, b'h', b'o', b's', b't']);
    dhcp.extend_from_slice(&[99, 3, 0x01, 0x02, 0x03]);
    dhcp.extend_from_slice(&[255]);
    ipv4_udp(67, &dhcp)
}

/// IPv4 + UDP + NTP client request (known good: golden test).
fn ipv4_udp_ntp() -> Vec<u8> {
    let mut ntp = Vec::new();
    ntp.extend_from_slice(&[0x1b]);
    ntp.extend_from_slice(&[0, 0, 0]);
    ntp.extend_from_slice(&0u32.to_be_bytes());
    ntp.extend_from_slice(&0u32.to_be_bytes());
    ntp.extend_from_slice(&[0, 0, 0, 0]);
    ntp.extend_from_slice(&[0u8; 8]);
    ntp.extend_from_slice(&[0u8; 8]);
    ntp.extend_from_slice(&[0u8; 8]);
    ntp.extend_from_slice(&[0xe6, 0x2f, 0x8a, 0x3c, 0, 0, 0, 0]);
    ipv4_udp(123, &ntp)
}

/// IPv4 + GRE + IPv4 + ICMP (known good: the GRE tunnel golden test).
fn ipv4_gre_tunnel() -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&[0x45, 0x00]);
    inner.extend_from_slice(&28u16.to_be_bytes());
    inner.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    inner.extend_from_slice(&[64, 1]);
    inner.extend_from_slice(&[0x00, 0x00]);
    inner.extend_from_slice(&[192, 168, 1, 1]);
    inner.extend_from_slice(&[192, 168, 1, 2]);
    inner.extend_from_slice(&[8, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let mut gre = Vec::new();
    gre.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]);
    gre.extend_from_slice(&inner);

    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&((20 + gre.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[64, 47]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&gre);
    pkt
}

/// IPv6 + UDP packet (known good).
fn ipv6_udp_dns() -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40]);
    pkt.extend_from_slice(&[0xfd; 16]);
    pkt.extend_from_slice(&[0x01; 16]);
    pkt.extend_from_slice(&12345u16.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&8u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt
}

/// Mutate a valid packet: flip a bit, randomize a byte, truncate, or
/// splice in noise. Mutants stay mostly valid, reaching deeper into the
/// parsers than pure garbage.
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut pkt = seed.to_vec();
    if pkt.is_empty() {
        return pkt;
    }
    match rng.below(4) {
        0 => {
            // flip one random bit
            let pos = rng.below(pkt.len() as u64);
            pkt[pos] ^= 1 << rng.below(8);
        }
        1 => {
            // randomize one random byte
            let pos = rng.below(pkt.len() as u64);
            pkt[pos] = rng.next() as u8;
        }
        2 => {
            // truncate at a random position
            pkt.truncate(rng.below(pkt.len() as u64));
        }
        _ => {
            // splice random bytes at a random position
            let pos = rng.below(pkt.len() as u64);
            let noise = rng.bytes(64);
            let mut spliced = pkt[..pos].to_vec();
            spliced.extend_from_slice(&noise);
            spliced.extend_from_slice(&pkt[pos..]);
            pkt = spliced;
        }
    }
    pkt
}

#[test]
fn dissectors_survive_mutations_of_valid_packets() {
    let seeds: Vec<(&str, u16, Vec<u8>)> = vec![
        ("ipv4-udp-dns", ETH_P_IP, ipv4_udp_dns()),
        ("ipv4-icmp", ETH_P_IP, ipv4_icmp()),
        ("arp", ETH_P_ARP, arp()),
        ("ipv4-udp-dhcp", ETH_P_IP, ipv4_udp_dhcp()),
        ("ipv4-udp-ntp", ETH_P_IP, ipv4_udp_ntp()),
        ("ipv4-gre-tunnel", ETH_P_IP, ipv4_gre_tunnel()),
        ("ipv6-udp", ETH_P_IPV6, ipv6_udp_dns()),
    ];
    for (name, hw_proto, seed) in seeds {
        let mut rng = Rng::new(0x5eed + name.len() as u64 * 131 + u64::from(hw_proto));
        let mut fmt = Formatter::new();
        let errors = AtomicU64::new(0);
        for iteration in 0..200 {
            let mutant = mutate(&mut rng, &seed);
            let pkt = NflogPacket {
                hw_protocol: Some(hw_proto),
                payload: Some(mutant),
                hook: Some(2),
                prefix: Some("fuzz".to_string()),
                ..Default::default()
            };
            let json = format_one(&mut fmt, &pkt, &errors);
            let parsed: Value = serde_json::from_str(&json).unwrap_or_else(|_| {
                panic!("seed {name:?} iteration {iteration}: invalid JSON: {json}")
            });
            assert!(parsed["layers"].is_object() || parsed["layers"].is_null());
        }
    }
}

// ---------------------------------------------------------------------------
// wire parser fuzzing

#[test]
fn wire_parsing_survives_garbage() {
    let mut rng = Rng::new(0xBEEF);
    for _ in 0..300 {
        // (a) fully random buffers through the datagram splitter: the
        // iterator must terminate and never panic
        let garbage = rng.bytes(512);
        let ranges: Vec<_> = message_ranges(&garbage).collect();
        assert!(
            ranges.len() <= garbage.len().div_ceil(16),
            "message_ranges produced more ranges than the datagram can hold"
        );

        // (b) valid nlmsghdr + nfgenmsg + random attribute bytes: the
        // attribute parser must terminate and produce a packet or an error
        let attrs = rng.bytes(256);
        let mut msg = Vec::with_capacity(20 + attrs.len());
        msg.extend_from_slice(&((20 + attrs.len()) as u32).to_le_bytes());
        msg.extend_from_slice(&packet_msg_type().to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes()); // flags
        msg.extend_from_slice(&0u32.to_le_bytes()); // seq
        msg.extend_from_slice(&0u32.to_le_bytes()); // pid
        msg.extend_from_slice(&[0, 0, 0, 0]); // nfgenmsg
        msg.extend_from_slice(&attrs);
        let result = catch_unwind(AssertUnwindSafe(|| {
            NetlinkMessage::<NflogPacket>::deserialize(&msg)
        }));
        let Ok(parsed) = result else {
            panic!("wire parser panicked on attrs {attrs:02x?}");
        };
        if let Ok(msg) = parsed {
            if let netlink_packet_core::NetlinkPayload::InnerMessage(pkt) = &msg.payload {
                // invariants that must hold for any parseable garbage:
                // the parser clamps attribute values to what is available
                if let Some(hw_addr) = &pkt.hw_addr {
                    assert!(
                        hw_addr.len() <= 256,
                        "hw_addr longer than the attribute section: {hw_addr:02x?}"
                    );
                }
                if let Some(prefix) = &pkt.prefix {
                    assert!(
                        prefix.len() <= 256,
                        "prefix longer than the attribute section: {prefix:?}"
                    );
                }
            }
        }

        // (c) truncated messages: header claims more than the buffer has
        let truncated = &msg[..msg.len() / 2];
        let _ = catch_unwind(AssertUnwindSafe(|| {
            NetlinkMessage::<NflogPacket>::deserialize(truncated)
        }))
        .expect("truncated message must not panic");
    }
}

#[test]
fn format_survives_random_nflog_metadata() {
    // random hw_protocol values with random payloads: the link-type
    // selection and every dissect entry must hold up
    let mut rng = Rng::new(0xC0DE);
    let mut fmt = Formatter::new();
    let errors = AtomicU64::new(0);
    for iteration in 0..300 {
        let hw_protocol = rng.next() as u16;
        let payload = rng.bytes(256);
        let pkt = NflogPacket {
            hw_protocol: Some(hw_protocol),
            hook: Some(rng.next() as u8),
            hw_type: Some(rng.next() as u16),
            mark: Some(rng.next() as u32),
            timestamp: Some((rng.next() as i64, rng.next() as i64)),
            payload: Some(payload.clone()),
            ..Default::default()
        };
        let json = format_one(&mut fmt, &pkt, &errors);
        let parsed: Value = serde_json::from_str(&json)
            .unwrap_or_else(|_| panic!("iteration {iteration}: invalid JSON: {json}"));
        assert!(parsed["layers"].is_object() || parsed["layers"].is_null());
    }
}
