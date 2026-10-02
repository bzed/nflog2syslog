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

//! Golden tests for the JSON record metadata: every NFLOG attribute set,
//! hook/ARPHRD/EtherType name mapping, timestamps, hw_addr hex, and the
//! formatter buffer reuse across packets.

use nflog2syslog::format::Formatter;
use nflog2syslog::wire::NflogPacket;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

/// Minimal valid IPv4+UDP packet so the layers object is non-error.
fn ipv4_udp() -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&28u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[64, 17]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&5353u16.to_be_bytes());
    pkt.extend_from_slice(&5353u16.to_be_bytes());
    pkt.extend_from_slice(&8u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt
}

fn format_json(fmt: &mut Formatter, pkt: &NflogPacket, errors: &AtomicU64) -> Value {
    serde_json::from_str(&fmt.format(pkt, errors)).expect("valid JSON")
}

#[test]
fn full_metadata_record() {
    let pkt = NflogPacket {
        hw_protocol: Some(0x0800),
        hook: Some(2),
        mark: Some(0xcafe_f00d),
        timestamp: Some((1727700000, 789012)),
        in_dev: Some(1),
        out_dev: Some(0),
        phys_in_dev: Some(u32::MAX),
        phys_out_dev: Some(0),
        hw_addr: Some(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        payload: Some(ipv4_udp()),
        prefix: Some("fw-drop".to_string()),
        uid: Some(1000),
        gid: Some(100),
        seq: Some(7),
        seq_global: Some(8),
        hw_type: Some(1), // ARPHRD_ETHER
    };
    let mut fmt = Formatter::new();
    let errors = AtomicU64::new(0);
    // two packets through the same formatter: the dissect buffer is reused
    let json = format_json(&mut fmt, &pkt, &errors);
    let again = format_json(&mut fmt, &pkt, &errors);
    assert_eq!(json, again);
    assert_eq!(errors.load(Ordering::Relaxed), 0);

    assert_eq!(json["prefix"], "fw-drop");
    assert_eq!(json["timestamp"], "2024-09-30T12:40:00.789012Z");
    assert_eq!(json["in_dev"], "lo");
    assert!(json["out_dev"].is_null(), "ifindex 0 means unset");
    assert_eq!(json["phys_in_dev"], "<invalid>");
    assert!(json["phys_out_dev"].is_null());
    assert_eq!(json["hook"], "forward");
    assert_eq!(json["hw_type"], "ETHER");
    assert_eq!(json["hw_protocol"], "IP");
    assert_eq!(json["hw_addr"], "00:11:22:33:44:55");
    assert_eq!(json["uid"], 1000);
    assert_eq!(json["gid"], 100);
    assert_eq!(json["mark"].as_u64(), Some(0xcafe_f00d));
    assert_eq!(json["seq"], 7);
    assert_eq!(json["seq_global"], 8);
    assert!(json["layers"].is_object());
    assert!(json["layers"]["UDP"].is_object());
}

#[test]
fn empty_packet_is_all_nulls() {
    let pkt = NflogPacket::default();
    let mut fmt = Formatter::new();
    let errors = AtomicU64::new(0);
    let json = format_json(&mut fmt, &pkt, &errors);
    for key in [
        "prefix",
        "timestamp",
        "in_dev",
        "out_dev",
        "phys_in_dev",
        "phys_out_dev",
        "hook",
        "hw_type",
        "hw_protocol",
        "hw_addr",
        "uid",
        "gid",
        "mark",
        "seq",
        "seq_global",
        "layers",
    ] {
        assert!(json[key].is_null(), "{key} = {}", json[key]);
    }
}

#[test]
fn unknown_enums_fall_back_to_numeric_names() {
    let pkt = NflogPacket {
        hw_protocol: Some(0x9999),
        hook: Some(9),
        hw_type: Some(0x1234),
        payload: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        ..Default::default()
    };
    let mut fmt = Formatter::new();
    let errors = AtomicU64::new(0);
    let json = format_json(&mut fmt, &pkt, &errors);
    assert_eq!(json["hook"], "unknown");
    assert_eq!(json["hw_type"], "<hwtype=0x1234>");
    assert_eq!(json["hw_protocol"], "<ether-type=0x9999>");
    // an unknown EtherType still dissects as raw IP (and fails: not a packet)
    assert!(json["layers"]["error"].is_string());
    assert_eq!(errors.load(Ordering::Relaxed), 1);
}

#[test]
fn out_of_range_timestamp_is_null() {
    // outside OffsetDateTime's range entirely
    let pkt = NflogPacket {
        timestamp: Some((i64::MAX, 0)),
        payload: None,
        ..Default::default()
    };
    let mut fmt = Formatter::new();
    let errors = AtomicU64::new(0);
    let json = format_json(&mut fmt, &pkt, &errors);
    assert!(json["timestamp"].is_null());
}

#[test]
fn timestamp_beyond_rfc3339_year_is_null() {
    // year 10000: a valid OffsetDateTime, but RFC 3339 has 4-digit years
    let pkt = NflogPacket {
        timestamp: Some((253_402_300_800, 0)),
        payload: None,
        ..Default::default()
    };
    let mut fmt = Formatter::new();
    let errors = AtomicU64::new(0);
    let json = format_json(&mut fmt, &pkt, &errors);
    assert!(json["timestamp"].is_null());
}

#[test]
fn interface_names_resolve_and_invalid_ones_are_marked() {
    // loopback is ifindex 1 on Linux; u32::MAX never resolves
    let pkt = NflogPacket {
        in_dev: Some(1),
        out_dev: Some(u32::MAX),
        payload: None,
        ..Default::default()
    };
    let mut fmt = Formatter::new();
    let errors = AtomicU64::new(0);
    let json = format_json(&mut fmt, &pkt, &errors);
    assert_eq!(json["in_dev"], "lo");
    assert_eq!(json["out_dev"], "<invalid>");
}

#[test]
fn all_arphrd_names_resolve() {
    for (hw_type, name) in [
        (libc::ARPHRD_ETHER, "ETHER"),
        (libc::ARPHRD_LOOPBACK, "LOOPBACK"),
        (libc::ARPHRD_PPP, "PPP"),
        (libc::ARPHRD_IPGRE, "IPGRE"),
        (libc::ARPHRD_SIT, "SIT"),
        (libc::ARPHRD_TUNNEL, "TUNNEL"),
        (libc::ARPHRD_IEEE802, "IEEE802"),
        (libc::ARPHRD_IEEE80211, "IEEE80211"),
        (libc::ARPHRD_NONE, "NONE"),
        (libc::ARPHRD_VOID, "VOID"),
    ] {
        let pkt = NflogPacket {
            hw_type: Some(hw_type),
            payload: None,
            ..Default::default()
        };
        let mut fmt = Formatter::new();
        let errors = AtomicU64::new(0);
        let json = format_json(&mut fmt, &pkt, &errors);
        assert_eq!(json["hw_type"], name, "hw_type {hw_type}");
    }
}

#[test]
fn all_ethertype_names_resolve() {
    for (hw_protocol, name) in [
        (libc::ETH_P_IP, "IP"),
        (libc::ETH_P_IPV6, "IPV6"),
        (libc::ETH_P_ARP, "ARP"),
        (libc::ETH_P_RARP, "RARP"),
        (libc::ETH_P_8021Q, "8021Q"),
        (libc::ETH_P_8021AD, "8021AD"),
        (libc::ETH_P_PPP_SES, "PPP_SES"),
        (libc::ETH_P_MPLS_UC, "MPLS_UC"),
        (libc::ETH_P_MPLS_MC, "MPLS_MC"),
    ] {
        let pkt = NflogPacket {
            hw_protocol: Some(hw_protocol as u16),
            payload: None, // no payload: dissection yields null layers
            ..Default::default()
        };
        let mut fmt = Formatter::new();
        let errors = AtomicU64::new(0);
        let json = format_json(&mut fmt, &pkt, &errors);
        assert_eq!(json["hw_protocol"], name, "hw_protocol {hw_protocol:#06x}");
    }
}

#[test]
fn all_hook_names_resolve() {
    for (hook, name) in [
        (0, "prerouting"),
        (1, "input"),
        (2, "forward"),
        (3, "output"),
        (4, "postrouting"),
        (9, "unknown"),
    ] {
        let pkt = NflogPacket {
            hook: Some(hook),
            payload: None,
            ..Default::default()
        };
        let mut fmt = Formatter::new();
        let errors = AtomicU64::new(0);
        let json = format_json(&mut fmt, &pkt, &errors);
        assert_eq!(json["hook"], name, "hook {hook}");
    }
}
