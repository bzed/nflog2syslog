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

//! Golden tests for the JSON output: synthetic packets through the full
//! nflog-event -> dissection -> JSON path.

use nflog2syslog::format::Formatter;
use nflog2syslog::wire::NflogPacket;
use serde_json::Value;
use std::sync::atomic::AtomicU64;

fn format_packet(hw_protocol: u16, payload: &[u8]) -> Value {
    let pkt = NflogPacket {
        hw_protocol: Some(hw_protocol),
        hook: Some(2),
        prefix: Some("golden".to_string()),
        payload: Some(payload.to_vec()),
        ..Default::default()
    };
    let mut fmt = Formatter::new();
    let errors = AtomicU64::new(0);
    let json: Value = serde_json::from_str(&fmt.format(&pkt, &errors)).expect("valid JSON");
    assert_eq!(errors.load(std::sync::atomic::Ordering::Relaxed), 0);
    json
}

/// IPv4 header (20 bytes) + UDP header + DNS query for "example.com".
fn ipv4_udp_dns() -> Vec<u8> {
    let mut pkt = Vec::new();
    // IPv4: ver/ihl 0x45, tos 0, total len 20+8+31=59
    let dns_len = 12 + 1 + 7 + 4 + 1 + 4 + 4;
    let total = 20 + 8 + dns_len;
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // id, flags
    pkt.extend_from_slice(&[64, 17]); // ttl, proto=UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum (not verified)
    pkt.extend_from_slice(&[10, 0, 0, 1]); // src
    pkt.extend_from_slice(&[10, 0, 0, 2]); // dst
                                           // UDP: sport 40000, dport 53, len 8+dns_len, checksum 0
    pkt.extend_from_slice(&40000u16.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&((8 + dns_len) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    // DNS: txid 0x1234, flags 0x0100, qd=1, an/ns/ar=0
    pkt.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    // question: 7"example" 3"com" 0, type A, class IN
    pkt.extend_from_slice(&[7]);
    pkt.extend_from_slice(b"example");
    pkt.extend_from_slice(&[3]);
    pkt.extend_from_slice(b"com");
    pkt.extend_from_slice(&[0]);
    pkt.extend_from_slice(&[0, 1, 0, 1]);
    pkt
}

#[test]
fn ipv4_udp_dns_layers() {
    let json = format_packet(0x0800, &ipv4_udp_dns());
    let layers = &json["layers"];
    let names: Vec<&str> = layers
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    assert!(names.contains(&"IPv4"), "layers: {names:?}");
    assert!(names.contains(&"UDP"), "layers: {names:?}");
    assert!(names.contains(&"DNS"), "layers: {names:?}");
    assert_eq!(json["prefix"], "golden");
    assert_eq!(json["hook"], "forward");
    assert_eq!(json["hw_protocol"], "IP");
    assert_eq!(json["layers"]["IPv4"]["src"], "10.0.0.1");
    assert_eq!(json["layers"]["IPv4"]["dst"], "10.0.0.2");
    assert_eq!(json["layers"]["UDP"]["dst_port"], 53);
}

/// ARP request (28 bytes), entered via the ETH_P_ARP path.
#[test]
fn arp_layer() {
    let mut arp = Vec::new();
    arp.extend_from_slice(&[0x00, 0x01]); // htype: Ethernet
    arp.extend_from_slice(&[0x08, 0x00]); // ptype: IPv4
    arp.extend_from_slice(&[0x06, 0x04]); // hlen, plen
    arp.extend_from_slice(&[0x00, 0x01]); // oper: request
    arp.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // sha
    arp.extend_from_slice(&[192, 168, 1, 1]); // spa
    arp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // tha
    arp.extend_from_slice(&[192, 168, 1, 2]); // tpa

    let json = format_packet(0x0806, &arp);
    let layers = &json["layers"];
    assert!(
        layers.as_object().unwrap().contains_key("ARP"),
        "layers: {layers}"
    );
    assert_eq!(json["hw_protocol"], "ARP");
}

/// A payload that is not a parseable packet must yield an error layer,
/// not a panic.
#[test]
fn garbage_payload_reports_error() {
    let mut fmt = Formatter::new();
    let errors = AtomicU64::new(0);
    let pkt = NflogPacket {
        hw_protocol: Some(0x0800),
        payload: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        ..Default::default()
    };
    let json = fmt.format(&pkt, &errors);
    assert!(json.contains("error"), "json: {json}");
}

/// No payload (copy mode META) -> layers null.
#[test]
fn no_payload_is_null_layers() {
    let mut fmt = Formatter::new();
    let errors = AtomicU64::new(0);
    let pkt = NflogPacket {
        hw_protocol: Some(0x0800),
        payload: None,
        ..Default::default()
    };
    let json: Value = serde_json::from_str(&fmt.format(&pkt, &errors)).unwrap();
    assert!(json["layers"].is_null());
}

/// IPv4 + ICMP echo request.
#[test]
fn ipv4_icmp_layers() {
    let mut pkt = Vec::new();
    // IPv4: 20 bytes header, proto ICMP
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&28u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[64, 1]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    // ICMP echo request: type 8, code 0, checksum, id, seq
    pkt.extend_from_slice(&[8, 0, 0x00, 0x00, 0xab, 0xcd, 0x00, 0x01]);

    let json = format_packet(0x0800, &pkt);
    let layers = &json["layers"];
    assert!(layers.as_object().unwrap().contains_key("IPv4"));
    assert!(
        layers.as_object().unwrap().contains_key("ICMP"),
        "layers: {layers}"
    );
}

/// IPv4 + GRE + IPv4 (tunneling): the registry chains through GRE.
#[test]
fn ipv4_gre_tunnel_layers() {
    // inner IPv4 header (20 bytes) + 8 bytes ICMP-ish payload
    let mut inner = Vec::new();
    inner.extend_from_slice(&[0x45, 0x00]);
    inner.extend_from_slice(&28u16.to_be_bytes());
    inner.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    inner.extend_from_slice(&[64, 1]);
    inner.extend_from_slice(&[0x00, 0x00]);
    inner.extend_from_slice(&[192, 168, 1, 1]);
    inner.extend_from_slice(&[192, 168, 1, 2]);
    inner.extend_from_slice(&[8, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // GRE header: flags/version 0x0000, protocol type IPv4 (0x0800)
    let mut gre = Vec::new();
    gre.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]);
    gre.extend_from_slice(&inner);

    // outer IPv4 header, proto GRE (47)
    let mut pkt = Vec::new();
    let total = 20 + gre.len();
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[64, 47]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&gre);

    let json = format_packet(0x0800, &pkt);
    let layers = &json["layers"];
    let names: Vec<&str> = layers
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    assert!(names.contains(&"IPv4"), "layers: {names:?}");
    assert!(names.contains(&"GRE"), "layers: {names:?}");
    // inner IPv4 layer: two IPv4 objects are merged by layer name; the
    // important part is that dissection chained through the tunnel
    assert!(names.contains(&"ICMP"), "layers: {names:?}");
}

/// IPv6 + UDP packet.
#[test]
fn ipv6_udp_layers() {
    let mut pkt = Vec::new();
    // IPv6: version 6, payload len 8, next header UDP(17), hop limit 64
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40]);
    pkt.extend_from_slice(&[0xfd; 16]); // src
    pkt.extend_from_slice(&[0x01; 16]); // dst
                                        // UDP
    pkt.extend_from_slice(&12345u16.to_be_bytes());
    pkt.extend_from_slice(&514u16.to_be_bytes());
    pkt.extend_from_slice(&8u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);

    let json = format_packet(0x86dd, &pkt);
    let layers = &json["layers"];
    assert!(layers.as_object().unwrap().contains_key("IPv6"));
    assert!(layers.as_object().unwrap().contains_key("UDP"));
    assert_eq!(json["hw_protocol"], "IPV6");
}
