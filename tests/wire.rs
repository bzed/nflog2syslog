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

//! Wire protocol tests: byte-exact fixtures for config request encoding and
//! packet attribute parsing.

use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLMSG_ERROR};
use nflog2syslog::wire::{check_ack, message_ranges, ConfigRequest, NflogPacket};

fn serialize_request(request: &ConfigRequest, seq: u32) -> Vec<u8> {
    let mut msg = request.to_netlink_message(seq);
    msg.finalize();
    let mut buf = vec![0u8; msg.buffer_len()];
    msg.serialize(&mut buf);
    buf
}

#[test]
fn copy_packet_request_bytes() {
    let buf = serialize_request(&ConfigRequest::copy_packet(5, 1024), 1);
    assert_eq!(
        buf,
        vec![
            // nlmsghdr: len=32, type=0x0401, flags=NLM_F_REQUEST|NLM_F_ACK,
            // seq=1, pid=0
            32, 0, 0, 0, 1, 4, 5, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            // nfgenmsg: family=AF_UNSPEC, version=NFNETLINK_V0, res_id=5
            0, 0, 0, 5,
            // attr CFG_MODE: len=10, type=2,
            // payload: copy_range=1024 (be32), copy_mode=PACKET(2), pad
            10, 0, 2, 0, 0, 0, 4, 0, 2, 0, 0, 0,
        ]
    );
}

#[test]
fn bind_group_request_bytes() {
    let buf = serialize_request(&ConfigRequest::bind_group(32), 7);
    assert_eq!(
        buf,
        vec![
            28, 0, 0, 0, 1, 4, 5, 0, 7, 0, 0, 0, 0, 0, 0, 0, // nfgenmsg with res_id=32
            0, 0, 0, 32,
            // attr CFG_CMD: len=5, type=1, payload=NFULNL_CFG_CMD_BIND(1), padded
            5, 0, 1, 0, 1, 0, 0, 0,
        ]
    );
}

/// A NFULNL_MSG_PACKET message with a payload, prefix, header and uid.
fn packet_message() -> Vec<u8> {
    let mut attrs: Vec<u8> = Vec::new();
    // PACKET_HDR: be16 hw_protocol=0x0800, hook=2, pad
    attrs.extend_from_slice(&[8, 0, 1, 0, 0x08, 0x00, 2, 0]);
    // PREFIX: "fw-drop\0"
    let prefix = b"fw-drop\0";
    attrs.extend_from_slice(&((4 + prefix.len()) as u16).to_le_bytes());
    attrs.extend_from_slice(&10u16.to_le_bytes());
    attrs.extend_from_slice(prefix);
    // UID: be32 1000
    attrs.extend_from_slice(&[8, 0, 11, 0, 0, 0, 3, 0xe8]);
    // INDEV: be32 1
    attrs.extend_from_slice(&[8, 0, 4, 0, 0, 0, 0, 1]);
    // PAYLOAD: 6 bytes
    // PAYLOAD: 6 bytes, padded to a 4-byte multiple (kernel NLA padding)
    let payload = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
    attrs.extend_from_slice(&((4 + payload.len()) as u16).to_le_bytes());
    attrs.extend_from_slice(&9u16.to_le_bytes());
    attrs.extend_from_slice(&payload);
    attrs.extend_from_slice(&[0, 0]);

    let mut msg = Vec::new();
    // nlmsghdr: len, type=0x0400, flags=0, seq=0, pid=0
    let len = 16 + 4 + attrs.len();
    msg.extend_from_slice(&(len as u32).to_le_bytes());
    msg.extend_from_slice(&0x0400u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    // nfgenmsg
    msg.extend_from_slice(&[0, 0, 0, 0]);
    msg.extend_from_slice(&attrs);
    msg
}

#[test]
fn parse_packet_attributes() {
    let buf = packet_message();
    let msg = NetlinkMessage::<NflogPacket>::deserialize(&buf).unwrap();
    let NetlinkPayload::InnerMessage(pkt) = &msg.payload else {
        panic!("expected inner message");
    };
    assert_eq!(pkt.hw_protocol, Some(0x0800));
    assert_eq!(pkt.hook, Some(2));
    assert_eq!(pkt.prefix.as_deref(), Some("fw-drop"));
    assert_eq!(pkt.uid, Some(1000));
    assert_eq!(pkt.in_dev, Some(1));
    assert_eq!(
        pkt.payload.as_deref(),
        Some(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe][..])
    );
}

#[test]
fn unknown_attributes_are_skipped_not_fatal() {
    let mut msg = packet_message();
    // append an attribute with an unknown type (99), len=5
    let attr = [5u8, 0, 99, 0, 0xaa, 0, 0, 0];
    let old_len = u32::from_le_bytes(msg[0..4].try_into().unwrap());
    msg[0..4].copy_from_slice(&(old_len + attr.len() as u32).to_le_bytes());
    msg.extend_from_slice(&attr);

    let parsed = NetlinkMessage::<NflogPacket>::deserialize(&msg).unwrap();
    let NetlinkPayload::InnerMessage(pkt) = &parsed.payload else {
        panic!("expected inner message");
    };
    assert_eq!(pkt.prefix.as_deref(), Some("fw-drop"));
    assert_eq!(
        pkt.payload.as_deref(),
        Some(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe][..])
    );
}

#[test]
fn ack_check() {
    // ACK for a config request: NLMSG_ERROR with code 0
    let mut ack = Vec::new();
    ack.extend_from_slice(&36u32.to_le_bytes()); // len
    ack.extend_from_slice(&NLMSG_ERROR.to_le_bytes());
    ack.extend_from_slice(&0u16.to_le_bytes());
    ack.extend_from_slice(&1u32.to_le_bytes()); // seq
    ack.extend_from_slice(&0u32.to_le_bytes()); // pid
    ack.extend_from_slice(&0i32.to_le_bytes()); // error code 0 = ACK
    ack.extend_from_slice(&[0u8; 16]); // original request header
    let msg = NetlinkMessage::<ConfigRequest>::deserialize(&ack).unwrap();
    assert!(check_ack(&msg).is_ok());

    // NACK: EPERM
    let mut nack = ack.clone();
    nack[16..20].copy_from_slice(&(-1i32).to_le_bytes()); // -EPERM
    let msg = NetlinkMessage::<ConfigRequest>::deserialize(&nack).unwrap();
    assert!(check_ack(&msg).is_err());
}

#[test]
fn message_ranges_walks_datagrams() {
    let one = packet_message();
    let mut two = one.clone();
    // NLMSG_NEXT aligns each message start to a 4-byte boundary
    while !two.len().is_multiple_of(4) {
        two.push(0);
    }
    let mut datagram = one.clone();
    while !datagram.len().is_multiple_of(4) {
        datagram.push(0);
    }
    datagram.extend_from_slice(&two);
    let ranges: Vec<_> = message_ranges(&datagram).collect();
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0].len(), one.len());
    assert_eq!(datagram[ranges[0].clone()].to_vec(), one);
    assert_eq!(datagram[ranges[1].clone()].to_vec(), two);
}

#[test]
fn truncated_datagram_yields_no_ranges() {
    assert_eq!(message_ranges(&[0u8; 8]).count(), 0);
    let one = packet_message();
    assert_eq!(message_ranges(&one[..one.len() - 1]).count(), 0);
}

// ---------------------------------------------------------------------------
// additions: full-attribute parsing, malformed input, remaining encodings

use netlink_packet_core::{NetlinkHeader, NLM_F_ACK, NLM_F_REQUEST};
use nflog2syslog::wire::{config_msg_type, packet_msg_type};

/// Build one NFLOG attribute (NLA) with 4-byte alignment padding.
fn nla(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = (4 + payload.len() as u16).to_le_bytes().to_vec();
    v.extend_from_slice(&kind.to_le_bytes());
    v.extend_from_slice(payload);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v
}

/// Wrap raw attribute bytes into a NFULNL_MSG_PACKET netlink message.
fn packet_msg(attrs: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    let len = 20 + attrs.len();
    msg.extend_from_slice(&(len as u32).to_le_bytes());
    msg.extend_from_slice(&packet_msg_type().to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes()); // flags
    msg.extend_from_slice(&0u32.to_le_bytes()); // seq
    msg.extend_from_slice(&0u32.to_le_bytes()); // pid
    msg.extend_from_slice(&[0, 0, 0, 0]); // nfgenmsg
    msg.extend_from_slice(attrs);
    msg
}

fn parse_packet(bytes: &[u8]) -> NflogPacket {
    match NetlinkMessage::<NflogPacket>::deserialize(bytes)
        .expect("packet message parses")
        .payload
    {
        NetlinkPayload::InnerMessage(pkt) => pkt,
        other => panic!("expected inner message, got {other:?}"),
    }
}

#[test]
fn msg_type_constants() {
    // NFNL_SUBSYS_ULOG=4 << 8, config=1, packet=0
    assert_eq!(config_msg_type(), 0x0401);
    assert_eq!(packet_msg_type(), 0x0400);
}

#[test]
fn pf_bind_unbind_request_bytes() {
    let buf = serialize_request(&ConfigRequest::unbind_pf(), 3);
    assert_eq!(
        buf,
        vec![
            28, 0, 0, 0, 1, 4, 5, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // attr CFG_CMD: len=5, type=1, payload=NFULNL_CFG_CMD_PF_UNBIND(4)
            5, 0, 1, 0, 4, 0, 0, 0,
        ]
    );
    let buf = serialize_request(&ConfigRequest::bind_pf(), 4);
    assert_eq!(
        buf,
        vec![
            28, 0, 0, 0, 1, 4, 5, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // attr CFG_CMD: len=5, type=1, payload=NFULNL_CFG_CMD_PF_BIND(3)
            5, 0, 1, 0, 3, 0, 0, 0,
        ]
    );
}

#[test]
fn unbind_group_request_bytes() {
    let buf = serialize_request(&ConfigRequest::unbind_group(7), 9);
    assert_eq!(
        buf,
        vec![
            28, 0, 0, 0, 1, 4, 5, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, // nfgenmsg res_id=7
            5, 0, 1, 0, 2, 0, 0, 0, // CFG_CMD UNBIND(2)
        ]
    );
}

#[test]
fn all_attributes_parse() {
    let mut attrs = Vec::new();
    attrs.extend(nla(1, &[0x08, 0x00, 2, 0])); // packet hdr: proto, hook
    attrs.extend(nla(2, &1_000_042u32.to_be_bytes())); // mark
    attrs.extend(nla(3, &1727700000i64.to_be_bytes())); // timestamp sec
    attrs.extend(nla(3, &789012i64.to_be_bytes())); // timestamp usec (own NLA)
    attrs.extend(nla(4, &2u32.to_be_bytes())); // indev
    attrs.extend(nla(5, &3u32.to_be_bytes())); // outdev
    attrs.extend(nla(6, &4u32.to_be_bytes())); // physindev
    attrs.extend(nla(7, &5u32.to_be_bytes())); // physoutdev
    attrs.extend(nla(8, &[0, 6, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])); // hwaddr
    attrs.extend(nla(9, b"payload!")); // payload
    attrs.extend(nla(10, b"prefix-without-nul")); // prefix
    attrs.extend(nla(11, &1000u32.to_be_bytes())); // uid
    attrs.extend(nla(12, &77u32.to_be_bytes())); // seq
    attrs.extend(nla(13, &88u32.to_be_bytes())); // seq_global
    attrs.extend(nla(14, &100u32.to_be_bytes())); // gid
    attrs.extend(nla(15, &[0x00, 0x01])); // hwtype
    let pkt = parse_packet(&packet_msg(&attrs));

    assert_eq!(pkt.hw_protocol, Some(0x0800));
    assert_eq!(pkt.hook, Some(2));
    assert_eq!(pkt.mark, Some(1_000_042));
    // two TIMESTAMP attributes: the kernel sends one 16-byte NLA; the last
    // one seen wins here (16 bytes -> sec+usec). This fixture uses two 8-byte
    // NLAs which fall below the 16-byte minimum, so timestamp stays unset.
    assert_eq!(pkt.timestamp, None);
    assert_eq!(pkt.in_dev, Some(2));
    assert_eq!(pkt.out_dev, Some(3));
    assert_eq!(pkt.phys_in_dev, Some(4));
    assert_eq!(pkt.phys_out_dev, Some(5));
    assert_eq!(
        pkt.hw_addr.as_deref(),
        Some(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff][..])
    );
    assert_eq!(pkt.payload.as_deref(), Some(b"payload!".as_slice()));
    assert_eq!(pkt.prefix.as_deref(), Some("prefix-without-nul"));
    assert_eq!(pkt.uid, Some(1000));
    assert_eq!(pkt.seq, Some(77));
    assert_eq!(pkt.seq_global, Some(88));
    assert_eq!(pkt.gid, Some(100));
    assert_eq!(pkt.hw_type, Some(1));
}

#[test]
fn timestamp_attribute_parses_sec_and_usec() {
    let mut attrs = Vec::new();
    let mut ts = 1727700000i64.to_be_bytes().to_vec();
    ts.extend_from_slice(&789012i64.to_be_bytes());
    attrs.extend(nla(3, &ts));
    let pkt = parse_packet(&packet_msg(&attrs));
    assert_eq!(pkt.timestamp, Some((1727700000, 789012)));
}

#[test]
fn hwaddr_is_clamped_to_available_bytes() {
    // struct nfulnl_attr_hwaddr: { __be16 addrlen; __u8 pad[2]; __u8 addr[] }
    // addrlen claims 10 but only 6 bytes follow the pad
    let attrs = nla(8, &[0, 10, 0, 0, 1, 2, 3, 4, 5, 6]);
    let pkt = parse_packet(&packet_msg(&attrs));
    assert_eq!(pkt.hw_addr.as_deref(), Some(&[1, 2, 3, 4, 5, 6][..]));
    // addrlen smaller than the available bytes
    let attrs = nla(8, &[0, 2, 0, 0, 1, 2, 3, 4, 5, 6]);
    let pkt = parse_packet(&packet_msg(&attrs));
    assert_eq!(pkt.hw_addr.as_deref(), Some(&[1, 2][..]));
}

#[test]
fn short_attributes_are_skipped_not_fatal() {
    let mut attrs = Vec::new();
    attrs.extend(nla(1, &[0x08, 0x00])); // packet hdr, too short for hook
    attrs.extend(nla(2, &[0, 42])); // mark, too short
    attrs.extend(nla(3, &[0; 8])); // timestamp, too short
    attrs.extend(nla(11, &[0, 100])); // uid, too short
    attrs.extend(nla(15, &[0])); // hwtype, too short
    attrs.extend(nla(9, b"payload")); // one good attribute
    let pkt = parse_packet(&packet_msg(&attrs));
    assert_eq!(pkt.hw_protocol, None);
    assert_eq!(pkt.hook, None);
    assert_eq!(pkt.mark, None);
    assert_eq!(pkt.timestamp, None);
    assert_eq!(pkt.uid, None);
    assert_eq!(pkt.hw_type, None);
    assert_eq!(pkt.payload.as_deref(), Some(b"payload".as_slice()));
}

#[test]
fn payload_too_short_for_nfgenmsg_is_rejected() {
    let mut msg = Vec::new();
    msg.extend_from_slice(&18u32.to_le_bytes()); // len
    msg.extend_from_slice(&packet_msg_type().to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&[0, 0]); // payload shorter than nfgenmsg
    let err = NetlinkMessage::<NflogPacket>::deserialize(&msg)
        .expect_err("must reject a too-short payload");
    assert!(err.to_string().contains("too short"), "err: {err}");
}

#[test]
fn wrong_message_type_is_rejected() {
    let mut msg = Vec::new();
    msg.extend_from_slice(&20u32.to_le_bytes()); // len
    msg.extend_from_slice(&0x0500u16.to_le_bytes()); // not NFULNL_MSG_PACKET
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0]); // nfgenmsg
    let err = NetlinkMessage::<NflogPacket>::deserialize(&msg)
        .expect_err("must reject a foreign message type");
    assert!(
        err.to_string().contains("unexpected message type"),
        "err: {err}"
    );
}

#[test]
fn config_request_cannot_be_received() {
    // config messages are requests we send; the deserializer must refuse
    let buf = serialize_request(&ConfigRequest::bind_pf(), 1);
    let err = NetlinkMessage::<ConfigRequest>::deserialize(&buf)
        .expect_err("config must not deserialize");
    assert!(err.to_string().contains("unexpected"), "err: {err}");
}

#[test]
fn check_ack_rejects_non_error_payload() {
    let mut header = NetlinkHeader::default();
    header.message_type = config_msg_type();
    header.flags = NLM_F_REQUEST | NLM_F_ACK;
    header.sequence_number = 1;
    let msg = NetlinkMessage::new(
        header,
        NetlinkPayload::InnerMessage(ConfigRequest::bind_group(5)),
    );
    let err = check_ack(&msg).expect_err("inner message is not an ACK");
    assert!(err.to_string().contains("expected"), "err: {err}");
}

#[test]
fn message_ranges_rejects_short_and_oversized_lengths() {
    // nlmsg_len < NLMSG_HDRLEN
    let mut d = vec![10u8, 0, 0, 0];
    d.extend_from_slice(&[0u8; 20]);
    assert_eq!(message_ranges(&d).count(), 0);
    // nlmsg_len larger than the datagram
    let mut d = vec![100u8, 0, 0, 0];
    d.extend_from_slice(&[0u8; 20]);
    assert_eq!(message_ranges(&d).count(), 0);
    // len < 16 but enough total bytes
    let mut d = vec![15u8, 0, 0, 0];
    d.extend_from_slice(&[0u8; 40]);
    assert_eq!(message_ranges(&d).count(), 0);
}
