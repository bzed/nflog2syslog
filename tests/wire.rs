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
