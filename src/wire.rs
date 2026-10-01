//! nfnetlink_log wire protocol, clean-room implemented from
//! include/uapi/linux/netfilter/nfnetlink_log.h and nfnetlink.h.
//!
//! Only the subset needed by nflog2syslog is modeled: the config
//! handshake (bind to an NFLOG group, set copy mode) and the
//! packet attributes the kernel sends for logged packets.

use netlink_packet_core::{
    DecodeError, NetlinkHeader, NetlinkMessage, NetlinkSerializable, NlasIterator, NLA_ALIGNTO,
    NLMSG_ERROR, NLM_F_ACK, NLM_F_REQUEST,
};
use std::fmt;
use std::ops::Range;

const NFNL_SUBSYS_ULOG: u16 = 4;
pub const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;
const NFNETLINK_V0: u8 = 0;
const AF_UNSPEC: u8 = 0;

/// nfulnl_msg_config_cmds
const CFG_CMD_BIND: u8 = 1;
const CFG_CMD_UNBIND: u8 = 2;
const CFG_CMD_PF_BIND: u8 = 3;
const CFG_CMD_PF_UNBIND: u8 = 4;

/// enum nfulnl_attr_config
const CFG_CMD: u16 = 1;
const CFG_MODE: u16 = 2;

/// NFULNL_COPY_*
pub const COPY_MODE_PACKET: u8 = 0x02;

/// enum nfulnl_attr_type
const ATTR_PACKET_HDR: u16 = 1;
const ATTR_MARK: u16 = 2;
const ATTR_TIMESTAMP: u16 = 3;
const ATTR_IFINDEX_INDEV: u16 = 4;
const ATTR_IFINDEX_OUTDEV: u16 = 5;
const ATTR_IFINDEX_PHYSINDEV: u16 = 6;
const ATTR_IFINDEX_PHYSOUTDEV: u16 = 7;
const ATTR_HWADDR: u16 = 8;
const ATTR_PAYLOAD: u16 = 9;
const ATTR_PREFIX: u16 = 10;
const ATTR_UID: u16 = 11;
const ATTR_SEQ: u16 = 12;
const ATTR_SEQ_GLOBAL: u16 = 13;
const ATTR_GID: u16 = 14;
const ATTR_HWTYPE: u16 = 15;

pub fn config_msg_type() -> u16 {
    (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG
}

pub fn packet_msg_type() -> u16 {
    (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET
}

#[derive(Debug)]
pub struct WireError(String);

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nflog wire error: {}", self.0)
    }
}

impl std::error::Error for WireError {}

impl From<DecodeError> for WireError {
    fn from(e: DecodeError) -> Self {
        WireError(e.to_string())
    }
}

/// One attribute of a NFULNL_MSG_CONFIG request.
#[derive(Debug, Clone)]
pub enum ConfigAttr {
    Cmd(u8),
    /// struct nfulnl_msg_config_mode: { be32 copy_range; u8 copy_mode; u8 pad }
    Mode {
        copy_range: u32,
        copy_mode: u8,
    },
}

impl ConfigAttr {
    fn attr_type(&self) -> u16 {
        match self {
            ConfigAttr::Cmd(_) => CFG_CMD,
            ConfigAttr::Mode { .. } => CFG_MODE,
        }
    }

    fn payload_bytes(&self) -> Vec<u8> {
        match self {
            ConfigAttr::Cmd(c) => vec![*c],
            ConfigAttr::Mode {
                copy_range,
                copy_mode,
            } => {
                let mut v = copy_range.to_be_bytes().to_vec();
                v.push(*copy_mode);
                v.push(0);
                v
            }
        }
    }
}

/// A NFULNL_MSG_CONFIG request. `res_id` carries the NFLOG group
/// for group-scoped commands (BIND/UNBIND/MODE).
#[derive(Debug, Clone)]
pub struct ConfigRequest {
    pub group: u16,
    pub attrs: Vec<ConfigAttr>,
}

impl ConfigRequest {
    pub fn unbind_pf() -> Self {
        ConfigRequest {
            group: 0,
            attrs: vec![ConfigAttr::Cmd(CFG_CMD_PF_UNBIND)],
        }
    }

    pub fn bind_pf() -> Self {
        ConfigRequest {
            group: 0,
            attrs: vec![ConfigAttr::Cmd(CFG_CMD_PF_BIND)],
        }
    }

    pub fn bind_group(group: u16) -> Self {
        ConfigRequest {
            group,
            attrs: vec![ConfigAttr::Cmd(CFG_CMD_BIND)],
        }
    }

    pub fn unbind_group(group: u16) -> Self {
        ConfigRequest {
            group,
            attrs: vec![ConfigAttr::Cmd(CFG_CMD_UNBIND)],
        }
    }

    pub fn copy_packet(group: u16, copy_range: u32) -> Self {
        ConfigRequest {
            group,
            attrs: vec![ConfigAttr::Mode {
                copy_range,
                copy_mode: COPY_MODE_PACKET,
            }],
        }
    }

    /// Serialize into a full netlink message with REQUEST|ACK flags set.
    pub fn to_netlink_message(&self, sequence_number: u32) -> NetlinkMessage<ConfigRequest> {
        // NetlinkHeader/NetlinkMessage are #[non_exhaustive]
        let mut header = NetlinkHeader::default();
        header.message_type = config_msg_type();
        header.flags = NLM_F_REQUEST | NLM_F_ACK;
        header.sequence_number = sequence_number;
        NetlinkMessage::new(
            header,
            netlink_packet_core::NetlinkPayload::InnerMessage(self.clone()),
        )
    }
}

/// Config requests are never received as inner messages (acks arrive as
/// NLMSG_ERROR, handled by netlink-packet-core), but NetlinkMessage<T> can
/// only be deserialized when T is NetlinkDeserializable.
impl netlink_packet_core::NetlinkDeserializable for ConfigRequest {
    type Error = WireError;

    fn deserialize(header: &NetlinkHeader, _payload: &[u8]) -> Result<Self, Self::Error> {
        Err(WireError(format!(
            "unexpected {} message (type {:#06x})",
            "NFULNL_MSG_CONFIG", header.message_type
        )))
    }
}

impl NetlinkSerializable for ConfigRequest {
    fn message_type(&self) -> u16 {
        config_msg_type()
    }

    fn buffer_len(&self) -> usize {
        // nfgenmsg + attributes (4-byte aligned)
        4 + self
            .attrs
            .iter()
            .map(|a| 4 + a.payload_bytes().len().div_ceil(NLA_ALIGNTO) * NLA_ALIGNTO)
            .sum::<usize>()
    }

    fn serialize(&self, buffer: &mut [u8]) {
        // struct nfgenmsg { u8 nfgen_family; u8 version; __be16 res_id }
        buffer[0] = AF_UNSPEC;
        buffer[1] = NFNETLINK_V0;
        buffer[2..4].copy_from_slice(&self.group.to_be_bytes());
        let mut off = 4;
        for attr in &self.attrs {
            let payload = attr.payload_bytes();
            let len = 4 + payload.len();
            buffer[off..off + 2].copy_from_slice(&(len as u16).to_le_bytes());
            buffer[off + 2..off + 4].copy_from_slice(&attr.attr_type().to_le_bytes());
            buffer[off + 4..off + 4 + payload.len()].copy_from_slice(&payload);
            let padded = 4 + payload.len().div_ceil(NLA_ALIGNTO) * NLA_ALIGNTO;
            for b in &mut buffer[off + 4 + payload.len()..off + padded] {
                *b = 0;
            }
            off += padded;
        }
    }
}

/// One logged packet as received from the kernel, converted to owned data.
#[derive(Debug, Default, Clone)]
pub struct NflogPacket {
    pub hw_protocol: Option<u16>,
    pub hook: Option<u8>,
    pub mark: Option<u32>,
    pub timestamp: Option<(i64, i64)>,
    pub in_dev: Option<u32>,
    pub out_dev: Option<u32>,
    pub phys_in_dev: Option<u32>,
    pub phys_out_dev: Option<u32>,
    pub hw_addr: Option<Vec<u8>>,
    pub payload: Option<Vec<u8>>,
    pub prefix: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub seq: Option<u32>,
    pub seq_global: Option<u32>,
    pub hw_type: Option<u16>,
}

impl netlink_packet_core::NetlinkDeserializable for NflogPacket {
    type Error = WireError;

    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        if header.message_type != packet_msg_type() {
            return Err(WireError(format!(
                "unexpected message type {:#06x}",
                header.message_type
            )));
        }
        if payload.len() < 4 {
            return Err(WireError("payload too short for nfgenmsg".into()));
        }
        // skip struct nfgenmsg
        let mut pkt = NflogPacket::default();
        for nla in NlasIterator::new(&payload[4..]) {
            let nla = nla?;
            let kind = nla.kind();
            let value = nla.value();
            match kind {
                ATTR_PACKET_HDR if value.len() >= 4 => {
                    pkt.hw_protocol = Some(u16::from_be_bytes([value[0], value[1]]));
                    // struct nfulnl_msg_packet_hdr { __be16 hw_protocol; __u8 hook; __u8 _pad }
                    pkt.hook = Some(value[2]);
                }
                ATTR_MARK if value.len() >= 4 => {
                    pkt.mark = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                ATTR_TIMESTAMP if value.len() >= 16 => {
                    let sec = i64::from_be_bytes(value[..8].try_into().unwrap());
                    let usec = i64::from_be_bytes(value[8..16].try_into().unwrap());
                    pkt.timestamp = Some((sec, usec));
                }
                ATTR_IFINDEX_INDEV if value.len() >= 4 => {
                    pkt.in_dev = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                ATTR_IFINDEX_OUTDEV if value.len() >= 4 => {
                    pkt.out_dev = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                ATTR_IFINDEX_PHYSINDEV if value.len() >= 4 => {
                    pkt.phys_in_dev = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                ATTR_IFINDEX_PHYSOUTDEV if value.len() >= 4 => {
                    pkt.phys_out_dev = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                ATTR_HWADDR if value.len() >= 4 => {
                    let addrlen = u16::from_be_bytes([value[0], value[1]]) as usize;
                    let avail = value.len().saturating_sub(4);
                    pkt.hw_addr = Some(value[4..4 + addrlen.min(avail)].to_vec());
                }
                ATTR_PAYLOAD => {
                    pkt.payload = Some(value.to_vec());
                }
                ATTR_PREFIX => {
                    let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                    pkt.prefix = Some(String::from_utf8_lossy(&value[..end]).into_owned());
                }
                ATTR_UID if value.len() >= 4 => {
                    pkt.uid = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                ATTR_GID if value.len() >= 4 => {
                    pkt.gid = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                ATTR_SEQ if value.len() >= 4 => {
                    pkt.seq = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                ATTR_SEQ_GLOBAL if value.len() >= 4 => {
                    pkt.seq_global = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                ATTR_HWTYPE if value.len() >= 2 => {
                    pkt.hw_type = Some(u16::from_be_bytes([value[0], value[1]]));
                }
                // unknown attributes are skipped, never fatal: the kernel
                // adds attributes (e.g. NFULA_VLAN, NFULA_L2HDR) newer tools
                // may know but this one does not need
                _ => {}
            }
        }
        Ok(pkt)
    }
}

/// NLMSG_ERROR ack for a config request: Ok(()) on ACK, Err on NACK.
pub fn check_ack(
    msg: &netlink_packet_core::NetlinkMessage<ConfigRequest>,
) -> Result<(), WireError> {
    if let netlink_packet_core::NetlinkPayload::Error(err) = &msg.payload {
        match err.code {
            None => Ok(()),
            // NLMSG_ERROR carries the error code as -errno
            Some(code) => Err(WireError(format!(
                "kernel NACK: {}",
                std::io::Error::from_raw_os_error(-code.get())
            ))),
        }
    } else {
        Err(WireError(format!(
            "expected {} message, got payload {:?}",
            NLMSG_ERROR, msg.payload
        )))
    }
}

/// Split a received datagram into individual netlink messages by walking
/// nlmsg_len fields. Yields one byte range per message, no allocation.
pub fn message_ranges(data: &[u8]) -> impl Iterator<Item = Range<usize>> + '_ {
    let mut off = 0usize;
    std::iter::from_fn(move || {
        if off + 16 > data.len() {
            return None;
        }
        let len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        if len < 16 || off + len > data.len() {
            return None;
        }
        let range = off..off + len;
        off += len.div_ceil(NLA_ALIGNTO) * NLA_ALIGNTO;
        Some(range)
    })
}
