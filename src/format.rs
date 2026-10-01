//! Assemble the full JSON log record for one NFLOG packet:
//! nflog metadata (prefix, interfaces, uid/gid, ...) plus the
//! dissected protocol layers.

use crate::dissect::{build_registry, dissect_into, DissectBuffer};
use crate::wire::NflogPacket;
use packet_dissector::registry::DissectorRegistry;
use serde_json::{Map, Value};
use std::ffi::CStr;
use std::sync::atomic::AtomicU64;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub struct Formatter {
    registry: DissectorRegistry,
    buf: DissectBuffer<'static>,
}

impl Formatter {
    pub fn new() -> Formatter {
        // The buffer is cleared between packets and only borrows the packet
        // payload during dissection, so it can be reused indefinitely.
        Formatter {
            registry: build_registry(),
            buf: DissectBuffer::new(),
        }
    }

    /// Format one packet into a single-line JSON string.
    pub fn format(&mut self, pkt: &NflogPacket, parse_errors: &AtomicU64) -> String {
        let mut root = Map::new();
        root.insert("prefix".into(), opt_string(pkt.prefix.clone()));
        root.insert("timestamp".into(), opt_timestamp(pkt.timestamp));
        root.insert("in_dev".into(), opt_iface(pkt.in_dev));
        root.insert("out_dev".into(), opt_iface(pkt.out_dev));
        root.insert("phys_in_dev".into(), opt_iface(pkt.phys_in_dev));
        root.insert("phys_out_dev".into(), opt_iface(pkt.phys_out_dev));
        root.insert(
            "hook".into(),
            pkt.hook
                .map(|h| Value::String(hook_name(h).to_string()))
                .unwrap_or(Value::Null),
        );
        root.insert(
            "hw_type".into(),
            pkt.hw_type
                .map(|t| Value::String(hw_type_name(t).to_string()))
                .unwrap_or(Value::Null),
        );
        root.insert(
            "hw_protocol".into(),
            pkt.hw_protocol
                .map(|p| Value::String(hw_protocol_name(p).to_string()))
                .unwrap_or(Value::Null),
        );
        root.insert("hw_addr".into(), opt_hex(pkt.hw_addr.clone()));
        root.insert("uid".into(), opt_num(pkt.uid));
        root.insert("gid".into(), opt_num(pkt.gid));
        root.insert("mark".into(), opt_num(pkt.mark));
        root.insert("seq".into(), opt_num(pkt.seq));
        root.insert("seq_global".into(), opt_num(pkt.seq_global));

        // Dissect into the (reused) buffer, then build the JSON while the
        // borrow is alive, then clear for the next packet.
        let layers = {
            let payload = pkt.payload.as_deref();
            let buf = self.buf.clear_into();
            dissect_into(&self.registry, payload, pkt.hw_protocol, buf, parse_errors)
        };
        root.insert("layers".into(), layers);
        Value::Object(root).to_string()
    }
}

fn opt_string(v: Option<String>) -> Value {
    v.map(Value::String).unwrap_or(Value::Null)
}

fn opt_num(v: Option<u32>) -> Value {
    v.map(Value::from).unwrap_or(Value::Null)
}

fn opt_hex(v: Option<Vec<u8>>) -> Value {
    match v {
        Some(bytes) => Value::String(
            bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        ),
        None => Value::Null,
    }
}

fn opt_iface(idx: Option<u32>) -> Value {
    match idx {
        None => Value::Null,
        Some(0) => Value::Null,
        Some(idx) => Value::String(interface_name(idx)),
    }
}

fn opt_timestamp(ts: Option<(i64, i64)>) -> Value {
    match ts {
        None => Value::Null,
        Some((sec, usec)) => match OffsetDateTime::from_unix_timestamp_nanos(
            sec as i128 * 1_000_000_000 + usec as i128 * 1_000,
        ) {
            Ok(dt) => match dt.format(&Rfc3339) {
                Ok(s) => Value::String(s),
                Err(_) => Value::Null,
            },
            Err(_) => Value::Null,
        },
    }
}

fn interface_name(index: u32) -> String {
    let mut name = [0i8; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
    if ptr.is_null() {
        return "<invalid>".to_string();
    }
    unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
}

/// Netfilter hook numbers (uapi netfilter.h), IPv4/IPv6 hooks share 0..=4.
fn hook_name(hook: u8) -> &'static str {
    match hook {
        0 => "prerouting",
        1 => "input",
        2 => "forward",
        3 => "output",
        4 => "postrouting",
        _ => "unknown",
    }
}

/// Names for the ARPHRD_* values that matter for NFLOG metadata.
/// Fallback keeps the numeric value visible.
fn hw_type_name(hw_type: u16) -> String {
    match hw_type {
        libc::ARPHRD_ETHER => "ETHER".to_string(),
        libc::ARPHRD_LOOPBACK => "LOOPBACK".to_string(),
        libc::ARPHRD_PPP => "PPP".to_string(),
        libc::ARPHRD_IPGRE => "IPGRE".to_string(),
        libc::ARPHRD_SIT => "SIT".to_string(),
        libc::ARPHRD_TUNNEL => "TUNNEL".to_string(),
        libc::ARPHRD_IEEE802 => "IEEE802".to_string(),
        libc::ARPHRD_IEEE80211 => "IEEE80211".to_string(),
        libc::ARPHRD_NONE => "NONE".to_string(),
        libc::ARPHRD_VOID => "VOID".to_string(),
        _ => format!("<hwtype={hw_type:#06x}>"),
    }
}

/// Names for the EtherType values (ETH_P_*) that NFLOG reports as
/// hw_protocol.
fn hw_protocol_name(hw_protocol: u16) -> String {
    let p = hw_protocol as i32;
    match p {
        libc::ETH_P_IP => "IP".to_string(),
        libc::ETH_P_IPV6 => "IPV6".to_string(),
        libc::ETH_P_ARP => "ARP".to_string(),
        libc::ETH_P_RARP => "RARP".to_string(),
        libc::ETH_P_8021Q => "8021Q".to_string(),
        libc::ETH_P_8021AD => "8021AD".to_string(),
        libc::ETH_P_PPP_SES => "PPP_SES".to_string(),
        libc::ETH_P_MPLS_UC => "MPLS_UC".to_string(),
        libc::ETH_P_MPLS_MC => "MPLS_MC".to_string(),
        _ => format!("<ether-type={hw_protocol:#06x}>"),
    }
}

impl Default for Formatter {
    fn default() -> Self {
        Formatter::new()
    }
}
