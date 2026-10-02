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

//! Dissection glue: run the packet-dissector registry over an NFLOG payload
//! and build the JSON layers object for it.

use packet_dissector::dissectors::arp::ArpDissector;
use packet_dissector::field::FieldValue;
pub use packet_dissector::packet::DissectBuffer;
use packet_dissector::packet::Layer;
use packet_dissector::registry::DissectorRegistry;
use prometheus::IntCounter;
use serde_json::{Map, Value};
use std::ops::Range;

/// pcap LINKTYPE_RAW: dissectors entry for raw IPv4/IPv6 payloads.
const LINKTYPE_RAW: u32 = 101;
/// Private link-type key used to enter the ARP dissector directly
/// (NFLOG hands us the ARP header without an Ethernet header).
pub const LINKTYPE_ARP: u32 = 0x0806; // ETH_P_ARP

/// Build the dissector registry with the protocols enabled via cargo
/// features, plus a custom entry for ARP payloads.
pub(crate) fn build_registry() -> DissectorRegistry {
    let mut registry = DissectorRegistry::default();
    registry.register_by_link_type_or_replace(LINKTYPE_ARP, Box::new(ArpDissector));
    registry
}

/// Dissect `payload` and return the "layers" JSON object with one entry
/// per protocol layer. A None payload yields Null; a payload that cannot
/// be dissected yields `{"error": ...}` and bumps the parse-error counter.
pub(crate) fn dissect_into<'pkt>(
    registry: &DissectorRegistry,
    payload: Option<&'pkt [u8]>,
    hw_protocol: Option<u16>,
    buf: &mut DissectBuffer<'pkt>,
    parse_errors: &IntCounter,
) -> Value {
    let Some(payload) = payload else {
        return Value::Null;
    };
    let link_type = match hw_protocol {
        // ETH_P_IP / ETH_P_IPV6
        Some(0x0800) | Some(0x86dd) => LINKTYPE_RAW,
        // ETH_P_ARP: payload starts at the ARP header
        Some(0x0806) => LINKTYPE_ARP,
        _ => LINKTYPE_RAW,
    };
    let mut layers = Map::new();
    match registry.dissect_with_link_type(payload, link_type, buf) {
        Ok(()) => {
            for layer in buf.layers() {
                layers.insert(layer.name.to_string(), layer_to_json(buf, layer));
            }
        }
        Err(e) => {
            parse_errors.inc();
            layers.insert("error".into(), Value::String(e.to_string()));
        }
    }
    Value::Object(layers)
}

fn layer_to_json(buf: &DissectBuffer, layer: &Layer) -> Value {
    let fields = buf.fields();
    let mut obj = Map::new();
    for idx in layer.field_range.clone() {
        let Some(field) = fields.get(idx as usize) else {
            continue;
        };
        obj.insert(
            field.descriptor.name.to_string(),
            field_value_to_json(buf, &field.value),
        );
    }
    Value::Object(obj)
}

fn field_value_to_json(buf: &DissectBuffer, value: &FieldValue) -> Value {
    match value {
        FieldValue::U8(v) => Value::from(*v),
        FieldValue::U16(v) => Value::from(*v),
        FieldValue::U32(v) => Value::from(*v),
        FieldValue::U64(v) => Value::from(*v),
        FieldValue::I32(v) => Value::from(*v),
        FieldValue::Bytes(b) => Value::String(hex(b)),
        FieldValue::Str(s) => Value::String(s.to_string()),
        FieldValue::Ipv4Addr(a) => Value::String(std::net::Ipv4Addr::from(*a).to_string()),
        FieldValue::Ipv6Addr(a) => Value::String(std::net::Ipv6Addr::from(*a).to_string()),
        FieldValue::MacAddr(m) => Value::String(m.to_string()),
        FieldValue::Array(range) => container_to_json(buf, range.clone(), true),
        FieldValue::Object(range) => container_to_json(buf, range.clone(), false),
        FieldValue::Scratch(range) => {
            let scratch = buf.scratch();
            let end = (range.end as usize).min(scratch.len());
            let start = (range.start as usize).min(end);
            Value::String(hex(&scratch[start..end]))
        }
    }
}

/// Expand a container field (Array/Object) by recursing into the flat field
/// buffer. Array elements become nested arrays, Object children nested maps.
fn container_to_json(buf: &DissectBuffer, range: Range<u32>, as_array: bool) -> Value {
    let fields = buf.fields();
    let mut items: Vec<Value> = Vec::new();
    let mut map = Map::new();
    let start = range.start as usize;
    let end = (range.end as usize).min(fields.len());
    let mut idx = start;
    while idx < end {
        let field = &fields[idx];
        let value = field_value_to_json(buf, &field.value);
        if as_array {
            items.push(value);
        } else {
            map.insert(field.descriptor.name.to_string(), value);
        }
        // A child may itself be a container that consumed following fields.
        idx = 1 + match (&field.value, as_array) {
            (FieldValue::Array(r), _) | (FieldValue::Object(r), _) => {
                idx.max(r.end.saturating_sub(1) as usize)
            }
            _ => idx,
        };
    }
    if as_array {
        Value::Array(items)
    } else {
        Value::Object(map)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
