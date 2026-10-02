# nflog2syslog — clean-room Rust rewrite of nflog-to-syslog

Implementation plan and benefit analysis.

Status: phases 1–5 implemented and verified; phases 6–8 implemented
(integration test script, Debian packaging, Apache-2.0 license) —
the root-only end-to-end run is still pending (needs a root shell),
see §8 and TESTING.md.

## 1. Benefit analysis

Baseline: the Go tool (nflog-to-syslog) is ~1600 lines: 3 protocol-name lookup
tables, 15 hand-rolled dissectors (L3/L4 plus DNS/NTP/DHCP/SNMP/GRE/ESP/AH/
WireGuard/OpenVPN heuristics), and a fully synchronous main loop. Its known
production issue was `ENOBUFS` (kernel netlink receive buffer overrun →
silent log loss), mitigated in Go by raising `SO_RCVBUF`.

What a clean-room Rust rewrite buys:

| Benefit | Assessment |
|---|---|
| Decoupled receive→process→sink pipeline | The real fix for the ENOBUFS class of problem. Not Rust-specific — but with a clean-room design we get it as the architecture instead of a retrofit. Includes explicit drop accounting (visible loss counters) instead of silent kernel-side drops. |
| `SO_RCVBUFFORCE` | Bypasses `net.core.rmem_max` (needs CAP_NET_ADMIN, which NFLOG binding requires anyway). The Go library only exposed plain `SO_RCVBUF`. Larger burst headroom without sysctl changes. |
| Dissection via libraries | The Go tool hand-rolls all 15 dissectors. The Rust ecosystem now has `packet-dissector`: a Wireshark-style registry-chaining framework with 80+ protocol crates (ethernet, ARP, VLAN, IPv4/6, TCP, UDP, ICMP/6, GRE, ESP, AH, DNS/mDNS/LLMNR, NTP, DHCP(v6), SNMP, VXLAN, Geneve, L2TP(v3), QUIC, TLS, IEEE802.11, SIP, HTTP, SCTP...). Actively maintained (PRs merged within the last week), MIT OR Apache-2.0, zero-copy, feature-gated. This is the biggest win: dissection becomes ~200 lines of glue instead of ~900 lines of parser code, and coverage grows with upstream. |
| Memory / GC | No GC pauses under packet bursts; RSS likely 3–8 MB vs 15–30 MB Go runtime. Relevant on small edge devices. |
| Static binary, no C deps | Pure-Rust netlink (`netlink-packet-core`/`netlink-sys`) keeps the binary free of libnetfilter-log; static musl builds possible. |
| Safety of parsers | Both languages are memory-safe; Rust adds exhaustive protocol enums and no nil-pointer patterns. Modest. |
| Costs | Porting the nflog wire protocol (~250 lines, clean-room from kernel uapi headers), new tests, Debian packaging switch (dh-golang → dh-cargo, cargo vendoring for reproducible builds), team familiarity, dual maintenance during transition. |

Verdict: worth doing, mostly because of library reuse (packet-dissector) and the
architecture (decoupling, drop accounting), less because of the language swap.
Estimated own code: ~700–900 lines Rust vs ~1600 lines Go.

## 2. Decisions

- **Backend**: pure Rust netlink (`netlink-packet-core` + `netlink-sys`), no
  FFI to libnetfilter_log. Keeps the binary free of GPL and C runtime deps.
- **Output**: structured JSON per packet (one JSON object per syslog message).
  New format — downstream parsers of the old `k=v` format must be adapted once.
- **License**: Apache-2.0 (LICENSE file, Cargo.toml, debian/copyright).
  Every dependency is MIT OR Apache-2.0 (dual), so the combination is clean.
- **Project**: standalone repo `nflog2syslog`, clean-room (implemented from
  kernel uapi headers, RFCs, and crate APIs — not translated from the Go code).

## 3. Crate set (all MIT OR Apache-2.0 unless noted)

| Concern | Crate | Notes |
|---|---|---|
| Netlink socket | `netlink-sys` 0.9 | `Socket::new(NETLINK_NETFILTER)`, `bind_auto()`, sync `recv`/`send`; `AsRawFd` for `SO_RCVBUFFORCE`; ENOBUFS surfaced on recv. |
| Netlink framing | `netlink-packet-core` 0.9 | `NetlinkMessage`, `Nlattr`, `NlasIterator`, parse/emit helpers, ACK/error payloads. |
| nfnetlink_log wire | own module (~250 lines) | Clean-room from `include/uapi/linux/netfilter/nfnetlink_log.h` and `nfnetlink.h`. Constants, config commands, packet attributes. |
| Dissection | `packet-dissector` 0.6 (+ family) | `DissectorRegistry::default()`, `dissect_with_link_type()` (DLT_RAW entry for IP, ARP entry for ARP), `Layer`/`Field`/`FieldValue`. Feature-gate to needed protocols only. |
| JSON | `serde_json` (+ `serde`) | `preserve_order` feature for deterministic field order. |
| Syslog sinks | `syslog` 7.0 | Local unix socket, TCP, UDP; RFC3164 formatter, facility LOCAL0, tag `nflog2syslog`. |
| CLI | `clap` 4 | derive API. |
| Constants / syscalls | `libc` | `ARPHRD_*`, `ETH_P_*`, `IPPROTO_*`, `if_indextoname`, `setsockopt`, signal handling. |
| Time | `time` | Kernel timestamp (sec/usec) → RFC 3339. |

Rejected: `nflog` crate (GPL-2.0+ FFI), `pktparse` (LGPL-3.0), `etherparse` /
`pnet_packet` (fine but strictly less coverage than packet-dissector),
`dnssector` (ISC — unnecessary, packet-dissector-dns covers DNS),
`hickory-proto`/`dhcproto`/`ntp-proto`/`rasn-snmp` (unneeded — the same
protocols ship as packet-dissector family crates), and `neli` (viable for
the wire module, but netlink-packet-core needs less ceremony for one
custom protocol and is the same crate family the rtnetlink/audit tooling
is built on).

## 4. Architecture

```
                     bounded queue q1 (default 8192)
kernel netlink ──> recv thread ───────────────────────> dissect/format worker
  (SO_RCVBUFFORCE)   try_send, drop+count                 (single thread:
                     on full — never block                 packet-dissector
                                                          registry, reusable
                     bounded queue q2 (default 8192)       DissectBuffer)
worker ────────────────────────────────────────────> sink thread
                                                       syslog (unix/tcp/udp),
                                                       optional stdout
```

- **recv thread**: owns the netlink socket. Loop: `recv()` → parse NFLOG
  attributes → copy payload (≤ `copy_range` bytes, default 1024) into an owned
  `NflogEvent` → `try_send(q1)`. On full queue: increment dropped counter,
  continue. On `ENOBUFS` from recv: increment `kernel_dropped` counter,
  continue. Never blocks on anything downstream.
- **worker thread** (single, preserves ordering): `recv(q1)` →
  `registry.dissect_with_link_type(...)` on payload → build `serde_json` value
  → `try_send(q2)` with drop counting. `DissectBuffer` is reused per packet
  (zero-allocation steady state); the only per-packet allocation is the final
  JSON string.
- **sink thread**: owns syslog writers. Blocks freely — a stalled collector
  applies backpressure to q2, which drops in the worker, which drops in the
  recv thread. Loss is always bounded and counted, never a socket stall.
- **stats**: `AtomicU64` counters (recv_dropped, worker_dropped, kernel_dropped,
  processed). Main thread reports nonzero counters to stderr every 10 s.
- **shutdown**: SIGINT/SIGTERM → stop recv loop → send NFULNL_CFG_CMD_UNBIND →
  drain q2 → close sinks. Exit 0.
- **socket setup**: `SO_RCVBUFFORCE(rcvbuf)` (default 8 MiB), fallback
  `SO_RCVBUF` with warning on EPERM; `bind_auto()`; config handshake:
  `PF_UNBIND` → `PF_BIND` → `BIND(group)` → `MODE{copy_range, CopyPacket}`,
  each request `NLM_F_REQUEST|NLM_F_ACK`, ACK checked via NLMSG_ERROR.

## 5. nfnetlink_log wire protocol (clean-room reference)

Source of truth: `include/uapi/linux/netfilter/nfnetlink_log.h` (verified
against `/usr/include/linux/netfilter/nfnetlink_log.h` on 2026-09-30),
`nfnetlink.h`. Netlink framing per RFC 3549 / `man 7 netlink`.

- Protocol: `NETLINK_NETFILTER` (12).
- Message types: base `(NFNL_SUBSYS_ULOG << 8) | type`, `NFNL_SUBSYS_ULOG = 4`,
  `NFULNL_MSG_PACKET = 0`, `NFULNL_MSG_CONFIG = 1`.
- Family header after nlmsghdr: `nfgenmsg { u8 nfgen_family; u8 version;
  be16 res_id }`, `NFNETLINK_V0 = 0`. `res_id` carries the NFLOG group for
  group-scoped config commands.
- Config attributes (after nfgenmsg):
  `CFG_CMD` (1, `u8`), `CFG_MODE` (2, `{ be32 copy_range; u8 copy_mode; u8 pad }`
  packed), `CFG_NLBUFSIZ` (3, be32), `CFG_TIMEOUT` (4, be32), `CFG_QTHRESH`
  (5, be32), `CFG_FLAGS` (6, be16).
- Config commands: `BIND` (1), `UNBIND` (2), `PF_BIND` (3), `PF_UNBIND` (4).
- Copy modes: `NONE` (0), `META` (1), `PACKET` (2).
- Packet attributes from kernel: `PACKET_HDR` (1, `{ be16 hw_protocol; u8 hook;
  u8 pad }`), `MARK` (2, be32), `TIMESTAMP` (3, `{ be64 sec; be64 usec }`),
  `IFINDEX_INDEV` (4, be32), `IFINDEX_OUTDEV` (5, be32), `PHYSINDEV` (6),
  `PHYSOUTDEV` (7), `HWADDR` (8, `{ be16 addrlen; u16 pad; addr[8] }`),
  `PAYLOAD` (9, raw bytes), `PREFIX` (10, NUL-terminated string), `UID` (11,
  be32), `SEQ` (12, be32), `SEQ_GLOBAL` (13, be32), `GID` (14, be32),
  `HWTYPE` (15, be16), `HWHEADER` (16), `HWLEN` (17, be16), `CT` (18),
  `CT_INFO` (19), `VLAN` (20, nested), `L2HDR` (21). Unknown attributes are
  counted and skipped, never fatal.

## 6. Output JSON schema

One JSON object per logged packet (syslog message body):

```json
{
  "prefix": "iptables-rule-comment",
  "timestamp": "2026-09-30T12:34:56.789012Z",
  "in_dev": "eth0",
  "out_dev": null,
  "phys_in_dev": null,
  "phys_out_dev": null,
  "hook": "forward",
  "hw_type": "ETHER",
  "hw_protocol": "IP",
  "uid": null,
  "gid": null,
  "mark": null,
  "seq": null,
  "seq_global": null,
  "layers": {
    "IPv4": { "version": 4, "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "TCP" },
    "TCP":  { "src_port": 443, "dst_port": 51000, "flags": "..." },
    "TLS":  { "version": "TLSv1.3", "sni": "example.org" }
  }
}
```

Rules:
- Absent nflog attributes serialize as `null` (explicit schema stability) or
  are omitted; decided once in `format.rs` and covered by golden tests.
- `layers` maps protocol short name → object of `field_name: value`.
  `FieldValue` maps to JSON naturally: `U8..U64` → number, `Str` → string,
  `Bytes` → hex string, `Ipv4Addr`/`Ipv6Addr`/`MacAddr` → canonical string,
  nested `FieldValue::Children` → nested object.
- Top-level metadata keys are stable; `layers` content varies by packet.
- Interface indices resolve to names via `if_indextoname`, `"<invalid>"`
  on failure, `null` when absent.

## 7. CLI

```
nflog2syslog [--nflog-group N] [--dest ip:port] [--proto udp|tcp]
             [--stdout true|false] [--copy-range N] [--rcvbuf BYTES]
             [--queue-size N] [--stats-interval SECS]
```

Two sinks only: JSON lines on stdout (default, disable with
`--stdout=false`) and an optional remote syslog server (`--dest`,
UDP default / `--proto tcp`). The daemon fails to start when both are
absent, so misconfiguration is caught at boot instead of silently
dropping packets. `--copy-range`, `--rcvbuf`, `--queue-size`,
`--stats-interval` are pipeline knobs.

## 8. Phases

1. **Scaffold**: cargo project, clippy/rustfmt clean skeleton. — **done**
2. **Wire module**: nfnetlink_log constants, config request encoding, ACK
   handling, packet attribute parsing. Unit tests with hand-built byte
   fixtures (round-trip + known vectors). This is the highest-risk module —
   integration-tested against a real kernel in phase 6. — **done**
   (`src/wire.rs`, byte-exact fixtures in `tests/wire.rs`; handshake verified
   against a real kernel: unprivileged config requests get a correctly parsed
   EPERM NACK)
3. **Pipeline**: recv thread, worker, sink threads, bounded queues, drop
   counters, stats reporting, signal handling, CLI. — **done**
   (`src/receiver.rs`, `src/stats.rs`, `src/cli.rs`, `src/main.rs`)
4. **Dissection glue**: entry-point selection (DLT_RAW for IP-family hwproto,
   ARP entry for ETH_P_ARP), JSON builder, golden tests for representative
   packets (IPv4/TCP, IPv6/UDP/DNS, ARP, ICMP, GRE, VLAN). — **done**
   (`src/dissect.rs`, `src/format.rs`, `tests/dissect.rs` covers IPv4/UDP/DNS,
   IPv6/UDP, ARP, malformed payloads; ICMP/GRE/VLAN goldens can be added as
   follow-up test vectors)
5. **Syslog sinks**: local, UDP, TCP; local-output mode. — **done**
   (`src/sinks.rs`)
6. **Integration test**: root-only end-to-end test — **implemented**
   (`scripts/root-integration-test.sh`: `unshare --net`, NFLOG rule with
   prefix, ping traffic, SIGTERM shutdown, jq assertions on prefix/ICMP/
   IPv4 layers; DEP-8 wrapper in `debian/tests/`). **Not yet executed —
   needs a root shell**; run `sudo make integration-test` (see TESTING.md §4).
7. **Packaging** — **done and verified** (systemd unit with hardening +
   systemd `DynamicUser=yes` (no static user), `/etc/default` config, plain debhelper+cargo rules
   with vendored offline builds, man page, DEP-8 autopkgtest, `.gitlab-ci.yml`
   with salsa-ci). Verified: `make vendor && dpkg-buildpackage -us -uc -b`
   builds, runs the full test suite during build, lintian-clean except the
   standard first-upload notice, packaged binary runs.
8. **License decision** — **done**: Apache-2.0.

## 8a. Implementation findings (worth keeping in mind)

- `netlink-sys` 0.9 `Socket::recv` takes a `bytes::BufMut`: it writes into the
  buffer's spare capacity *past* `len` and advances. Buffers must be
  `Vec::with_capacity(n)` and `clear()`ed before each receive; the received
  data is what `recv` appended, not `buf[..return_value]`.
- `nfulnl_msg_packet_hdr` is `{ __be16 hw_protocol; __u8 hook; __u8 _pad }`:
  the hook is byte 2. go-nflog (and therefore the old Go tool) reads byte 3,
  the pad field — harmless there because the hook was never logged, but
  clean-rooming from the uapi header avoids this class of bug.
- `netlink-packet-core` marks `NetlinkHeader`/`NetlinkMessage`/`NetlinkPayload`
  as `#[non_exhaustive]`: build messages via `NetlinkMessage::new`,
  `NetlinkHeader::default()` + field mutation, and variant constructors.
- libc constants: `ARPHRD_*` are `u16`, `ETH_P_*` are `i32` (in the current
  libc version) — keep the casts local to the name tables.

## 9. Risks

| Risk | Mitigation |
|---|---|
| All crates are 0.x (API churn) | Pin exact versions (`=x.y.z`), commits to Cargo.lock, review on major bumps of packet-dissector (very active upstream — good and bad). |
| packet-dissector is young | Feature-gate to the ~20 protocols we need; own JSON layer is isolated behind one module, swap to etherparse/pnet fallback is possible without touching the pipeline. |
| Wire-protocol bugs (bind/config) | Phase 2 byte-fixture tests + phase 6 real-kernel integration test. |
| Debian builds need network | `make vendor` snapshots all crates (plus a workaround for a cargo vendor checksum bug) so builds run offline; CI sbuild alternatively uses `--enable-network`. |
| JSON output churn | Golden tests fix the schema; schema documented in README. |
