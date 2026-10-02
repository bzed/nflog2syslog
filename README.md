<div align="center">
  <img src="docs/logo.svg" alt="nflog2syslog logo" width="192">
</div>

# nflog2syslog

[![CI](https://github.com/bzed/nflog2syslog/actions/workflows/ci.yml/badge.svg)](https://github.com/bzed/nflog2syslog/actions/workflows/ci.yml)
[![Release](https://github.com/bzed/nflog2syslog/actions/workflows/release.yml/badge.svg)](https://github.com/bzed/nflog2syslog/actions/workflows/release.yml)
[![codecov](https://codecov.io/gh/bzed/nflog2syslog/graph/badge.svg)](https://codecov.io/gh/bzed/nflog2syslog)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Reads packets from the Linux kernel's NFLOG target (netfilter) over a
netlink socket, dissects them, and forwards one JSON object per packet to
syslog. Clean-room Rust rewrite of `nflog-to-syslog`; output is structured
JSON instead of the old `key=value` line format.

Licensed under Apache-2.0. See `PLAN.md` for the design and rationale.

## How it works

```
netlink recv thread -> [bounded queue] -> dissect/format worker
                                           -> [bounded queue] -> syslog sink
```

- Every queue is bounded and fed with `try_send`: a stalled syslog server
  causes counted, reported drops — never a stalled kernel socket (the root
  cause of the old tool's `ENOBUFS`/lost-log problems).
- The netlink socket is enlarged with `SO_RCVBUFFORCE` (8 MiB default),
  falling back to `SO_RCVBUF` without `CAP_NET_ADMIN`.
- Dissection is done by the [packet-dissector](https://crates.io/crates/packet-dissector)
  framework (Ethernet/ARP/VLAN, IPv4/IPv6, TCP/UDP, ICMP/ICMPv6, GRE, ESP,
  AH, DNS/mDNS/LLMNR, NTP, DHCP(v6), SNMP, VXLAN, L2TP and more; coverage
  follows the enabled cargo features).
- Statistics (processed, queue drops, kernel drops, sink errors) are
  reported on stderr every `--stats-interval` seconds when nonzero.

## Output

One JSON object per logged packet:

```json
{"prefix":"fw-drop","timestamp":"2026-09-30T12:34:56.789012Z",
 "in_dev":"eth0","out_dev":null,"phys_in_dev":null,"phys_out_dev":null,
 "hook":"forward","hw_type":"ETHER","hw_protocol":"IP","hw_addr":null,
 "uid":null,"gid":null,"mark":null,"seq":null,"seq_global":null,
 "layers":{"IPv4":{"src":"10.0.0.1","dst":"10.0.0.2","protocol":"TCP"},
           "TCP":{"src_port":443,"dst_port":51000}}}
```

`layers` contains one object per protocol layer found; undissectable
payloads produce `{"layers":{"error":"..."}}` instead of a panic.

## Usage

```
nflog2syslog [--nflog-group N] [--dest ip:port] [--proto udp|tcp]
             [--stdout true|false] [--copy-range N] [--rcvbuf BYTES]
             [--queue-size N] [--stats-interval SECS]
```

- JSON messages are logged to stdout by default (under systemd they land
  in the journal); `--stdout=false` disables that, leaving only status
  messages on stderr.
- `--dest` sets an optional remote syslog server (UDP by default, `--proto`
  to switch to TCP); no `--dest` means no remote sink.
- The daemon refuses to start when no sink is configured: stdout logging
  disabled and no `--dest` given.
- Matching firewall rule: `nft add rule inet filter forward log prefix
  "fw-drop: " group 5` — the `log group` statement sends packets through
  the kernel's nfnetlink_log, which is what nflog2syslog reads.

Requires `CAP_NET_ADMIN` (the NFLOG bind needs it anyway; it also enables
the `SO_RCVBUFFORCE` path).

## Building

```
cargo build --release
cargo test            # unit + golden tests
cargo clippy --all-targets
```

Rust >= 1.85 (packet-dissector 0.6 requirement).

## CI and releases

- GitHub Actions (`.github/workflows/`): on every push/PR — format, clippy,
  unit tests (via cargo-nextest, with JUnit XML results uploaded to
  Codecov's test analytics, posted as PR comments, and kept as
  artifacts), coverage (cargo-llvm-cov uploaded to Codecov, gated at
  >= 85% line coverage — see `AGENTS.md`), the
  unprivileged EPERM smoke test, the root-only end-to-end integration test
  (runners have passwordless sudo), and a Debian package build with lintian
  inside a `debian:trixie` container (the Rust toolchain comes from rustup,
  since Debian's rustc is older than the dependency set needs). Pushing a
  `v*` tag publishes a GitHub release
  with the binary tarball, the `.deb`, and checksums.
- Coverage and test results are uploaded to [Codecov](https://about.codecov.io/):
  set a `CODECOV_TOKEN` repository secret for private repositories (the
  upload is a non-failing step when the token is absent).
- GitLab CI (`.gitlab-ci.yml`): salsa-ci package build plus the same
  compile/lint/test jobs.

See `TESTING.md` for the full manual checklist.

## Debian packaging

```
make vendor           # vendor crates for an offline package build
dpkg-buildpackage -us -uc -b
```

See `debian/` and `TESTING.md` for the full test checklist, including the
root-only end-to-end test (`scripts/root-integration-test.sh`).
