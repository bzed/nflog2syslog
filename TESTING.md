# nflog2syslog — test sheet

Run through this checklist before tagging a release. Sections are ordered
from cheap to expensive; each states what it proves. Everything in §1–§3
runs unprivileged in seconds; §4 needs root; §5–§7 are runtime and
packaging checks.

## 1. Static checks (no root)

```bash
cd nflog2syslog
cargo fmt --check                 # PASS: no output
cargo clippy --all-targets -- -D warnings   # PASS: no warnings
cargo build --release            # PASS: compiles, binary ~2 MB
```

Proves: formatting/lint discipline, the dependency set still resolves and
builds.

## 2. Unit + golden tests (no root)

```bash
cargo test
```

Expected: 15 tests pass across three suites:

- `tests/wire.rs`: byte-exact NFLOG config request encoding, packet
  attribute parsing, unknown-attribute tolerance, ACK/NACK interpretation,
  multi-message datagram walking.
- `tests/dissect.rs`: golden JSON for IPv4+UDP+DNS (chained into the DNS
  layer, query name resolvable), IPv4+ICMP, IPv4+GRE+IPv4+ICMP (tunnel
  chaining), IPv6+UDP, ARP, malformed payload → `layers.error`, no payload
  → `layers: null`.
- `main.rs` unit test: netlink alignment helper.

Proves: wire protocol fidelity and JSON schema stability.

## 3. Unprivileged smoke test (no root)

```bash
./target/release/nflog2syslog --nflog-group 7 --stdout; echo "exit: $?"
```

Expected (as non-root):

```
Warning: SO_RCVBUFFORCE not permitted (no CAP_NET_ADMIN?), used SO_RCVBUF: ...
Error: nflog configuration failed: nflog wire error: kernel NACK: Operation not permitted (os error 1)
exit: 1
```

Proves: socket creation, bind, request encoding, live kernel round-trip,
ACK parsing, error path. (Getting EPERM here is correct — NFLOG binding
needs CAP_NET_ADMIN.)

```bash
./target/release/nflog2syslog --help   # shows all flags
```

## 4. Root integration test (the real end-to-end check)

```bash
sudo make integration-test
# or directly:
sudo scripts/root-integration-test.sh
```

What it does, inside a throwaway `unshare --net` namespace (nothing on the
host is touched):

1. brings up `lo`, installs `iptables -A INPUT -i lo -p icmp -j NFLOG
   --nflog-group 42 --nflog-prefix "test-integration"`
2. runs `nflog2syslog --nflog-group 42 --stdout` on that group
3. generates traffic with `ping -c 3 127.0.0.1`
4. SIGTERMs the daemon (exercises graceful shutdown + group unbind)
5. asserts with `jq` that JSON lines with `prefix=="test-integration"`,
   an `ICMP` layer and `IPv4.src == 127.0.0.1` arrived

Expected: final line `PASS: NFLOG packets dissected end-to-end` plus two
sample JSON lines. If the kernel lacks the `nfnetlink_log` module the
script skips with an explanation (exit 77).

This is the only test that exercises the full kernel → netlink →
dissection → JSON path. Run it before every release.

## 5. Manual runtime checks (root shell on a test box)

a) Live traffic to stdout:

```bash
iptables -A INPUT -p udp --dport 53 -j NFLOG --nflog-group 5 --nflog-prefix "dns-watch"
./target/release/nflog2syslog --nflog-group 5 --stdout --stats-interval 5
# in another shell: dig @8.8.8.8 example.com
```

Expected: JSON lines with `layers.DNS`, `layers.UDP`, `layers.IPv4`;
the `timestamp` field matches packet time; `in_dev` shows the interface
name, not an index. Check one line with `jq`:

```bash
... | jq -c '{prefix, in_dev, layers: (.layers | keys)}'
```

b) Remote syslog sink:

```bash
# listener: nc -ul 5514   (or syslog-ng/rsyslog)
./target/release/nflog2syslog --dest 127.0.0.1:5514 --proto udp --nflog-group 5 --stdout
```

Expected: same JSON lines wrapped in RFC3164 framing (`<PRI>Mmm dd
HH:MM:SS nflog2syslog[PID]: {...}`) arrive at the listener. Repeat with
`--proto tcp`.

c) Graceful shutdown: send SIGTERM while idle and while traffic flows.
Expected: `nflog2syslog: unbound from group N` then `nflog2syslog stopped.`
on stderr, exit within ~1 s, and the iptables NFLOG rule can be re-bound
by a restarted instance without `EBUSY`-style errors.

## 6. Backpressure / drop accounting (root)

Prove the decoupling actually bounds loss instead of stalling:

```bash
# a TCP syslog server that never reads:
python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',5514)); s.listen(1); input()"
# generate a flood on the NFLOG group, e.g.:
#   hping3 --flood -i u100 -S -p 443 localhost  (with a matching NFLOG rule)
./target/release/nflog2syslog --dest 127.0.0.1:5514 --proto tcp \
    --nflog-group 5 --queue-size 100 --stats-interval 2
```

Expected: stderr shows `stats: processed=... dropped(queue_sink)=N ...`
growing; the process stays alive and responsive; when the listener starts
reading (or you kill it and it drains), counting stops. No unbounded memory
growth (check with `ps -o rss`).

## 7. Debian package build

```bash
make vendor                       # offline dependency snapshot
dpkg-buildpackage -us -uc -b
lintian ../nflog2syslog_0.1.0-1_amd64.deb
```

Expected: `.deb` builds (vendor/ makes it offline-capable; without
vendor/, the build host needs network to fetch crates); lintian reports
nothing fatal for a native initial release.

Install and service test on a VM:

```bash
sudo apt install ./nflog2syslog_0.1.0-1_amd64.deb
sudo iptables -A INPUT -j NFLOG --nflog-group 5 --nflog-prefix "pkg-test"
sudo sed -i 's/NFLOG_GROUP="0"/NFLOG_GROUP="5"/' /etc/default/nflog2syslog
sudo systemctl restart nflog2syslog
journalctl -u nflog2syslog -n 20      # stats lines; hardening active
sudo journalctl -f | grep nflog       # or configure DEST to your SIEM
```

Expected: unit runs as `nfl2sl` with `CAP_NET_ADMIN` (check
`systemctl show nflog2syslog -p AmbientCapabilities`), restarts on
failure, and the postinst created the system user (`id nfl2sl`).

Autopkgtest (runs §4 against the installed package):

```bash
autopkgtest --user root -B .. nflog2syslog_0.1.0-1_amd64.deb ./
```

Expected: `root-integration` passes, marked `needs-root`.

## 8. Optional: ENOBUFS stress (root)

The regression test for the original problem:

```bash
sudo sysctl net.core.rmem_max=8192   # force a tiny SO_RCVBUF fallback path
# flood the NFLOG group harder than userspace can drain
./target/release/nflog2syslog --nflog-group 5 --stdout --stats-interval 2
```

Expected: `dropped(kernel)=N` may grow under extreme load, is reported on
stderr (never silent), and recovers when load drops. With CAP_NET_ADMIN
the daemon uses `SO_RCVBUFFORCE` and the same flood should produce no
kernel drops at all — undo the sysctl first with
`sudo sysctl net.core.rmem_max=<original>`.
