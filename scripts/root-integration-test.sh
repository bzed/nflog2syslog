#!/bin/bash
# Copyright 2026 Bernd Zeimetz <bernd@bzed.de>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Root-only end-to-end test for nflog2syslog.
#
# Runs everything inside a throwaway network namespace:
#   - bring up lo
#   - install an nftables log rule for ICMP on input (log group)
#   - run nflog2syslog against that NFLOG group, output to stdout
#   - generate traffic (ping 127.0.0.1)
#   - assert valid JSON lines with the expected layers
#
# Exit codes: 0 = pass, 77 = skipped (not root / missing tools), 1 = fail.

set -u
cd "$(dirname "$0")/.."

GROUP=42
OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP: needs root (try: sudo $0)"
    exit 77
fi
for tool in unshare nft ip ping jq timeout; do
    command -v "$tool" >/dev/null || { echo "SKIP: $tool not installed"; exit 77; }
done

echo "== building release binary =="
if [ -n "${NFLOG2SYSLOG_BIN:-}" ]; then
    # use a pre-built binary (set by autopkgtest against the installed package)
    BIN="${NFLOG2SYSLOG_BIN}"
else
    cargo build --release || exit 1
    BIN="$PWD/target/release/nflog2syslog"
fi

unshare --net bash -euo pipefail -c "
    GROUP=$GROUP
    OUT='$OUT'
    BIN='$BIN'
    ip link set lo up
    nft add table ip nflog2syslog-test \
        || { echo 'FAIL: could not add nftables table (kernel module missing?)'; exit 1; }
    nft add chain ip nflog2syslog-test input '{ type filter hook input priority 0; }'
    nft add rule ip nflog2syslog-test input iifname "lo" ip protocol icmp \
        log group \$GROUP prefix "test-integration" counter \
        || { echo 'FAIL: could not install NFLOG rule (nfnetlink_log missing?)'; exit 1; }
    \$BIN --nflog-group \$GROUP --stats-interval 1 --metrics-addr 127.0.0.1:9559 > \"\$OUT\" 2>/tmp/nflog2syslog-test.err &
    DAEMON=\$!
    sleep 1
    # fail loudly (with the daemon's stderr) if it exited early
    if ! kill -0 \$DAEMON 2>/dev/null; then
        echo 'FAIL: daemon exited early'; exit 1
    fi
    ping -c 3 -W 1 127.0.0.1 >/dev/null
    sleep 1
    # scrape the Prometheus endpoint
    exec 3<>/dev/tcp/127.0.0.1/9559
    printf 'GET /metrics HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3
    timeout 5 cat <&3 > /tmp/nflog2syslog-metrics.out
    exec 3<&- 3>&-
    kill -TERM \$DAEMON 2>/dev/null || true
    wait \$DAEMON || true
" || { echo "FAIL: namespace test run failed"; cat /tmp/nflog2syslog-test.err; exit 1; }

echo "== stderr of the daemon =="
cat /tmp/nflog2syslog-test.err
rm -f /tmp/nflog2syslog-test.err

echo "== received $(wc -l < "$OUT") JSON lines =="

if [ "$(jq -r 'select(.layers.ICMP) | .layers.IPv4.src' "$OUT" | sort -u)" != "127.0.0.1" ]; then
    echo "FAIL: no JSON line with IPv4.src=127.0.0.1 and an ICMP layer found"
    head -3 "$OUT"
    exit 1
fi
if [ -z "$(jq -r 'select(.prefix == "test-integration")' "$OUT")" ]; then
    echo "FAIL: no JSON line with prefix=test-integration found"
    head -3 "$OUT"
    exit 1
fi

echo "== metrics endpoint =="
# labeled metrics only expose values that were touched, so assert on
# the counters a clean run is guaranteed to move
for metric in \
    'nflog2syslog_packets_received_total [1-9]' \
    'nflog2syslog_packets_processed_total [1-9]' \
    'nflog2syslog_nflog_group 42' \
    '# TYPE nflog2syslog_packets_dropped_total counter'; do
    if ! grep -Eq "$metric" /tmp/nflog2syslog-metrics.out; then
        echo "FAIL: metrics scrape missing or does not match: $metric"
        head -20 /tmp/nflog2syslog-metrics.out
        exit 1
    fi
done
rm -f /tmp/nflog2syslog-metrics.out

echo "PASS: NFLOG packets dissected end-to-end (IPv4 + ICMP layers present)"
echo "sample line:"
jq -c '.' "$OUT" | head -2
exit 0
