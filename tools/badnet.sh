#!/usr/bin/env bash
# Run a command under emulated bad-network conditions (netem on an interface).
# The qdisc is always removed on exit, including on failure or Ctrl-C.
#
#   sudo ./tools/badnet.sh -- ./build/bin/librats_tests --gtest_filter='*Udp*'
#   sudo ./tools/badnet.sh -i enp0s3 -l 10% -d 200ms -- ping -c 20 1.1.1.1
#   sudo ./tools/badnet.sh --profile 3g -- ./build/bin/librats_tests
#
# NOTE: netem only shapes egress. On `lo` a packet crosses the qdisc once per
# direction, so `-l 25%` means 25% loss *each way* (~56% of round-trips survive).

set -euo pipefail

IFACE=lo
LOSS="25%"
DELAY="80ms 40ms distribution normal"
RATE="2mbit"
EXTRA="reorder 5% 50% duplicate 0.5% limit 2000"

usage() {
    cat <<EOF
usage: $0 [options] -- <command> [args...]

  -i, --iface IFACE     interface to shape (default: lo)
  -l, --loss SPEC       netem loss spec, e.g. '25%', '25% 30%' (correlated),
                        'gemodel 25% 30% 70% 5%' (bursty)  (default: $LOSS)
  -d, --delay SPEC      netem delay spec (default: $DELAY)
  -r, --rate RATE       bandwidth cap, or 'none' (default: $RATE)
  -x, --extra SPEC      extra netem options (default: $EXTRA)
  -p, --profile NAME    preset: mobile-bad | 3g | 4g | lossy-only | clean
  -h, --help
EOF
}

profile() {
    case "$1" in
        mobile-bad) LOSS="gemodel 25% 30% 70% 5%"; DELAY="150ms 80ms distribution normal"
                    RATE="1mbit"; EXTRA="reorder 10% 50% duplicate 1% limit 2000" ;;
        3g)         LOSS="5%"; DELAY="200ms 100ms distribution normal"
                    RATE="768kbit"; EXTRA="reorder 5% 50% limit 1000" ;;
        4g)         LOSS="1%"; DELAY="50ms 20ms distribution normal"
                    RATE="12mbit"; EXTRA="limit 4000" ;;
        lossy-only) LOSS="25%"; DELAY=""; RATE="none"; EXTRA="limit 4000" ;;
        clean)      LOSS=""; DELAY=""; RATE="none"; EXTRA="" ;;
        *) echo "unknown profile: $1" >&2; exit 2 ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--iface)   IFACE=$2; shift 2 ;;
        -l|--loss)    LOSS=$2; shift 2 ;;
        -d|--delay)   DELAY=$2; shift 2 ;;
        -r|--rate)    RATE=$2; shift 2 ;;
        -x|--extra)   EXTRA=$2; shift 2 ;;
        -p|--profile) profile "$2"; shift 2 ;;
        -h|--help)    usage; exit 0 ;;
        --)           shift; break ;;
        *)            echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ $# -gt 0 ]] || { echo "no command given" >&2; usage >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "must run as root (tc needs CAP_NET_ADMIN)" >&2; exit 1; }

SPEC=""
[[ -n $LOSS  ]] && SPEC+=" loss $LOSS"
[[ -n $DELAY ]] && SPEC+=" delay $DELAY"
[[ $RATE != none && -n $RATE ]] && SPEC+=" rate $RATE"
[[ -n $EXTRA ]] && SPEC+=" $EXTRA"

# Refuse to clobber a shaper someone else set up (ours would be deleted on exit).
if tc qdisc show dev "$IFACE" | grep -qE 'qdisc (netem|tbf|htb|prio|netem) '; then
    echo "a shaping qdisc is already active on $IFACE:" >&2
    tc qdisc show dev "$IFACE" >&2
    echo "remove it first: sudo tc qdisc del dev $IFACE root" >&2
    exit 1
fi

cleanup() {
    local rc=$?
    echo "--- badnet: removing qdisc from $IFACE"
    tc qdisc del dev "$IFACE" root 2>/dev/null || true
    exit $rc
}
trap cleanup EXIT INT TERM

echo "--- badnet: tc qdisc add dev $IFACE root netem$SPEC"
# shellcheck disable=SC2086
tc qdisc add dev "$IFACE" root netem $SPEC
tc -s qdisc show dev "$IFACE"

"$@"
