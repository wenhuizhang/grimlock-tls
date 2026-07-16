#!/usr/bin/env bash
source "$(dirname "$0")/../common.sh"
banner "RQ2: data-plane cost (fast splice vs guarded vs direct)"

# Smoke: loopback throughput for the splice fast path vs a userspace copy.
grun RQ2_dataplane.txt go test ./cmd/grimlock/ -run '^$' \
  -bench 'BenchmarkDataPlane' -benchtime=500x -count=6

note "loopback understates the fast lane: the two local traversals dominate."

if have_peer; then
  echo "[full] cross-host throughput over a real NIC to $GRIMLOCK_PEER"
  note "TODO: a two-host driver that runs a fast and a guarded channel to GRIMLOCK_PEER and reports throughput + CPU both directions."
else
  skip "cross-host data-plane run needs a second host: set GRIMLOCK_PEER=host."
fi

echo
echo "RQ2 done. Results in $RESULTS/RQ2_*.txt"
