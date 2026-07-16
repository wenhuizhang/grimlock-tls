#!/usr/bin/env bash
source "$(dirname "$0")/../common.sh"
banner "RQ4: per-request enforcement overhead (payments, capabilities, composed)"

# Full result now: no trusted domain needed.
grun RQ4_enforcement.txt go test ./cmd/grimlock/ -run '^$' \
  -bench 'BenchmarkEnforce' -benchmem -benchtime=200000x -count=5

echo
echo "RQ4 done. Results in $RESULTS/RQ4_*.txt"
