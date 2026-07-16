#!/usr/bin/env bash
source "$(dirname "$0")/../common.sh"
banner "RQ6: end-to-end paid tool call"

# Smoke: the full datapath composes end to end without a trusted domain.
grun RQ6_datapath.txt go test ./cmd/grimlock/ -v -count=1 \
  -run 'TestE2E_CAModeForwards|TestE2E_CAModePoolConcurrent|TestE2E_AttestedResumption|TestE2E_MCPManifestCaptured'

if have_tdx && have_peer; then
  echo "[full] two demo agents on a trusted domain with a facilitator and testnet"
  note "TODO: drive the python-sdk demo agents through a paid tool call to GRIMLOCK_PEER; report added latency by request type and a no-Grimlock baseline."
else
  skip "the full agent workload needs a trusted domain and a second host: set GRIMLOCK_TDX=1 and GRIMLOCK_PEER=host."
fi

echo
echo "RQ6 done. Results in $RESULTS/RQ6_*.txt"
