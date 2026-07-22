#!/usr/bin/env bash
source "$(dirname "$0")/../common.sh"
banner "RQ3: attestation amortization (full gate vs resume)"

# Smoke: protocol cost of a full gate vs a resume, over real TLS+kTLS, stub quote.
grun RQ3_setup.txt go test ./cmd/grimlock/ -run '^$' \
  -bench 'BenchmarkSetup' -benchtime=150x -count=5

if have_tdx; then
  echo "[full] real quote-generation and verification cost on the trusted domain"
  note "TODO: a microbenchmark of ConfigfsQuoter.Quote and TDXVerifier.Verify; add the gen cost to the full-gate number."
else
  note "quote generation is stubbed here (protocol cost only). On a trusted domain set GRIMLOCK_TDX=1 to add the real quote constant."
fi

echo
echo "RQ3 done. Results in $RESULTS/RQ3_*.txt"
