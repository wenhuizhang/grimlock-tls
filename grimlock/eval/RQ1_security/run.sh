#!/usr/bin/env bash
source "$(dirname "$0")/../common.sh"
banner "RQ1: does Grimlock block attacks that baselines do not?"

# Smoke: the attack matrix without a trusted domain (stub quote, real everything else).
grun RQ1_attacks.txt go test ./cmd/grimlock/ -run '^TestAttack' -v -count=1

# Full-a: interception (A4) and secret extraction (A10) end to end need root.
if have_root; then
  echo "[full] A4 interception redirect and A10 seccomp on the real kernel"
  if ( cd "$GRIM" && go test -c -o /tmp/grim_sec.test ./cmd/grimlock/ >/dev/null 2>&1 ); then
    sudo /tmp/grim_sec.test -test.run 'TestEBPF_Connect4Redirects|TestSeccompBlocksPtrace' -test.v 2>&1 \
      | tee "$RESULTS/RQ1_root_A4_A10.txt"
  else
    skip "could not build the test binary for the root steps"
  fi
else
  skip "A4 interception and A10 seccomp end to end need root: rerun after 'sudo -v'."
fi

# Full-b: real-quote forms of A5 (relay) and A6 (drift) on a trusted domain.
if have_tdx; then
  echo "[full] A5 relay and A6 drift with real attestation quotes"
  note "point the attested managers at ConfigfsQuoter/TDXVerifier and rerun the A5/A6 variants (TODO in attack_test.go)."
  # TODO(tdx): GRIMLOCK_TDX build tag or a flag that swaps the stub quoter for the real one.
else
  note "A5/A6 shown with stub quotes over real sessions; on a trusted domain set GRIMLOCK_TDX=1 for real-quote forms."
fi

echo
echo "RQ1 done. Results in $RESULTS/RQ1_*.txt"
