#!/usr/bin/env bash
source "$(dirname "$0")/../common.sh"
banner "RQ5: kernel mechanisms on a real kernel (interception, kTLS, splice)"

if ! have_root; then
  skip "RQ5 needs root to load eBPF and attach to a cgroup: rerun after 'sudo -v'."
  exit 0
fi

if ( cd "$GRIM" && go test -c -o /tmp/grim_mech.test ./cmd/grimlock/ >/dev/null 2>&1 ); then
  sudo /tmp/grim_mech.test \
    -test.run 'TestEBPF_LoadAndAttach|TestEBPF_Connect4Redirects|TestKTLS_Engages|TestSplice_TCPToTCP' \
    -test.v 2>&1 | tee "$RESULTS/RQ5_mechanisms.txt"
else
  skip "could not build the test binary"
fi

echo
echo "[optional] splice syscalls under strace:"
echo "  strace -f -e trace=splice /tmp/grim_mech.test -test.run TestSplice_TCPToTCP 2>&1 | grep 'splice('"

echo
echo "RQ5 done. Results in $RESULTS/RQ5_*.txt"
