#!/usr/bin/env bash
# Shared helpers for the evaluation scripts.
#
# Design: every experiment runs in SMOKE mode now, without a trusted domain, using
# a stub quoter over real sessions and loopback where a second host is absent. When
# a capability appears (a trusted domain, root, or a second host), the same script
# runs the FULL experiment. Nothing is silently skipped; a skipped full step prints
# what it needs and how to enable it. This is what lets "run all" succeed once TDX
# is up without changing the scripts.
#
# Capability signals:
#   root   : id 0, or passwordless sudo.
#   tdx    : configfs-tsm present, or GRIMLOCK_TDX=1 to force.
#   peer   : GRIMLOCK_PEER set to a second host's address for cross-host runs.

set -uo pipefail

EVAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRIM="$(cd "$EVAL_DIR/.." && pwd)"   # grimlock Go module root
RESULTS="$EVAL_DIR/results"
mkdir -p "$RESULTS"

have_root() { [ "$(id -u)" = "0" ] || sudo -n true 2>/dev/null; }
have_tdx()  { [ -e /sys/kernel/config/tsm/report ] || [ "${GRIMLOCK_TDX:-0}" = "1" ]; }
have_peer() { [ -n "${GRIMLOCK_PEER:-}" ]; }

capline() {
  printf 'capabilities: root=%s tdx=%s peer=%s\n' \
    "$(have_root && echo yes || echo no)" \
    "$(have_tdx  && echo yes || echo no)" \
    "${GRIMLOCK_PEER:-none}"
}

banner() { echo; echo "================ $1 ================"; capline; echo; }

skip() { echo "[SKIP] $1"; }
note() { echo "[NOTE] $1"; }

# grun <result-basename> <command...> : run from the module root, echo and save.
grun() {
  local base="$1"; shift
  echo "[run] $*"
  ( cd "$GRIM" && "$@" ) 2>&1 | tee "$RESULTS/$base"
}
