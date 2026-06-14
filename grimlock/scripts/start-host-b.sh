#!/bin/bash
# Launch grimlock on Host B (peers with Host A).
#
# Required environment variables:
#   HOST_A_IP    IP address of the peer running on Host A
# Optional:
#   GRIMLOCK_BIN path to the grimlock binary (defaults to /tmp/grimlock-poc)
set -euo pipefail

: "${HOST_A_IP:?set HOST_A_IP to the peer's IP, e.g. export HOST_A_IP=10.0.0.1}"
GRIMLOCK_BIN="${GRIMLOCK_BIN:-/tmp/grimlock-poc}"

cd ~/grimlock
CERT=certs/agent-b.crt
KEY=certs/agent-b.pem
CA=certs/ca.crt

sudo "$GRIMLOCK_BIN" --peers "$HOST_A_IP" --cert "$CERT" --key "$KEY" --ca "$CA"
