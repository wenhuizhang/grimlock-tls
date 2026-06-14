#!/bin/bash
# Launch grimlock on Host A (peers with Host B).
#
# Required environment variables:
#   HOST_B_IP    IP address of the peer running on Host B
# Optional:
#   GRIMLOCK_BIN path to the grimlock binary (defaults to /tmp/grimlock-poc)
set -euo pipefail

: "${HOST_B_IP:?set HOST_B_IP to the peer's IP, e.g. export HOST_B_IP=10.0.0.2}"
GRIMLOCK_BIN="${GRIMLOCK_BIN:-/tmp/grimlock-poc}"

cd ~/grimlock
CERT=certs/agent-a.crt
KEY=certs/agent-a.pem
CA=certs/ca.crt

sudo "$GRIMLOCK_BIN" --peers "$HOST_B_IP" --cert "$CERT" --key "$KEY" --ca "$CA"
