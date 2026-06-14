#!/bin/bash
# Deploy Grimlock to a remote host
# Usage: ./scripts/deploy-remote.sh <user>@<host> [ssh-key]

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <user>@<host> [ssh-key-path]"
    echo ""
    echo "Examples:"
    echo "  $0 ubuntu@10.0.0.1 ~/.ssh/your-key.pem"
    echo "  $0 root@192.168.1.100"
    exit 1
fi

REMOTE_HOST="$1"
SSH_KEY="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}/.."

# Build SSH command
SSH_CMD="ssh"
SCP_CMD="scp"
RSYNC_CMD="rsync"

if [[ -n "$SSH_KEY" ]]; then
    SSH_CMD="ssh -i $SSH_KEY"
    SCP_CMD="scp -i $SSH_KEY"
    RSYNC_CMD="rsync -e 'ssh -i $SSH_KEY'"
fi

echo "=============================================="
echo "     Grimlock Remote Deployment"
echo "=============================================="
echo ""
echo "Target: $REMOTE_HOST"
echo ""

# Test connection
echo "[1/5] Testing connection..."
$SSH_CMD "$REMOTE_HOST" "echo 'Connection OK'"

# Check remote system
echo ""
echo "[2/5] Checking remote system..."
$SSH_CMD "$REMOTE_HOST" << 'REMOTE_CHECK'
echo "  Kernel: $(uname -r)"
echo "  BTF: $(test -f /sys/kernel/btf/vmlinux && echo 'Available' || echo 'Not available')"
echo "  kTLS: $(modprobe -n tls 2>/dev/null && echo 'Available' || echo 'Check needed')"
REMOTE_CHECK

# Sync project files
echo ""
echo "[3/5] Syncing project files..."
cd "$PROJECT_DIR"

# Use rsync for efficient sync
if [[ -n "$SSH_KEY" ]]; then
    rsync -avz --progress \
        --exclude 'target' \
        --exclude 'certs/*.key' \
        --exclude 'certs/*.pem' \
        --exclude '.git' \
        --exclude 'src/bpf/vmlinux.h' \
        -e "ssh -i $SSH_KEY" \
        ./ "${REMOTE_HOST}:~/grimlock/"
else
    rsync -avz --progress \
        --exclude 'target' \
        --exclude 'certs/*.key' \
        --exclude 'certs/*.pem' \
        --exclude '.git' \
        --exclude 'src/bpf/vmlinux.h' \
        ./ "${REMOTE_HOST}:~/grimlock/"
fi

# Run setup on remote
echo ""
echo "[4/5] Running setup on remote host..."
$SSH_CMD "$REMOTE_HOST" << 'REMOTE_SETUP'
cd ~/grimlock

# Make scripts executable
chmod +x scripts/*.sh

# Generate vmlinux.h if BTF available
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "Generating vmlinux.h..."
    sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
    echo "  Done"
else
    echo "Warning: BTF not available, vmlinux.h not generated"
fi

# Quick dependency check
echo ""
echo "Checking dependencies..."
which clang > /dev/null && echo "  clang: OK" || echo "  clang: MISSING"
which bpftool > /dev/null && echo "  bpftool: OK" || echo "  bpftool: MISSING"
which openssl > /dev/null && echo "  openssl: OK" || echo "  openssl: MISSING"

REMOTE_SETUP

# Build on remote (optional)
echo ""
echo "[5/5] Build status..."
read -p "Build eBPF programs on remote? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    $SSH_CMD "$REMOTE_HOST" "cd ~/grimlock && make bpf"
fi

echo ""
echo "=============================================="
echo "     Deployment Complete"
echo "=============================================="
echo ""
echo "To connect to the remote host:"
if [[ -n "$SSH_KEY" ]]; then
    echo "  ssh -i $SSH_KEY $REMOTE_HOST"
else
    echo "  ssh $REMOTE_HOST"
fi
echo ""
echo "Then:"
echo "  cd ~/grimlock"
echo "  sudo ./scripts/setup-host.sh  # Full setup (if needed)"
echo "  make bpf                       # Build eBPF programs"
echo ""
