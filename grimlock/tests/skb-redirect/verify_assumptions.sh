#!/bin/bash
# Verify assumptions for sk_skb redirect approach
#
# This script tests the key assumptions before we implement the full solution:
# 1. Can we create and use a sockmap?
# 2. Does the kernel support sk_skb programs?
# 3. Does kTLS work with sockmap/sk_skb?

set -e

echo "=============================================="
echo "  Grimlock sk_skb Redirect - Assumption Tests"
echo "=============================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must run as root"
    exit 1
fi

echo "[1] Checking kernel version and eBPF support..."
echo "    Kernel: $(uname -r)"

# Check kernel version (need 4.18+ for sk_skb, 5.x preferred)
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
echo "    Version: $KERNEL_MAJOR.$KERNEL_MINOR"

if [ "$KERNEL_MAJOR" -lt 5 ]; then
    echo "    WARNING: Kernel < 5.x may have sk_skb bugs"
fi

# Check BPF filesystem
if ! mount | grep -q "bpf on /sys/fs/bpf"; then
    echo "    Mounting BPF filesystem..."
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
fi
echo "    ✓ BPF filesystem available"

echo ""
echo "[2] Checking kTLS support..."

# Check if kTLS module is available
if [ -f /proc/config.gz ]; then
    if zcat /proc/config.gz | grep -q "CONFIG_TLS="; then
        echo "    ✓ kTLS compiled in kernel"
    fi
elif [ -f /boot/config-$(uname -r) ]; then
    if grep -q "CONFIG_TLS=" /boot/config-$(uname -r); then
        echo "    ✓ kTLS in kernel config"
    fi
fi

# Try to load tls module
modprobe tls 2>/dev/null || true
if lsmod | grep -q "^tls "; then
    echo "    ✓ kTLS module loaded"
else
    echo "    Note: kTLS may be built-in (not a module)"
fi

echo ""
echo "[3] Checking bpftool availability..."
if command -v bpftool &> /dev/null; then
    echo "    ✓ bpftool available: $(which bpftool)"
    BPFTOOL="bpftool"
else
    echo "    Installing bpftool..."
    apt-get update && apt-get install -y linux-tools-common linux-tools-$(uname -r) 2>/dev/null || {
        echo "    WARNING: Could not install bpftool"
        BPFTOOL=""
    }
fi

echo ""
echo "[4] Testing sockmap creation..."

# Create a test sockmap using bpftool
TEST_MAP="/sys/fs/bpf/test_sockmap_$$"
if [ -n "$BPFTOOL" ]; then
    $BPFTOOL map create $TEST_MAP type sockhash key 4 value 8 entries 16 name test_sockmap 2>/dev/null
    if [ -f "$TEST_MAP" ]; then
        echo "    ✓ Sockmap created successfully"
        rm -f $TEST_MAP
    else
        echo "    ✗ Failed to create sockmap"
    fi
else
    echo "    Skipped (no bpftool)"
fi

echo ""
echo "[5] Checking available eBPF program types..."
if [ -n "$BPFTOOL" ]; then
    # List supported program types
    echo "    Checking for sk_skb support..."
    if $BPFTOOL feature probe | grep -q "sk_skb"; then
        echo "    ✓ sk_skb program type supported"
    else
        # Try alternative check
        if [ -f /proc/config.gz ]; then
            if zcat /proc/config.gz | grep -q "CONFIG_BPF_STREAM_PARSER=y"; then
                echo "    ✓ BPF stream parser enabled (sk_skb support)"
            fi
        fi
    fi
    
    echo "    Checking for sk_msg support..."
    if $BPFTOOL feature probe | grep -q "sk_msg"; then
        echo "    ✓ sk_msg program type supported"
    fi
fi

echo ""
echo "[6] Testing basic socket operations with Python..."

# Use Python for quick socket testing (available on most systems)
python3 << 'PYEOF'
import socket
import os
import struct

print("    Testing socket cookie retrieval...")

# Create a socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 19999))
sock.listen(1)

# Get socket cookie (SO_COOKIE = 57)
SO_COOKIE = 57
try:
    cookie_bytes = sock.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8)
    cookie = struct.unpack('Q', cookie_bytes)[0]
    print(f"    ✓ Socket cookie: {cookie}")
except Exception as e:
    print(f"    ✗ Could not get socket cookie: {e}")

sock.close()

print("    Testing TCP connection...")
# Quick server/client test
import threading

received = []

def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 19998))
    s.listen(1)
    conn, addr = s.accept()
    data = conn.recv(1024)
    received.append(data)
    conn.close()
    s.close()

t = threading.Thread(target=server)
t.start()

import time
time.sleep(0.1)

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect(('127.0.0.1', 19998))
c.send(b'TEST_DATA')
c.close()

t.join()

if received and received[0] == b'TEST_DATA':
    print("    ✓ Basic TCP works")
else:
    print("    ✗ Basic TCP failed")

PYEOF

echo ""
echo "[7] Testing kTLS socket option..."

python3 << 'PYEOF'
import socket
import struct

# Constants for kTLS
TCP_ULP = 31
SOL_TCP = 6
SOL_TLS = 282
TLS_TX = 1
TLS_RX = 2

print("    Testing TCP_ULP=tls...")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 19997))
sock.listen(1)

# We need a connected socket for TCP_ULP
import threading
def connect():
    import time
    time.sleep(0.1)
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect(('127.0.0.1', 19997))
    return c

import concurrent.futures
with concurrent.futures.ThreadPoolExecutor() as executor:
    future = executor.submit(connect)
    conn, addr = sock.accept()
    client = future.result()

try:
    # Try to set TCP_ULP to "tls"
    conn.setsockopt(SOL_TCP, TCP_ULP, b'tls')
    print("    ✓ TCP_ULP=tls succeeded (kTLS available)")
    
    # Note: We can't actually configure TLS_TX/TLS_RX without doing
    # a real TLS handshake first to get the keys
    
except OSError as e:
    if e.errno == 92:  # ENOPROTOOPT
        print("    ✗ TCP_ULP=tls failed (kTLS not available)")
    elif e.errno == 22:  # EINVAL
        print("    ✗ TCP_ULP=tls failed (invalid state)")
    else:
        print(f"    ✗ TCP_ULP=tls failed: {e}")

conn.close()
client.close()
sock.close()

PYEOF

echo ""
echo "[8] Checking sk_skb + sockmap kernel support..."

# Check kernel config for stream parser
if [ -f /proc/config.gz ]; then
    echo "    Kernel config checks:"
    for opt in CONFIG_BPF_STREAM_PARSER CONFIG_NET_SOCK_MSG CONFIG_TLS CONFIG_TLS_DEVICE; do
        val=$(zcat /proc/config.gz | grep "^$opt=" | cut -d= -f2)
        if [ -n "$val" ]; then
            echo "      $opt=$val"
        fi
    done
elif [ -f /boot/config-$(uname -r) ]; then
    echo "    Kernel config checks:"
    for opt in CONFIG_BPF_STREAM_PARSER CONFIG_NET_SOCK_MSG CONFIG_TLS CONFIG_TLS_DEVICE; do
        val=$(grep "^$opt=" /boot/config-$(uname -r) | cut -d= -f2)
        if [ -n "$val" ]; then
            echo "      $opt=$val"
        fi
    done
fi

echo ""
echo "=============================================="
echo "  Summary"
echo "=============================================="
echo ""
echo "  To proceed with sk_skb redirect, we need:"
echo "  1. Kernel 5.x+ (recommended)"
echo "  2. CONFIG_BPF_STREAM_PARSER=y"
echo "  3. kTLS support"
echo ""
echo "  Next steps:"
echo "  1. Create a minimal sk_skb program"
echo "  2. Load with bpf2go or bpftool"
echo "  3. Attach to sockmap"
echo "  4. Test redirect between two sockets"
echo "  5. Test with kTLS enabled socket"
echo ""
