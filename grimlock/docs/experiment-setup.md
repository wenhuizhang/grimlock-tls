# Grimlock Experiment Setup Guide

This document describes how to set up the POC experiment environment.

## Test Infrastructure

### Current Test Machine
- **Host A (Primary)**: `<HOST_A_IP>` (AWS Lightsail)
  - Access: `ssh -i "~/.ssh/<your-key>.pem" ubuntu@<HOST_A_IP>`

### Recommended: Add Second Test Machine
For mTLS testing, we need a second machine. Options:

1. **AWS Lightsail** (recommended for consistency)
   - Launch another Ubuntu 22.04/24.04 instance
   - Ensure security group allows traffic between hosts
   
2. **Local VM**
   - Vagrant or Multipass
   - Requires bridged networking for host-to-host communication

3. **Docker** (limited)
   - Can test basic eBPF but kTLS may have limitations in containers

## Initial Host Setup

### 1. Connect to Test Machine

```bash
# From your local machine
ssh -i "~/.ssh/<your-key>.pem" ubuntu@<HOST_A_IP>
```

### 2. Check Kernel Version & Requirements

```bash
# Check kernel version (need 5.10+, prefer 6.1+)
uname -r

# Check for BTF support (needed for CO-RE)
ls -la /sys/kernel/btf/vmlinux

# Check if kTLS module is available
modprobe -n tls && echo "kTLS available"
cat /boot/config-$(uname -r) | grep CONFIG_TLS

# Check eBPF features
cat /boot/config-$(uname -r) | grep -E "CONFIG_BPF|CONFIG_CGROUP_BPF"
```

### 3. Install Dependencies

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install eBPF development tools
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    linux-tools-common \
    pkg-config \
    libssl-dev \
    openssl \
    git \
    curl

# Install bpftool (may need this)
sudo apt-get install -y linux-tools-generic || true

# Verify installation
clang --version
bpftool version
```

### 4. Enable kTLS

```bash
# Load kTLS module
sudo modprobe tls

# Make persistent
echo "tls" | sudo tee -a /etc/modules

# Verify
lsmod | grep tls
```

### 5. System Configuration

```bash
# Mount BPF filesystem (if not already)
sudo mount -t bpf bpf /sys/fs/bpf || true

# Enable BPF JIT
sudo sysctl -w net.core.bpf_jit_enable=1
echo "net.core.bpf_jit_enable=1" | sudo tee -a /etc/sysctl.d/99-ebpf.conf

# Increase locked memory for eBPF maps
echo "* soft memlock unlimited" | sudo tee -a /etc/security/limits.conf
echo "* hard memlock unlimited" | sudo tee -a /etc/security/limits.conf
```

### 6. Clone Project

```bash
cd ~
git clone <your-repo-url> grimlock
cd grimlock
```

### 7. Generate vmlinux.h

```bash
# This generates kernel type definitions for eBPF CO-RE
mkdir -p src/bpf
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```

### 8. Build eBPF Programs

```bash
make bpf
```

## Two-Host Experiment Setup

### Network Configuration

Ensure both hosts can communicate:

```bash
# On Host A
ping <host-b-ip>

# Check ports are open (we'll use 9443 for control plane)
# May need to configure security groups/firewall
```

### Certificate Generation

```bash
# On your local machine or Host A
./scripts/generate-certs.sh \
    --agent agent-a --ip <HOST_A_IP> \
    --agent agent-b --ip <host-b-ip>

# Deploy certificates
scp -i ~/.ssh/<your-key>.pem certs/ca.crt certs/agent-a.* ubuntu@<HOST_A_IP>:~/grimlock/certs/
scp -i ~/.ssh/<key>.pem certs/ca.crt certs/agent-b.* ubuntu@<host-b-ip>:~/grimlock/certs/
```

## Quick Validation Tests

### Test 1: Verify eBPF Loading

```bash
# Load a simple program
sudo bpftool prog load target/bpf/sock_ops.bpf.o /sys/fs/bpf/test_prog

# Check it's loaded
sudo bpftool prog list

# Clean up
sudo rm /sys/fs/bpf/test_prog
```

### Test 2: Verify kTLS Works

```bash
# Create a simple kTLS test
cat > /tmp/test_ktls.c << 'EOF'
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <linux/tls.h>

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Check if SOL_TLS is recognized
    struct tls12_crypto_info_aes_gcm_128 crypto_info = {
        .info.version = TLS_1_2_VERSION,
        .info.cipher_type = TLS_CIPHER_AES_GCM_128,
    };
    
    printf("kTLS structures available!\n");
    printf("TLS_1_2_VERSION = %d\n", TLS_1_2_VERSION);
    printf("TLS_CIPHER_AES_GCM_128 = %d\n", TLS_CIPHER_AES_GCM_128);
    
    close(sock);
    return 0;
}
EOF

gcc -o /tmp/test_ktls /tmp/test_ktls.c && /tmp/test_ktls
```

### Test 3: Verify Sockmap Operations

```bash
# Create a test sockmap
sudo bpftool map create /sys/fs/bpf/test_sockmap type sockmap entries 10 name test key 4 value 8

# Verify
sudo bpftool map list

# Clean up  
sudo rm /sys/fs/bpf/test_sockmap
```

## Development Workflow

### On Local Machine (macOS)
- Edit code
- Run linters/tests that don't require Linux

### On Test Machine
```bash
# Sync code (from local)
rsync -avz --exclude 'target' --exclude 'certs' \
    ./ ubuntu@<HOST_A_IP>:~/grimlock/

# Or use git
git push
# Then on test machine:
git pull

# Build and test
make clean && make bpf
sudo make test
```

## Troubleshooting

### "vmlinux.h not found"
```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```

### "Permission denied" when loading eBPF
```bash
# Must run as root
sudo bpftool prog load ...

# Or add CAP_BPF capability
sudo setcap cap_bpf+ep /path/to/binary
```

### kTLS setsockopt fails
```bash
# Ensure module is loaded
sudo modprobe tls
lsmod | grep tls

# Check kernel config
zcat /proc/config.gz | grep CONFIG_TLS  # or
cat /boot/config-$(uname -r) | grep CONFIG_TLS
```

### eBPF verifier rejects program
```bash
# Get detailed verifier output
sudo bpftool prog load target/bpf/sock_ops.bpf.o /sys/fs/bpf/test 2>&1 | head -100

# Common issues:
# - Unbounded loops (add explicit bounds)
# - Invalid memory access (check map lookups for NULL)
# - Stack too large (reduce local variables)
```

## Next Steps

After basic setup is validated:

1. **Phase 1**: Get basic sock_ops program working - just tracking connections
2. **Phase 2**: Implement user-space TLS handshake
3. **Phase 3**: Connect kTLS to eBPF redirect
4. **Phase 4**: Full mTLS tunnel test
