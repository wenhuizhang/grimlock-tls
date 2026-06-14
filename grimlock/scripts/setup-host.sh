#!/bin/bash
# Grimlock Host Setup Script
# Sets up a Linux host for eBPF + kTLS development

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check kernel version
check_kernel() {
    log_info "Checking kernel version..."
    KERNEL_VERSION=$(uname -r)
    KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
    
    echo "  Kernel: $KERNEL_VERSION"
    
    if [[ $KERNEL_MAJOR -lt 5 ]] || [[ $KERNEL_MAJOR -eq 5 && $KERNEL_MINOR -lt 10 ]]; then
        log_error "Kernel 5.10+ required. Current: $KERNEL_VERSION"
        log_info "Consider upgrading kernel or using a newer distribution"
        exit 1
    fi
    
    if [[ $KERNEL_MAJOR -ge 6 ]]; then
        log_info "✓ Kernel $KERNEL_VERSION (excellent eBPF support)"
    else
        log_warn "Kernel $KERNEL_VERSION (minimum supported, 6.1+ recommended)"
    fi
}

# Check and enable kTLS
check_ktls() {
    log_info "Checking kTLS support..."
    
    # Check if tls module is available
    if modprobe -n tls 2>/dev/null; then
        modprobe tls
        log_info "✓ kTLS module loaded"
    else
        log_warn "kTLS module not found - checking if built-in..."
    fi
    
    # Verify kTLS is available
    if [[ -d /sys/module/tls ]] || grep -q "CONFIG_TLS=y" /boot/config-$(uname -r) 2>/dev/null; then
        log_info "✓ kTLS is available"
    else
        log_error "kTLS not available in this kernel"
        log_info "Rebuild kernel with CONFIG_TLS=y or use a distribution that includes it"
        exit 1
    fi
}

# Check eBPF capabilities
check_ebpf() {
    log_info "Checking eBPF capabilities..."
    
    # Check BPF syscall
    if [[ -e /sys/kernel/btf/vmlinux ]]; then
        log_info "✓ BTF (BPF Type Format) available"
    else
        log_warn "BTF not available - CO-RE (Compile Once, Run Everywhere) won't work"
        log_info "Consider using a kernel with CONFIG_DEBUG_INFO_BTF=y"
    fi
    
    # Check bpf filesystem
    if mount | grep -q "bpf on /sys/fs/bpf"; then
        log_info "✓ BPF filesystem mounted"
    else
        log_info "Mounting BPF filesystem..."
        mount -t bpf bpf /sys/fs/bpf || true
    fi
    
    # Check cgroup2
    if mount | grep -q "cgroup2"; then
        log_info "✓ cgroup2 available"
    else
        log_warn "cgroup2 not mounted - some eBPF programs may not work"
    fi
}

# Install development dependencies
install_deps_ubuntu() {
    log_info "Installing dependencies (Ubuntu/Debian)..."
    
    apt-get update
    apt-get install -y \
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
        curl \
        bpftool || apt-get install -y linux-tools-generic
    
    # Install Rust if not present
    if ! command -v rustc &> /dev/null; then
        log_info "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    log_info "✓ Dependencies installed"
}

install_deps_fedora() {
    log_info "Installing dependencies (Fedora/RHEL)..."
    
    dnf install -y \
        clang \
        llvm \
        libbpf-devel \
        elfutils-libelf-devel \
        kernel-headers \
        kernel-devel \
        bpftool \
        openssl-devel \
        openssl \
        git \
        curl \
        make \
        gcc
    
    # Install Rust if not present
    if ! command -v rustc &> /dev/null; then
        log_info "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    log_info "✓ Dependencies installed"
}

# Detect OS and install deps
install_deps() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian)
                install_deps_ubuntu
                ;;
            fedora|rhel|centos|rocky|alma)
                install_deps_fedora
                ;;
            *)
                log_warn "Unknown OS: $ID - please install dependencies manually"
                log_info "Required: clang, llvm, libbpf-dev, libelf-dev, bpftool, openssl, rust"
                ;;
        esac
    else
        log_error "Cannot detect OS"
        exit 1
    fi
}

# Generate vmlinux.h for BTF-based eBPF
generate_vmlinux() {
    log_info "Generating vmlinux.h for BTF..."
    
    VMLINUX_PATH="$(dirname "$0")/../src/bpf/vmlinux.h"
    
    if command -v bpftool &> /dev/null && [[ -e /sys/kernel/btf/vmlinux ]]; then
        mkdir -p "$(dirname "$VMLINUX_PATH")"
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX_PATH"
        log_info "✓ Generated vmlinux.h"
    else
        log_warn "Cannot generate vmlinux.h - bpftool or BTF not available"
        log_info "You may need to use kernel headers instead"
    fi
}

# System tuning for eBPF
tune_system() {
    log_info "Tuning system for eBPF..."
    
    # Increase locked memory limit (for eBPF maps)
    if ! grep -q "memlock" /etc/security/limits.conf; then
        echo "* soft memlock unlimited" >> /etc/security/limits.conf
        echo "* hard memlock unlimited" >> /etc/security/limits.conf
        log_info "✓ Set memlock to unlimited"
    fi
    
    # Enable BPF JIT
    sysctl -w net.core.bpf_jit_enable=1
    echo "net.core.bpf_jit_enable=1" >> /etc/sysctl.d/99-ebpf.conf
    
    log_info "✓ System tuned"
}

# Print system info
print_summary() {
    echo ""
    echo "=============================================="
    echo "           Grimlock Host Setup Complete"
    echo "=============================================="
    echo ""
    echo "Kernel:     $(uname -r)"
    echo "Clang:      $(clang --version | head -1)"
    echo "LLVM:       $(llvm-config --version 2>/dev/null || echo 'N/A')"
    echo "bpftool:    $(bpftool version 2>/dev/null | head -1 || echo 'N/A')"
    echo "OpenSSL:    $(openssl version)"
    echo "Rust:       $(rustc --version 2>/dev/null || echo 'Not installed')"
    echo ""
    echo "BTF:        $(test -e /sys/kernel/btf/vmlinux && echo 'Available' || echo 'Not available')"
    echo "kTLS:       $(test -d /sys/module/tls && echo 'Loaded' || echo 'Check /boot/config-*')"
    echo ""
    echo "Next steps:"
    echo "  1. Run ./scripts/generate-certs.sh to create test certificates"
    echo "  2. Run 'make' to build the project"
    echo "  3. Deploy to second host and repeat setup"
    echo ""
}

# Main
main() {
    echo "=============================================="
    echo "        Grimlock Host Setup Script"
    echo "=============================================="
    echo ""
    
    check_root
    check_kernel
    check_ktls
    check_ebpf
    install_deps
    generate_vmlinux
    tune_system
    print_summary
}

main "$@"
