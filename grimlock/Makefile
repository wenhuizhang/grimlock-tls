# Grimlock Makefile
# Builds eBPF programs and Go control plane

.PHONY: all clean generate build vmlinux install help test check

# Directories
BPF_SRC := src/bpf
CMD_DIR := cmd/grimlock
BIN_DIR := bin

# Tools
CLANG ?= clang
BPFTOOL ?= bpftool
GO ?= go

# Default target
all: vmlinux generate build

# Help
help:
	@echo "Grimlock Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build everything (default)"
	@echo "  vmlinux   - Generate vmlinux.h from BTF"
	@echo "  generate  - Generate Go bindings from eBPF C"
	@echo "  build     - Build Go binary"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to /usr/local/bin"
	@echo "  test      - Run tests"
	@echo "  check     - Check system requirements"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build everything"
	@echo "  sudo ./bin/grimlock --peers \$$HOST_B_IP"

# Generate vmlinux.h from kernel BTF
vmlinux: $(BPF_SRC)/vmlinux.h

$(BPF_SRC)/vmlinux.h:
	@echo "[1/3] Generating vmlinux.h from kernel BTF..."
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
		echo "      Generated $@"; \
	else \
		echo "      ERROR: /sys/kernel/btf/vmlinux not found"; \
		echo "      Run this on a system with BTF support"; \
		exit 1; \
	fi

# Generate Go bindings using bpf2go
generate: vmlinux
	@echo "[2/3] Generating Go bindings from eBPF..."
	cd $(CMD_DIR) && $(GO) generate ./...
	@echo "      Generated bpf_bpfel.go"

# Build Go binary
build: 
	@echo "[3/3] Building grimlock binary..."
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/grimlock ./$(CMD_DIR)
	@echo "      Built $(BIN_DIR)/grimlock"

# Build for Linux (cross-compile from macOS)
build-linux:
	@echo "Cross-compiling for Linux..."
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BIN_DIR)/grimlock-linux ./$(CMD_DIR)
	@echo "      Built $(BIN_DIR)/grimlock-linux"

# Clean build artifacts  
clean:
	rm -rf $(BIN_DIR)
	rm -f $(CMD_DIR)/bpf_bpfel.go $(CMD_DIR)/bpf_bpfel.o
	rm -f $(CMD_DIR)/bpf_bpfeb.go $(CMD_DIR)/bpf_bpfeb.o
	rm -f $(BPF_SRC)/vmlinux.h

# Install binary
install: all
	@echo "Installing grimlock..."
	install -m 755 $(BIN_DIR)/grimlock /usr/local/bin/grimlock
	@echo "Installed to /usr/local/bin/grimlock"

# Run on remote host. Set the following env vars before invoking:
#   SSH_KEY    path to the SSH private key (e.g. ~/.ssh/your-key.pem)
#   SSH_USER   remote user (defaults to ubuntu)
#   HOST_A_IP  IP of host A
#   HOST_B_IP  IP of host B
SSH_USER ?= ubuntu
SSH_KEY ?= ~/.ssh/your-key.pem

run-host1:
	@: $${HOST_A_IP:?set HOST_A_IP} $${HOST_B_IP:?set HOST_B_IP}
	ssh -i $(SSH_KEY) $(SSH_USER)@$(HOST_A_IP) \
		'cd ~/grimlock && sudo ./bin/grimlock --peers $(HOST_B_IP)'

run-host2:
	@: $${HOST_A_IP:?set HOST_A_IP} $${HOST_B_IP:?set HOST_B_IP}
	ssh -i $(SSH_KEY) $(SSH_USER)@$(HOST_B_IP) \
		'cd ~/grimlock && sudo ./bin/grimlock --peers $(HOST_A_IP)'

# Test
test:
	$(GO) test -v ./...

# Check system requirements
check:
	@echo "Checking system requirements..."
	@echo ""
	@echo "System:"
	@echo "  Kernel: $$(uname -r)"
	@echo "  OS: $$(uname -s)"
	@echo ""
	@echo "Tools:"
	@echo "  Clang: $$(which clang 2>/dev/null && clang --version | head -1 || echo 'NOT FOUND')"
	@echo "  Go: $$(which go 2>/dev/null && go version || echo 'NOT FOUND')"
	@echo "  bpftool: $$(which bpftool 2>/dev/null || echo 'NOT FOUND')"
	@echo ""
	@echo "eBPF Support:"
	@echo "  BTF: $$(test -f /sys/kernel/btf/vmlinux && echo 'Available' || echo 'Not available')"
	@echo "  kTLS: $$(lsmod 2>/dev/null | grep -q tls && echo 'Loaded' || echo 'Not loaded')"
	@echo "  cgroup2: $$(mount | grep -q cgroup2 && echo 'Mounted' || echo 'Not mounted')"
