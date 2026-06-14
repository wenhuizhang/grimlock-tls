# Grimlock: Transparent Security for AI Agent Communication

> eBPF + kTLS for zero-code-change mTLS between A2A agents

## What is Grimlock?

Grimlock provides **transparent mTLS encryption** for AI agent-to-agent (A2A) communication. Agents write plain HTTP code — Grimlock handles encryption invisibly using eBPF for connection interception and kernel TLS (kTLS) for encryption.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Agent A (plain HTTP)                    Agent B (plain HTTP)           │
│         │                                       ▲                       │
│         │ connect(B:8080)                       │                       │
│         ▼                                       │                       │
│  ┌──────────────┐                        ┌──────────────┐               │
│  │   Grimlock   │ ═══ TLS 1.3 Tunnel ═══ │   Grimlock   │               │
│  │  (eBPF +     │      (encrypted)       │  (eBPF +     │               │
│  │   kTLS)      │                        │   kTLS)      │               │
│  └──────────────┘                        └──────────────┘               │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Features

| Feature | Description |
|---------|-------------|
| **Zero Code Changes** | Agents use plain HTTP — no TLS libraries needed |
| **eBPF Connection Interception** | `cgroup/connect4` transparently redirects connections |
| **Kernel TLS (kTLS)** | Encryption/decryption in kernel for efficiency |
| **Mutual TLS (mTLS)** | Both agents verify each other's identity via certificates |
| **A2A Protocol Compatible** | Works with Google's Agent2Agent protocol |

## Quick Start

### Prerequisites
- Linux kernel 5.15+ with eBPF and kTLS support
- Go 1.21+
- Root access (for eBPF)

### Build
```bash
cd cmd/grimlock
go generate ./...
go build -o grimlock .
```

### Run
```bash
# On Host A (with Agent A)
sudo ./grimlock --peers=<host-b-ip> \
    --cert=certs/agent-a.crt \
    --key=certs/agent-a.pem \
    --ca=certs/ca.crt

# On Host B (with Agent B)  
sudo ./grimlock --peers=<host-a-ip> \
    --cert=certs/agent-b.crt \
    --key=certs/agent-b.pem \
    --ca=certs/ca.crt
```

### Test
```bash
# From Host A - this request is transparently encrypted!
curl http://<host-b-ip>:8080/.well-known/agent.json
```

## Architecture

```
                           HOST A                                    
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│  Agent (curl/app)                                                │
│       │                                                          │
│       │ connect(B:8080)                                          │
│       ▼                                                          │
│  ┌─────────────────────────────────────┐                        │
│  │  eBPF: cgroup/connect4              │                        │
│  │  - Intercepts connect() syscall     │                        │
│  │  - Redirects to localhost:15001     │                        │
│  └─────────────────────────────────────┘                        │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────────────────────────────┐                        │
│  │  Grimlock Daemon (Go)               │                        │
│  │  - Accepts on :15001                │                        │
│  │  - Creates TLS tunnel to peer       │                        │
│  │  - kTLS enabled (kernel encrypts)   │                        │
│  │  - Forwards bidirectionally         │                        │
│  └─────────────────────────────────────┘                        │
│       │                                                          │
│       │  TLS 1.3 (AES-128-GCM)                                  │
│       │  Port 9443                                               │
└───────┼──────────────────────────────────────────────────────────┘
        │
        ▼  ENCRYPTED ON WIRE
        │
┌───────┼──────────────────────────────────────────────────────────┐
│       │                          HOST B                          │
│       ▼                                                          │
│  ┌─────────────────────────────────────┐                        │
│  │  Grimlock Daemon (Go)               │                        │
│  │  - Accepts on :9443                 │                        │
│  │  - Verifies peer certificate        │                        │
│  │  - Forwards to local agent          │                        │
│  └─────────────────────────────────────┘                        │
│       │                                                          │
│       ▼                                                          │
│  Agent B (:8080)                                                 │
│  - Receives plain HTTP                                           │
│  - No TLS code needed                                            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## How It Works

1. **Agent makes connection**: Agent A calls `connect(host-b:8080)`
2. **eBPF intercepts**: `cgroup/connect4` program redirects to Grimlock's local listener
3. **Grimlock forwards**: Creates TLS tunnel to peer Grimlock, enables kTLS
4. **Kernel encrypts**: kTLS handles encryption in kernel space
5. **Peer receives**: Grimlock B receives, forwards to local Agent B
6. **Agent B responds**: Response flows back through encrypted tunnel

## Project Structure

```
ai-grimlock/
├── cmd/
│   └── grimlock/           # Main Grimlock daemon
│       ├── main.go         # Entry point, eBPF loading
│       ├── tunnel.go       # TLS tunnel management
│       └── crypto.go       # kTLS key derivation
├── src/bpf/
│   └── grimlock.bpf.c      # eBPF programs (sock_ops, connect4)
├── demo/
│   └── a2a-agent/          # Demo A2A agent for testing
├── docs/
│   ├── POC-PLAN.md         # Detailed implementation plan
│   ├── DEMO-GUIDE.md       # Testing and demo guide
│   └── LESSONS-LEARNED.md  # Technical discoveries
├── certs/                  # Certificates (not in git)
└── scripts/
    └── generate-certs.sh   # PKI generation
```

## Documentation

- [Demo Guide](docs/DEMO-GUIDE.md) - How to test and demo
- [POC Plan](docs/POC-PLAN.md) - Detailed design and implementation plan
- [Lessons Learned](docs/LESSONS-LEARNED.md) - Technical discoveries during development
- [Architecture](docs/architecture.md) - Technical deep-dive

## Test Infrastructure

| Host | IP | Role |
|------|-----|------|
| Host 1 | <HOST_A_IP> | planning-agent |
| Host 2 | <HOST_B_IP> | research-agent |

## Key Technical Insights

1. **sk_msg bypasses kTLS**: We discovered that `sk_msg` redirect operates at TCP buffer level, bypassing kTLS encryption. Solution: Use `cgroup/connect4` for interception + user-space forwarding.

2. **kTLS requires key derivation**: Go's `crypto/tls` doesn't expose symmetric keys directly. We implemented HKDF-Expand-Label to derive keys from TLS 1.3 traffic secrets.

3. **TLS 1.3 + AES-128-GCM**: Best supported combination for kTLS on modern kernels.

## Status

| Phase | Status |
|-------|--------|
| Infrastructure Setup | ✅ Complete |
| eBPF Connection Tracking | ✅ Complete |
| TLS Tunnel + kTLS | ✅ Complete |
| Traffic Forwarding | ✅ Complete |
| End-to-End Demo | ✅ Complete |

## Why This Matters

As AI agents become more autonomous and handle sensitive data, secure agent-to-agent communication becomes critical. Grimlock provides:

- **Infrastructure-level security**: No agent code changes needed
- **Consistent policy**: All A2A traffic encrypted automatically
- **Identity verification**: mTLS ensures both parties are who they claim
- **Audit capability**: Grimlock logs all inter-agent communication

## License

Apache 2.0
