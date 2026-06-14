# Grimlock POC Plan: Zero-Trust Security for AI Agent Communication

## Executive Summary

**Goal**: Demonstrate that eBPF + kTLS can provide **transparent mTLS** for AI agent-to-agent (A2A) communication, requiring zero code changes to the agents.

**The AI Agent Security Problem**:
- AI agents are proliferating (planning agents, coding agents, research agents, etc.)
- These agents need to communicate securely with each other
- The A2A protocol (Google, 2025) standardizes agent communication but leaves security to developers
- Most AI developers focus on prompts and tools, not TLS configuration

**Our Solution**: Infrastructure-level security for AI agents
1. Agents write plain HTTP code — no TLS libraries needed
2. eBPF intercepts connections to known agent peers
3. Control plane verifies identity via mTLS certificates
4. kTLS encrypts all traffic in the kernel
5. Agents never know encryption happened — it's invisible to them

**Why This Matters**: As AI agents become more autonomous and handle sensitive data, secure agent-to-agent communication becomes critical infrastructure — not an afterthought.

---

## Background: A2A Protocol & Security

### What is A2A?

Google's Agent2Agent (A2A) Protocol (announced April 2025) enables AI agents to:
- Discover each other's capabilities (via "Agent Cards")
- Exchange tasks and messages (JSON-RPC 2.0 over HTTP)
- Collaborate without sharing internal state

### A2A Security Model

From the A2A specification:
> "A2A treats agents as standard enterprise applications, relying on established web security practices. Identity information is not transmitted within A2A JSON-RPC payloads; it is handled at the HTTP **transport layer**."

A2A explicitly supports:
- TLS 1.2+ for transport security
- mTLS for mutual authentication
- Certificate validation against trusted CAs

**Key Insight**: A2A expects security at the transport layer, but **agents must implement it themselves**. Our solution provides this transparently.

---

## Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              HOST 1 (<HOST_A_IP>)                        │
│                                                                             │
│   ┌─────────────────────────────────────────┐                               │
│   │         Container: Agent A              │                               │
│   │  ┌───────────────────────────────────┐  │                               │
│   │  │   A2A Agent (Python/Go/etc)       │  │                               │
│   │  │   - Speaks plain HTTP             │  │                               │
│   │  │   - No TLS code                   │  │                               │
│   │  │   - connect(host2:8080)           │  │                               │
│   │  └───────────────┬───────────────────┘  │                               │
│   └──────────────────┼──────────────────────┘                               │
│                      │ Plain HTTP request                                   │
│                      ▼                                                      │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │                     Grimlock eBPF Layer                              │  │
│   │  ┌────────────────┐  ┌─────────────────┐  ┌──────────────────────┐  │  │
│   │  │   sock_ops     │  │    sk_msg       │  │   Control Plane      │  │  │
│   │  │  (intercept    │  │  (redirect to   │  │  (TLS handshake,     │  │  │
│   │  │   connect)     │  │   kTLS socket)  │  │   cert management)   │  │  │
│   │  └────────────────┘  └─────────────────┘  └──────────────────────┘  │  │
│   │                              │                                       │  │
│   │                              ▼                                       │  │
│   │                    ┌─────────────────┐                               │  │
│   │                    │  kTLS Socket    │                               │  │
│   │                    │ (kernel encrypt)│                               │  │
│   │                    └────────┬────────┘                               │  │
│   └─────────────────────────────┼────────────────────────────────────────┘  │
│                                 │                                           │
└─────────────────────────────────┼───────────────────────────────────────────┘
                                  │
                                  │  ═══════════════════════════════
                                  │   mTLS Encrypted (TLS 1.3)
                                  │   - Agent A's cert presented
                                  │   - Agent B's cert verified
                                  │  ═══════════════════════════════
                                  │
┌─────────────────────────────────┼───────────────────────────────────────────┐
│                                 │            HOST 2 (<HOST_B_IP>)         │
│                                 ▼                                           │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                     Grimlock eBPF Layer                             │   │
│   │                    ┌─────────────────┐                              │   │
│   │                    │  kTLS Socket    │                              │   │
│   │                    │ (kernel decrypt)│                              │   │
│   │                    └────────┬────────┘                              │   │
│   │                             │                                       │   │
│   │  ┌────────────────┐  ┌──────┴──────────┐  ┌──────────────────────┐ │   │
│   │  │   sock_ops     │  │    sk_msg       │  │   Control Plane      │ │   │
│   │  │  (intercept    │  │  (redirect from │  │  (verify Agent A's   │ │   │
│   │  │   accept)      │  │   kTLS socket)  │  │   certificate)       │ │   │
│   │  └────────────────┘  └─────────────────┘  └──────────────────────┘ │   │
│   └──────────────────────────────┬──────────────────────────────────────┘   │
│                                  │ Plain HTTP delivered                     │
│                                  ▼                                          │
│   ┌──────────────────────────────────────────┐                              │
│   │         Container: Agent B               │                              │
│   │  ┌────────────────────────────────────┐  │                              │
│   │  │   A2A Agent (Python/Go/etc)        │  │                              │
│   │  │   - Listens on plain HTTP :8080    │  │                              │
│   │  │   - Receives request normally      │  │                              │
│   │  │   - No TLS code needed             │  │                              │
│   │  └────────────────────────────────────┘  │                              │
│   └──────────────────────────────────────────┘                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Breakdown

### 1. eBPF Programs (Kernel Space)

| Program | Type | Purpose |
|---------|------|---------|
| `sock_ops.bpf.c` | BPF_PROG_TYPE_SOCK_OPS | Intercept connect/accept, add sockets to sockmap |
| `sk_msg.bpf.c` | BPF_PROG_TYPE_SK_MSG | Redirect data to/from kTLS sockets |

### 2. Control Plane (User Space - Go)

| Component | Purpose |
|-----------|---------|
| `bpf_loader.go` | Load eBPF programs, manage maps |
| `tls_handshake.go` | Perform mTLS handshake with peer agents |
| `ktls_setup.go` | Configure kTLS sockets with negotiated keys |
| `identity.go` | Certificate management, identity verification |
| `config.go` | Configuration (peer IPs, cert paths, etc.) |

### 3. Infrastructure

| Component | Purpose |
|-----------|---------|
| CA + Certificates | Pre-shared PKI for agent identity |
| Docker containers | Simulated A2A agents |
| Test harness | Validation scripts |

---

## Identity Verification Strategy

### For POC: Pre-Shared Certificate PKI

```
┌─────────────────────────────────────────────────────────────────┐
│                    Certificate Authority (CA)                    │
│                      (Generated offline)                         │
│                                                                  │
│                         ca.crt (public)                          │
│                         ca.key (private, secured)                │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
┌─────────────────────────┐   ┌─────────────────────────┐
│   Agent A Certificate   │   │   Agent B Certificate   │
│                         │   │                         │
│ CN: agent-a.grimlock    │   │ CN: agent-b.grimlock    │
│ SAN: <HOST_A_IP>     │   │ SAN: <HOST_B_IP>      │
│                         │   │                         │
│ agent-a.crt (public)    │   │ agent-b.crt (public)    │
│ agent-a.key (private)   │   │ agent-b.key (private)   │
└─────────────────────────┘   └─────────────────────────┘
```

### Verification Flow

1. **Agent A connects to Agent B**
2. Grimlock on Host 1 detects connection to known peer (<HOST_B_IP>)
3. Control plane initiates TLS handshake with Grimlock on Host 2
4. Both sides present certificates, verify against shared CA
5. If valid → establish kTLS tunnel
6. If invalid → reject connection (agent never knows why)

---

## Phased Implementation Plan

### Phase 1: Foundation (Infrastructure + Containers)
**Goal**: Both hosts ready with Docker and eBPF development environment

**Host Setup**:
- [ ] Set up Host 1 (<HOST_A_IP>)
  - Install dependencies (clang, llvm, libbpf-dev, Go 1.21+)
  - Install Docker
  - Load kTLS module (`modprobe tls`)
  - Verify eBPF capabilities (BTF, cgroup2)
- [ ] Set up Host 2 (<HOST_B_IP>)
  - Same as Host 1

**PKI Setup**:
- [ ] Generate Certificate Authority
  - `ca.crt` (distributed to both hosts)
  - `ca.key` (kept secure)
- [ ] Generate Agent A certificate
  - CN: `agent-a.grimlock`
  - SAN: `<HOST_A_IP>`
- [ ] Generate Agent B certificate
  - CN: `agent-b.grimlock`
  - SAN: `<HOST_B_IP>`
- [ ] Deploy certificates to hosts

**Minimal A2A Agent Container**:
- [ ] Create simple A2A-compatible agent (Go)
  - `GET /.well-known/agent.json` — returns Agent Card
  - `POST /a2a` — handles `message/send` JSON-RPC
  - Plain HTTP only (no TLS code)
  - Logs all received messages
- [ ] Build Docker image
- [ ] Test: Verify agent responds on both hosts (without Grimlock yet)

**Network Verification**:
- [ ] Verify hosts can reach each other on port 8080
- [ ] Verify containers can reach external hosts
- [ ] Baseline: Capture unencrypted traffic with tcpdump

### Phase 2: Basic eBPF (Connection Tracking)
**Goal**: eBPF can intercept and track connections between agent containers

- [ ] Implement `sock_ops.bpf.c`
  - Track connections to/from peer agent IP
  - Add sockets to sockmap
  - Send events to user-space (ring buffer)
  - Filter: Only track port 8080 (A2A traffic)
- [ ] Implement Go control plane skeleton
  - Load eBPF programs
  - Attach to root cgroup (covers all containers)
  - Read events from ring buffer
  - Log: "Agent A connecting to Agent B"
- [ ] Test: Container A curls Container B, see eBPF logs

### Phase 3: TLS Handshake + kTLS (Standalone)
**Goal**: Control plane can establish mTLS tunnel between hosts

- [ ] Implement TLS handshake in Go (`tls_handshake.go`)
  - Use `crypto/tls` with `tls.RequireAndVerifyClientCert`
  - Load agent certificates and CA
  - On success: log verified peer identity
  - On failure: log and reject (no fallback)
- [ ] Implement kTLS setup (`ktls_setup.go`)
  - Extract symmetric keys from `tls.Conn`
  - Call `setsockopt(SOL_TLS, TLS_TX, ...)` with AES-GCM keys
  - Call `setsockopt(SOL_TLS, TLS_RX, ...)` for receive
- [ ] Test (standalone, no eBPF redirect yet):
  - Grimlock on Host 1 connects to Grimlock on Host 2
  - Handshake succeeds, kTLS socket established
  - Send test data, verify encryption with tcpdump
  - Try with invalid cert — verify rejection + logging

### Phase 4: eBPF Redirect (The Integration)
**Goal**: Transparently redirect agent traffic through kTLS tunnel

- [ ] Implement `sk_msg.bpf.c`
  - Look up connection in map
  - If `use_ktls == true`, redirect to kTLS socket
  - Track bytes sent/received for metrics
- [ ] Update control plane
  - When eBPF signals new connection to peer agent:
    1. Check if kTLS tunnel exists to that peer
    2. If not: establish tunnel (Phase 3 code)
    3. Update eBPF maps: mark connection for redirect
  - Handle tunnel failures gracefully (log, drop connection)
- [ ] Update eBPF maps interface
  - Go code updates `conn_map` to enable redirect
  - Go code adds kTLS socket to `ktls_sock_map`
- [ ] Test:
  - Container A sends HTTP request to Container B
  - Traffic intercepted, routed through kTLS
  - Container B receives plain HTTP
  - tcpdump shows TLS on wire

### Phase 5: A2A Demo (The Payoff)
**Goal**: End-to-end demonstration of secure AI agent communication

**Demo Setup**:
- [ ] Deploy Grimlock daemon on both hosts
- [ ] Start Agent A container on Host 1
- [ ] Start Agent B container on Host 2
- [ ] Grimlock auto-discovers peer via configuration

**Demo Script**:
- [ ] Agent A sends A2A `message/send` to Agent B
  - "Summarize this document for me"
- [ ] Capture with tcpdump — show TLS records (not plaintext)
- [ ] Agent B logs received message — plaintext visible
- [ ] Agent B responds — same encryption path back

**Failure Demo**:
- [ ] Revoke Agent A's certificate (or use wrong cert)
- [ ] Agent A tries to send message
- [ ] Connection rejected, logged by Grimlock
- [ ] Agent A sees connection refused

**Metrics Demo** (stretch goal):
- [ ] Show bytes encrypted/decrypted
- [ ] Show successful/failed handshakes
- [ ] Show active tunnels

---

## Demo Scenario (Phase 5)

### The Story

> *"Imagine you're building a multi-agent AI system. You have a Planning Agent that coordinates work, and a Research Agent that gathers information. These agents need to communicate — but you don't want to add TLS code to every agent. Grimlock makes security invisible."*

### Setup
```
Host 1 (<HOST_A_IP>)                Host 2 (<HOST_B_IP>)
┌──────────────────────────────┐       ┌──────────────────────────────┐
│                              │       │                              │
│  ┌────────────────────────┐  │       │  ┌────────────────────────┐  │
│  │  grimlock-agent        │  │       │  │  grimlock-agent        │  │
│  │  (control plane)       │  │       │  │  (control plane)       │  │
│  │  - loads eBPF          │  │       │  │  - loads eBPF          │  │
│  │  - manages kTLS        │  │       │  │  - manages kTLS        │  │
│  │  - verifies certs      │  │       │  │  - verifies certs      │  │
│  └────────────────────────┘  │       └────────────────────────────┘  │
│                              │       │                              │
│  ┌────────────────────────┐  │       │  ┌────────────────────────┐  │
│  │  Container:            │  │       │  │  Container:            │  │
│  │  planning-agent        │  │  TLS  │  │  research-agent        │  │
│  │                        │  │ ════> │  │                        │  │
│  │  "Research topic X"    │──┼───────┼──│  Receives request      │  │
│  │                        │  │       │  │  "Here's what I found" │  │
│  │  HTTP :8080 (no TLS!)  │  │       │  │  HTTP :8080 (no TLS!)  │  │
│  └────────────────────────┘  │       │  └────────────────────────┘  │
│                              │       │                              │
└──────────────────────────────┘       └──────────────────────────────┘
```

### Demo Script

```bash
# === STEP 1: Show the agents are plain HTTP ===

# On Host 2: Research Agent is listening
$ docker logs research-agent
2025-01-26 10:00:00 INFO  Starting A2A Agent: research-agent
2025-01-26 10:00:00 INFO  Agent Card: http://0.0.0.0:8080/.well-known/agent.json
2025-01-26 10:00:00 INFO  A2A Endpoint: http://0.0.0.0:8080/a2a
2025-01-26 10:00:00 INFO  NOTE: Running plain HTTP (no TLS configured)

# === STEP 2: Start packet capture ===

# On Host 2: Watch the wire
$ sudo tcpdump -i eth0 -A 'host <HOST_A_IP> and port 8080' -w capture.pcap &

# === STEP 3: Agent A sends a task to Agent B ===

# On Host 1: Planning Agent sends a research request
$ docker exec planning-agent /bin/sh -c '
  curl -s -X POST http://<HOST_B_IP>:8080/a2a \
    -H "Content-Type: application/json" \
    -d "{
      \"jsonrpc\": \"2.0\",
      \"method\": \"message/send\",
      \"params\": {
        \"message\": {
          \"role\": \"user\",
          \"parts\": [{
            \"kind\": \"text\",
            \"text\": \"Research the latest developments in quantum computing\"
          }]
        }
      },
      \"id\": 1
    }"
'

# Response from Research Agent:
{
  "jsonrpc": "2.0",
  "result": {
    "status": {"state": "completed"},
    "artifacts": [{
      "parts": [{"kind": "text", "text": "Here are the latest developments..."}]
    }]
  },
  "id": 1
}

# === STEP 4: Verify encryption ===

# On Host 2: Analyze the capture
$ tcpdump -r capture.pcap -A | head -50
# OUTPUT: TLS handshake, then encrypted application data
# You'll see: "...TLSv1.3...Application Data..."
# You will NOT see: "quantum computing" or "jsonrpc"

# === STEP 5: Check Grimlock logs ===

$ journalctl -u grimlock -f
2025-01-26 10:00:05 INFO  New connection: <HOST_A_IP> -> <HOST_B_IP>:8080
2025-01-26 10:00:05 INFO  Peer identity verified: agent-a.grimlock (CN)
2025-01-26 10:00:05 INFO  kTLS tunnel established (TLS 1.3, AES-128-GCM)
2025-01-26 10:00:05 INFO  Redirecting traffic through encrypted tunnel
2025-01-26 10:00:05 INFO  Request: 847 bytes encrypted, 523 bytes response

# === STEP 6: Demonstrate identity enforcement ===

# Temporarily use wrong certificate on Host 1
$ grimlock config set cert /tmp/wrong-agent.crt

# Try to send message again
$ docker exec planning-agent curl -s http://<HOST_B_IP>:8080/a2a ...
# ERROR: Connection refused (or timeout)

$ journalctl -u grimlock -f
2025-01-26 10:01:00 WARN  TLS handshake failed: certificate verify failed
2025-01-26 10:01:00 WARN  Peer certificate CN "unknown-agent" not in allowed list
2025-01-26 10:01:00 INFO  Connection dropped (identity verification failed)

# Restore correct certificate
$ grimlock config set cert /etc/grimlock/agent-a.crt
```

### Success Criteria

| Criteria | Verification |
|----------|--------------|
| Agents use plain HTTP code | Inspect agent source — no TLS imports |
| Wire traffic is encrypted | tcpdump shows TLS, not plaintext JSON |
| Mutual authentication works | Both agents verify each other's certs |
| Invalid cert = rejected | Connection fails with wrong cert |
| Agents unaware of encryption | Agent logs show normal HTTP handling |

### What Makes This Compelling

1. **Zero Code Changes**: Neither agent has any TLS code
2. **A2A Compatible**: Standard A2A protocol, just secured transparently
3. **Mutual Verification**: Both sides prove identity
4. **Fail Secure**: Bad cert = no connection (not degraded security)
5. **Observable**: Grimlock logs show what's happening

---

## Technical Decisions

### Language: Go

**Rationale**:
- `cilium/ebpf` is mature and well-documented
- Go's `crypto/tls` has good mTLS support
- Fast iteration for POC
- Same language as many A2A implementations

### Container Runtime: Docker

**Rationale**:
- Simple and widely available
- cgroup integration for eBPF attachment
- Easy networking for demo

### TLS Version: TLS 1.3 (fallback to 1.2)

**Rationale**:
- kTLS supports TLS 1.2 and 1.3
- TLS 1.3 is simpler (fewer cipher suites)
- May need 1.2 depending on kernel version

### Cipher Suite: AES-128-GCM

**Rationale**:
- Well-supported by kTLS
- Good performance (hardware acceleration)
- Sufficient for POC

---

## Risk & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| kTLS setup complexity | Medium | High | Start with Phase 3 standalone test |
| eBPF verifier rejection | Medium | Medium | Keep programs simple, test incrementally |
| Kernel version issues | Low | High | Both hosts have 6.8 kernel (verified) |
| Sockmap redirect limitations | Medium | High | Have fallback to user-space proxy |
| Container networking complexity | Medium | Medium | Start without containers, add later |

---

## File Structure

```
ai-grimlock/
├── README.md                      # Project overview (AI agent security focus)
├── HOSTS.md                       # Test infrastructure reference
├── Makefile                       # Build system
├── go.mod                         # Go module definition
├── go.sum                         # Go dependencies
│
├── docs/
│   ├── POC-PLAN.md               # This document
│   ├── architecture.md           # Technical deep-dive
│   └── experiment-setup.md       # Host setup guide
│
├── scripts/
│   ├── setup-host.sh             # Automated host setup
│   ├── generate-certs.sh         # PKI generation
│   ├── deploy-remote.sh          # Deploy to test hosts
│   └── run-demo.sh               # End-to-end demo script
│
├── certs/                         # Generated certificates (gitignored)
│   ├── ca.crt                    # Certificate Authority
│   ├── agent-a.crt               # Host 1 agent cert
│   ├── agent-a.key               # Host 1 agent key
│   ├── agent-b.crt               # Host 2 agent cert
│   └── agent-b.key               # Host 2 agent key
│
├── src/
│   ├── bpf/                      # eBPF programs (C)
│   │   ├── sock_ops.bpf.c        # Socket operations interception
│   │   ├── sk_msg.bpf.c          # Message redirection
│   │   ├── maps.h                # Shared map definitions
│   │   └── vmlinux.h             # Generated on target system
│   │
│   └── grimlock/                 # Control plane (Go)
│       ├── main.go               # Entry point
│       ├── cmd/
│       │   └── root.go           # CLI commands
│       ├── internal/
│       │   ├── bpf/
│       │   │   ├── loader.go     # eBPF program loader
│       │   │   └── maps.go       # Map management
│       │   ├── tls/
│       │   │   ├── handshake.go  # mTLS handshake
│       │   │   └── ktls.go       # kTLS socket setup
│       │   ├── identity/
│       │   │   ├── certs.go      # Certificate management
│       │   │   └── verify.go     # Identity verification
│       │   └── config/
│       │       └── config.go     # Configuration handling
│       └── pkg/
│           └── a2a/
│               └── types.go      # A2A protocol types
│
├── demo/
│   ├── a2a-agent/                # Minimal A2A agent for demo
│   │   ├── Dockerfile
│   │   ├── main.go               # Simple A2A server
│   │   └── agent_card.json       # Agent Card template
│   │
│   ├── docker-compose.yml        # Local multi-container setup
│   ├── docker-compose.host1.yml  # Host 1 deployment
│   └── docker-compose.host2.yml  # Host 2 deployment
│
└── tests/
    ├── integration/
    │   ├── tunnel_test.go        # kTLS tunnel tests
    │   └── a2a_test.go           # A2A communication tests
    └── e2e/
        └── demo_test.sh          # End-to-end validation
```

---

## Next Steps (Immediate)

### Step 1: Set Up Both Hosts
```bash
# SSH to each host and run setup
ssh -i ~/.ssh/<your-key>.pem ubuntu@<HOST_A_IP>
ssh -i ~/.ssh/<your-key>.pem ubuntu@<HOST_B_IP>

# On each host:
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libelf-dev \
    linux-headers-$(uname -r) pkg-config golang-go docker.io
sudo modprobe tls
sudo usermod -aG docker ubuntu
```

### Step 2: Generate and Deploy Certificates
```bash
# On local machine
./scripts/generate-certs.sh \
    --agent agent-a --ip <HOST_A_IP> \
    --agent agent-b --ip <HOST_B_IP>

# Deploy
scp -i ~/.ssh/<your-key>.pem certs/ca.crt certs/agent-a.* ubuntu@<HOST_A_IP>:~/
scp -i ~/.ssh/<your-key>.pem certs/ca.crt certs/agent-b.* ubuntu@<HOST_B_IP>:~/
```

### Step 3: Build and Test Minimal A2A Agent
```bash
# Build the demo agent image
cd demo/a2a-agent
docker build -t a2a-agent .

# Test locally
docker run -p 8080:8080 a2a-agent
curl http://localhost:8080/.well-known/agent.json
```

### Step 4: Begin Phase 2 - Basic eBPF
Start with the sock_ops program that just logs connections.

---

## Why This Matters for AI Agents

### The Multi-Agent Future

We're moving toward a world where:
- AI agents handle increasingly sensitive tasks (code, data, decisions)
- Agents from different vendors need to collaborate (A2A enables this)
- Agents operate autonomously without human oversight of every call
- A single compromised agent could access others' data

### Current Security Gap

The A2A protocol defines **what** agents communicate, but security is left to:
- Each agent developer to implement TLS
- Each deployment to manage certificates
- Each organization to audit every agent's security

This doesn't scale. Most AI developers aren't security engineers.

### Our Approach: Infrastructure-Level Security

Just as:
- Kubernetes provides networking without apps knowing
- Service meshes provide mTLS for microservices
- VPNs encrypt all traffic transparently

Grimlock provides:
- **mTLS for AI agents without agent code changes**
- **Centralized certificate management**
- **Consistent security policy across all agents**
- **Audit trail of agent-to-agent communication**

### Future Vision

This POC is step one. The full vision includes:
- **Agent identity based on SPIFFE** (not just certificates)
- **Policy engine** (which agents can talk to which)
- **Observability** (who talked to whom, when, what)
- **Integration with agent orchestrators** (AutoGPT, CrewAI, etc.)

---

## References

- [A2A Protocol Specification](https://google.github.io/A2A/specification/)
- [A2A Security Best Practices](https://developers.redhat.com/articles/2025/08/19/how-enhance-agent2agent-security)
- [Kernel TLS Documentation](https://www.kernel.org/doc/html/latest/networking/tls.html)
- [cilium/ebpf Go Library](https://github.com/cilium/ebpf)
- [libbpf-bootstrap Examples](https://github.com/libbpf/libbpf-bootstrap)
- [SPIFFE - Secure Production Identity Framework](https://spiffe.io/)
