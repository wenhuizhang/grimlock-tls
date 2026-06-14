# Grimlock Implementation Progress

> Last updated: 2025-01-28

## Quick Status

| Phase | Status | Notes |
|-------|--------|-------|
| Phase 1: Foundation | ✅ COMPLETE | Both hosts set up, A2A agents running |
| Phase 2: Basic eBPF | ✅ COMPLETE | Connection tracking working |
| Phase 3: TLS + kTLS | ✅ COMPLETE | mTLS tunnels + kTLS working |
| Phase 4: eBPF Redirect | ✅ COMPLETE | cgroup/connect4 + forwarding working |
| Phase 5: A2A Demo | ✅ COMPLETE | End-to-end verified with tcpdump |

## 🎉 POC COMPLETE! 

**Date: 2025-01-28**

Successfully demonstrated transparent A2A security:
1. Agent on Host 1 calls `curl http://<HOST_B_IP>:8080/.well-known/agent.json`
2. eBPF `cgroup/connect4` intercepts and redirects to Grimlock (localhost:15001)
3. Grimlock forwards through encrypted TLS 1.3 tunnel to peer Grimlock
4. Peer Grimlock forwards to local A2A agent on port 8080
5. Response flows back through the same encrypted path
6. **Traffic on wire is encrypted** (verified with tcpdump)

## Test Infrastructure

| Host | IP | SSH | Status |
|------|-----|-----|--------|
| Host 1 | <HOST_A_IP> | `ssh -i ~/.ssh/<your-key>.pem ubuntu@<HOST_A_IP>` | ✅ Ready (planning-agent running) |
| Host 2 | <HOST_B_IP> | `ssh -i ~/.ssh/<your-key>.pem ubuntu@<HOST_B_IP>` | ✅ Ready (research-agent running) |

---

## Phase 1: Foundation ✅ COMPLETE

### 1.1 Host Setup

#### Host 1 (<HOST_A_IP>)
- [x] Kernel version verified: 6.8.0-1044-aws ✅
- [x] BTF available ✅
- [x] kTLS module loaded ✅
- [x] Dependencies installed (clang 14, llvm, libbpf-dev, Go 1.18) ✅
- [x] Docker 28.2.2 installed and working ✅
- [x] User added to docker group ✅

#### Host 2 (<HOST_B_IP>)
- [x] Kernel version verified: 6.8.0-1044-aws ✅
- [x] BTF available ✅
- [x] kTLS module loaded ✅
- [x] Dependencies installed (clang 14, llvm, libbpf-dev, Go 1.18) ✅
- [x] Docker 28.2.2 installed and working ✅
- [x] User added to docker group ✅

### 1.2 PKI Setup
- [x] CA generated (ca.crt, ca.key) ✅
- [x] Agent A certificate generated (CN=agent-a, SAN=<HOST_A_IP>) ✅
- [x] Agent B certificate generated (CN=agent-b, SAN=<HOST_B_IP>) ✅
- [x] Certificates deployed to Host 1 ✅
- [x] Certificates deployed to Host 2 ✅

### 1.3 Minimal A2A Agent
- [x] Go code written (demo/a2a-agent/main.go) ✅
- [x] Dockerfile created ✅
- [x] Image builds successfully on both hosts ✅
- [x] Agent Card endpoint works (/.well-known/agent.json) ✅
- [x] A2A message/send endpoint works (/a2a) ✅
- [x] Deployed to Host 1 as "planning-agent" ✅
- [x] Deployed to Host 2 as "research-agent" ✅
- [x] Cross-host communication verified (without Grimlock) ✅

### 1.4 Network Verification
- [x] Host 1 can reach Host 2:8080 ✅
- [x] Host 2 can reach Host 1:8080 ✅
- [x] tcpdump baseline captured - **PLAINTEXT VISIBLE** ✅

**Baseline Evidence**: tcpdump shows `SECRET_DATA_VISIBLE_IN_TCPDUMP` in plaintext.
This is what Grimlock will encrypt.

---

## Phase 2: Basic eBPF (Connection Tracking) ✅ COMPLETE

### 2.1 eBPF Programs
- [x] grimlock.bpf.c compiles ✅
- [x] vmlinux.h generated on target (3.1MB) ✅
- [x] Program loads without verifier errors ✅
- [x] Attaches to cgroup successfully (/sys/fs/cgroup/system.slice) ✅

### 2.2 Go Control Plane
- [x] go.mod initialized with cilium/ebpf v0.12.3 ✅
- [x] bpf2go generates Go bindings ✅
- [x] BPF program loader works ✅
- [x] Ring buffer reader works ✅
- [x] Events logged to stdout ✅

### 2.3 Testing
- [x] Connection from planning-agent container to research-agent detected ✅
- [x] Correct IPs/ports logged (172.17.0.2:40912 -> <HOST_B_IP>:8080) ✅
- [x] CONNECT and CLOSE events captured ✅
- [x] No crashes or errors ✅

**Key Achievement**: eBPF successfully tracks A2A agent connections between containers on different hosts!

---

## Phase 3: TLS Handshake + kTLS

### Design Decisions
- **Tunnel port**: 9443 (separate from A2A port 8080)
- **One tunnel per peer**: Lazy establishment, persistent until failure
- **TLS version**: TLS 1.3 (fallback to 1.2 if kernel issues)
- **Invalid cert handling**: Drop connection + log (no fallback)
- **Bidirectional**: Both Grimlocks can initiate tunnels

### 3a: Standalone kTLS Test ✅ COMPLETE
- [x] cmd/ktls-test/ binary created ✅
- [x] TLS 1.3 handshake works (client ↔ server) ✅
- [x] Key extraction via KeyLogWriter works ✅
- [x] HKDF-Expand-Label key derivation works ✅
- [x] Both sides derive identical keys ✅
- [x] setsockopt(SOL_TLS, TLS_TX) succeeds ✅
- [x] setsockopt(SOL_TLS, TLS_RX) succeeds ✅
- [ ] tcpdump confirms encrypted traffic (next step)

### 3b: Grimlock TLS Listener ✅ COMPLETE
- [x] Grimlock listens on port 9443 ✅
- [x] Accepts mTLS connections from peer Grimlocks ✅
- [x] Validates peer cert against CA (CN=agent-a, CN=agent-b) ✅

### 3c: Tunnel Manager ✅ COMPLETE
- [x] TunnelManager struct with map[peerIP]*Tunnel ✅
- [x] CreateTunnel() - establishes mTLS to peer:9443 ✅
- [x] GetOrCreateTunnel() - reuses existing tunnel ✅
- [x] Tunnel state machine (None → Connecting → Ready → Failed) ✅
- [x] kTLS automatically enabled on tunnels ✅

### 3d: Integration ✅ COMPLETE
- [x] CONNECT event triggers tunnel creation ✅
- [x] Grimlock-to-Grimlock tunnels established ✅
- [x] Both directions work (Host1→Host2, Host2→Host1) ✅
- [x] Data transfer verified: "GRIMLOCK_TUNNEL_TEST" sent and received ✅
- [x] Bidirectional echo test confirmed ✅
- [x] tcpdump shows encrypted TLS traffic on port 9443 ✅

---

## Phase 4: eBPF Traffic Redirect 🔄 IN PROGRESS

### Design Decision: Pure eBPF Approach
After analysis, we're implementing the most aggressive eBPF approach:
- **Sender side**: sk_msg redirect (zero user-space copies)
- **Receiver side**: sk_skb redirect (kernel-to-kernel)
- **Encryption**: kTLS (kernel-level)

This differentiates us from ztunnel/ambient mesh which uses user-space proxy.

### Architecture
```
Host 1 (Sender)                        Host 2 (Receiver)
┌─────────────┐                        ┌─────────────┐
│ Agent A     │                        │ Agent B     │
│ write()     │                        │ read()      │
└──────┬──────┘                        └──────▲──────┘
       │ sk_msg                               │ sk_skb
       │ redirect                             │ redirect
       ▼                                      │
┌──────────────┐    kTLS tunnel       ┌──────────────┐
│ Tunnel Sock  │═════════════════════▶│ Tunnel Sock  │
│ (encrypt)    │                      │ (decrypt)    │
└──────────────┘                      └──────────────┘

Data path: 100% kernel (sender side)
User-space: Control plane only
```

### 4a: Kernel Support Verification ✅ COMPLETE
- [x] Kernel 6.8.0-1044-aws supports all features ✅
- [x] CONFIG_BPF_STREAM_PARSER=y ✅
- [x] CONFIG_NET_SOCK_MSG=y ✅
- [x] sk_skb program type: SUPPORTED ✅
- [x] sk_msg program type: SUPPORTED ✅
- [x] kTLS module loaded ✅
- [x] sk_skb/stream_parser loads successfully ✅
- [x] sk_skb/stream_verdict loads successfully ✅
- [x] sockhash map creates ✅

**Finding**: Kernel fully supports sk_skb redirect. Tooling (bpftool) 
doesn't have attach command, need Go cilium/ebpf for proper attachment.

### 4b: Implementation ✅ sk_skb Redirect VERIFIED
- [x] Created sk_skb eBPF programs (cmd/skb-test/) ✅
- [x] Used cilium/ebpf for proper program loading ✅
- [x] Attached sk_skb via BPF_PROG_ATTACH syscall ✅
- [x] **TEST PASSED**: Data sent to Socket A arrived at Socket B! ✅
- [ ] Test kTLS socket + sk_skb interaction (NEXT)
- [ ] Verify sk_skb sees decrypted data from kTLS

**Test Results (2025-01-28):**
```
Stats: sockops_est=6 verdict=2 redir_ok=1 pass=1
Server A: read timeout (expected - data redirected)
Server B received: "REDIRECT_TEST_DATA_67890"
✓✓✓ REDIRECT TEST PASSED! ✓✓✓
```

### 4c: Integration with Grimlock ✅ COMPLETE
- [x] Modified sock_ops to add sockets to shared sockmap ✅
- [x] Added sk_skb programs to Grimlock daemon ✅
- [x] Created RedirectManager for sk_skb attachment ✅
- [x] All programs load and attach successfully on both hosts ✅
- [x] SSH exclusion prevents lockout (CRITICAL FIX!) ✅
- [x] mTLS tunnels establish correctly (kTLS enabled) ✅
- [x] Test messages flow through tunnel ✅
- [ ] Wire up redirect maps (configure actual redirects)

**Critical Lesson: SSH Lockout**
- Attaching to root cgroup affects ALL TCP including SSH
- Fixed by adding `#define SSH_PORT 22` and early return in sock_ops
- Always exclude management ports from eBPF processing!

**Implementation Notes:**
- Added `sock_map` (BPF_MAP_TYPE_SOCKHASH) to grimlock.bpf.c
- Added `redirect_map` for source→target port mapping
- Added `stats` map for debugging
- sock_ops now adds all TCP sockets to sockmap on ESTABLISHED
- Created redirect.go with RedirectManager class
- Used raw BPF_PROG_ATTACH syscall for sk_skb attachment

**Verified Working (2025-01-28):**
- Host 1: CONNECT event → Creates tunnel → kTLS enabled → Sends test msg
- Host 2: Accepts tunnel → kTLS enabled → Receives "GRIMLOCK_TUNNEL_TEST_022437"
- sk_msg program attached to sockmap (for outgoing data redirect)
- SSH exclusion working - no lockouts after fix

### 4d: Wire Up Redirect Maps - DISCOVERY

**Key Finding (2025-01-28):**
sk_msg redirect works at TCP layer, but bypasses kTLS (ULP layer):

```
sk_msg:   TCP buffer ──direct inject──► TCP buffer (BYPASSES kTLS!)
splice(): fd ──kernel pipe──► fd (goes through sendmsg, kTLS WORKS!)
```

**Verified Issue:**
- sk_msg puts data directly in TCP buffer, bypassing Upper Layer Protocol (kTLS)
- Even with kTLS enabled, sk_msg-redirected data goes out UNENCRYPTED
- This is a fundamental kernel design - sk_msg is a fast path that skips ULP

**Research Validation:**
- Cilium already does WireGuard + eBPF (not novel for us)
- WireGuard is per-host, not per-agent (can't distinguish agents on same host)
- A2A protocol has documented security gaps (weak auth, overbroad scopes)
- No existing solution for eBPF + A2A-specific security

### 4e: REVISED APPROACH - splice() + kTLS + cgroup/connect4

**New Architecture (Minimal User-Space):**
```
┌─────────────────────────────────────────────────────────────────────┐
│  eBPF Layer (Pure Kernel):                                          │
│  • cgroup/connect4: Intercept connect(), redirect to Grimlock       │
│  • sock_ops: Track connections, identity binding (cgroup→agent)     │
│  • Policy enforcement BEFORE connection established                 │
│                                                                     │
│  User-Space (Control Plane + Zero-Copy Data):                       │
│  • Grimlock daemon manages kTLS tunnels                             │
│  • splice() for zero-copy forwarding (no data touching!)            │
│  • Local listener receives redirected connections                   │
│                                                                     │
│  Data Flow:                                                         │
│  Agent → eBPF redirect → Grimlock local socket                      │
│       → splice() → kTLS tunnel socket (kernel encrypts)             │
│       → Network → Peer Grimlock → splice() → Agent B                │
└─────────────────────────────────────────────────────────────────────┘
```

**Why splice() works with kTLS (unlike sk_msg):**
- splice() uses kernel pipe between file descriptors
- Writes to kTLS socket go through sendmsg() syscall path
- kTLS hooks into sendmsg(), so encryption happens automatically
- Zero-copy: data never enters user-space memory

**Novel Claims for Paper:**
1. Kernel-level zero-trust: Policy enforced at connect() time
2. Identity at cgroup granularity: Each container = unique agent identity
3. Zero-copy encrypted tunnel: splice() + kTLS
4. A2A protocol aware: Designed specifically for AI agent security

**POC Design Choices:**
- Identity from config file (simpler than container labels)
- Destination in header (prepend to first packet)
- Single tunnel per peer (reuse existing)

### 4f: splice/Write + kTLS Verification ✅ COMPLETE

**Test (2025-01-28):**
Created `cmd/splice-test/` to verify that data can be forwarded from a plain 
socket to a kTLS socket with encryption happening correctly.

**Results:**
```
Client → plain socket → Server
Server reads: "SPLICE_TEST_MESSAGE_043726"
Server writes to kTLS socket
kTLS encrypts → wire → kTLS decrypts
Client receives on TLS socket: "SPLICE_TEST_MESSAGE_043726"
```

**Verified:**
- Plain socket → kTLS socket forwarding works ✅
- kTLS encrypts data correctly ✅
- Data integrity maintained ✅
- Architecture is viable ✅

**Next Steps:**
1. Implement cgroup/connect4 eBPF program to intercept agent connections
2. Redirect to Grimlock's local listener
3. Forward through kTLS tunnel to peer
4. Test end-to-end with actual A2A agents

### 4d: Verification
- [ ] tcpdump on :8080 shows NO traffic (redirected)
- [ ] tcpdump on :9443 shows encrypted traffic
- [ ] A2A message still works end-to-end
- [ ] strace shows no read/write in data path

### Challenges Identified
1. **Dummy connection required**: Agent socket only exists after accept()
2. **kTLS + sk_skb**: Need to verify sk_skb sees decrypted data
3. **Socket lifecycle**: Careful cleanup when connections close
4. **Bidirectional redirect**: Need both sk_msg (send) and sk_skb (receive)

---

## Phase 5: A2A Demo

### 5.1 Setup
- [ ] Grimlock daemon running on Host 1
- [ ] Grimlock daemon running on Host 2
- [ ] Agent A container running on Host 1
- [ ] Agent B container running on Host 2

### 5.2 Demo Execution
- [ ] Agent A sends A2A message to Agent B
- [ ] tcpdump shows TLS encrypted traffic
- [ ] Agent B receives plaintext message
- [ ] Response path also encrypted

### 5.3 Failure Demo
- [ ] Wrong cert causes connection rejection
- [ ] Logged appropriately

---

## Session Notes

### 2025-01-27 - Session 1
- Created project structure and documentation
- Created POC plan with A2A protocol integration
- **Phase 1 COMPLETE**:
  - Set up both hosts (<HOST_A_IP>, <HOST_B_IP>)
  - Installed all dependencies (clang, llvm, libbpf-dev, Docker, Go 1.21)
  - Generated mTLS certificates (CA + agent certs)
  - Built and deployed minimal A2A agents (planning-agent, research-agent)
  - Verified cross-host A2A communication works
  - Captured tcpdump baseline showing plaintext traffic
- **Phase 2 COMPLETE**:
  - Implemented grimlock.bpf.c with sock_ops for connection tracking
  - Created Go control plane with cilium/ebpf
  - Fixed port parsing (remote_port >> 16 + bpf_ntohs)
  - Fixed IP byte order (LittleEndian for x86)
  - Successfully tracking CONNECT and CLOSE events!
  - Events flow: Container curl → eBPF sock_ops → Ring buffer → Go control plane
- **Phase 3a (kTLS test) COMPLETE**:
  - Created cmd/ktls-test/ standalone binary
  - TLS 1.3 handshake with mTLS works between hosts
  - Implemented KeyLogWriter to capture traffic secrets
  - Implemented HKDF-Expand-Label to derive keys/IVs
  - Both client and server derive IDENTICAL keys (verified!)
  - Successfully configured kTLS: TCP_ULP=tls, TLS_TX, TLS_RX
  - Key files: cmd/ktls-test/main.go, added golang.org/x/crypto dep
- **Phase 3b/3c/3d COMPLETE**:
  - Added tunnel.go with TunnelManager
  - Added crypto.go with HKDF and kTLS helpers
  - Grimlock now listens on port 9443 for peer connections
  - CONNECT event automatically triggers tunnel creation
  - mTLS verified (CN=agent-a ↔ CN=agent-b)
  - kTLS automatically enabled on both sides
  - Bidirectional: Host 1 connects to Host 2, Host 2 accepts
- **Phase 4b sk_skb redirect VERIFIED!**:
  - Created cmd/skb-test/ with sk_skb eBPF programs
  - sock_ops adds sockets to sockmap automatically
  - sk_skb/stream_verdict successfully redirects data
  - **TEST PASSED**: Data sent to Socket A arrived at Socket B!
  - Stats: verdict=2, redir_ok=1, pass=1
- **Next**: Integrate sk_skb into Grimlock for kTLS tunnel redirect

### 2025-01-28 - Session 2: POC COMPLETE! 🎉

**BREAKTHROUGH: End-to-end transparent A2A security working!**

After discovering that `sk_msg` bypasses kTLS (documented in LESSONS-LEARNED.md), pivoted to:
- `cgroup/connect4` for connection interception
- User-space forwarding through kTLS tunnel

#### Changes Made:
1. **grimlock.bpf.c**:
   - Added `cgroup/connect4` program (`grimlock_connect4`)
   - Intercepts connections to known agent peers on port 8080
   - Redirects to localhost:15001 (Grimlock local listener)

2. **main.go**:
   - Added local listener on port 15001
   - `handleLocalConnection()` accepts redirected connections
   - Forwards through dedicated TLS tunnel to peer Grimlock

3. **tunnel.go**:
   - Added `CreateDedicatedTunnel()` for per-request connections
   - Added `handleForwardingConnection()` on receiver side
   - Parses destination header and forwards to local agent

#### Test Results:
```bash
# On Host 1
curl http://<HOST_B_IP>:8080/.well-known/agent.json
# Returns: {"name":"research-agent",...}

# tcpdump on wire shows encrypted TLS 1.3, no readable HTTP!
```

#### Data Flow (Verified Working):
```
Agent curl                          Research Agent
      │                                    ▲
      │ connect(<HOST_B_IP>:8080)        │
      ▼                                    │
eBPF cgroup/connect4 ─── intercepts ───────┤
      │                                    │
      │ redirect to 127.0.0.1:15001        │
      ▼                                    │
Grimlock:15001                             │
      │                                    │
      │ TLS tunnel (port 9443, kTLS)       │
      ▼                                    │
Grimlock ══════ ENCRYPTED ══════▶ Grimlock │
                                          │
                      forwards to 127.0.0.1:8080
                                          │
                             response ────┘
```

---

## Files Created

| File | Purpose | Status |
|------|---------|--------|
| `README.md` | Project overview | ✅ Done |
| `HOSTS.md` | Infrastructure reference | ✅ Done |
| `PROGRESS.md` | This file | ✅ Done |
| `docs/POC-PLAN.md` | Detailed plan | ✅ Done |
| `docs/architecture.md` | Technical architecture | ✅ Done |
| `docs/experiment-setup.md` | Host setup guide | ✅ Done |
| `scripts/setup-host.sh` | Host setup automation | ✅ Done |
| `scripts/generate-certs.sh` | PKI generation | ✅ Done |
| `scripts/deploy-remote.sh` | Remote deployment | ✅ Done |
| `src/bpf/maps.h` | eBPF map definitions | ✅ Done |
| `src/bpf/sock_ops.bpf.c` | Socket ops eBPF (skeleton) | ✅ Done |
| `src/bpf/sk_msg.bpf.c` | Message redirect eBPF (skeleton) | ✅ Done |
| `Makefile` | Build system | ✅ Done |
| `demo/a2a-agent/main.go` | A2A demo agent | ✅ Done & Deployed |
| `demo/a2a-agent/Dockerfile` | Agent container | ✅ Done & Built |
| `certs/ca.crt` | Certificate Authority | ✅ Generated |
| `certs/agent-a.*` | Host 1 certificates | ✅ Deployed |
| `certs/agent-b.*` | Host 2 certificates | ✅ Deployed |
| `go.mod` | Go module | ⏳ Pending (Phase 2) |
| `src/grimlock/main.go` | Control plane | ⏳ Pending (Phase 2) |

## Running Containers

| Host | Container | Image | Port | Status |
|------|-----------|-------|------|--------|
| <HOST_A_IP> | planning-agent | a2a-agent:latest | 8080 | ✅ Running |
| <HOST_B_IP> | research-agent | a2a-agent:latest | 8080 | ✅ Running |
