# Grimlock Architecture

> Technical deep-dive into the eBPF + kTLS implementation

## High-Level Overview

Grimlock provides transparent mTLS encryption for A2A agent communication using:
- **eBPF `cgroup/connect4`**: Intercepts outgoing connections at syscall level
- **User-space daemon**: Manages TLS tunnels and certificate verification
- **kTLS**: Kernel-level TLS encryption for efficiency

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                HOST A                                        │
│                                                                              │
│   ┌─────────────┐                                                            │
│   │ Application │                                                            │
│   │  (Agent)    │                                                            │
│   └──────┬──────┘                                                            │
│          │ connect(host_b:8080)                                              │
│          ▼                                                                   │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │                         KERNEL                                        │  │
│   │  ┌────────────────────────────────────────────────────────────────┐  │  │
│   │  │                    eBPF Programs                                │  │  │
│   │  │                                                                 │  │  │
│   │  │  ┌─────────────────┐      ┌────────────────────────────────┐   │  │  │
│   │  │  │ cgroup/connect4 │      │         sock_ops               │   │  │  │
│   │  │  │                 │      │                                │   │  │  │
│   │  │  │ Intercepts      │      │ Tracks socket lifecycle        │   │  │  │
│   │  │  │ connect() calls │      │ Sends events to user-space     │   │  │  │
│   │  │  │                 │      │                                │   │  │  │
│   │  │  │ Redirects to    │      │                                │   │  │  │
│   │  │  │ localhost:15001 │      │                                │   │  │  │
│   │  │  └─────────────────┘      └────────────────────────────────┘   │  │  │
│   │  └─────────────────────────────────────────────────────────────────┘  │  │
│   └───────────────────────────────────────────────────────────────────────┘  │
│          │                                                                   │
│          │ Redirected to 127.0.0.1:15001                                    │
│          ▼                                                                   │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │                    Grimlock Daemon (User Space)                       │  │
│   │                                                                       │  │
│   │  ┌───────────────┐  ┌───────────────┐  ┌────────────────────────┐   │  │
│   │  │ Local Listener│  │ Tunnel Manager│  │ TLS + kTLS Setup      │   │  │
│   │  │ (:15001)      │  │               │  │                        │   │  │
│   │  │               │  │ Creates TLS   │  │ - mTLS handshake      │   │  │
│   │  │ Accepts       │  │ connections   │  │ - Cert verification   │   │  │
│   │  │ redirected    │  │ to peers      │  │ - HKDF key derivation │   │  │
│   │  │ connections   │  │               │  │ - setsockopt(kTLS)    │   │  │
│   │  └───────────────┘  └───────────────┘  └────────────────────────┘   │  │
│   │                            │                                          │  │
│   │                            │ TLS 1.3 tunnel (kTLS encrypts)          │  │
│   │                            ▼                                          │  │
│   │                    ┌───────────────┐                                  │  │
│   │                    │ Tunnel Socket │                                  │  │
│   │                    │ (port 9443)   │                                  │  │
│   │                    └───────────────┘                                  │  │
│   └───────────────────────────────────────────────────────────────────────┘  │
│                                │                                             │
└────────────────────────────────┼─────────────────────────────────────────────┘
                                 │
                    ═════════════════════════════
                     mTLS Encrypted (TLS 1.3)
                     AES-128-GCM via kTLS
                    ═════════════════════════════
                                 │
┌────────────────────────────────┼─────────────────────────────────────────────┐
│                                ▼                          HOST B             │
│   ┌───────────────────────────────────────────────────────────────────────┐  │
│   │                    Grimlock Daemon (User Space)                        │  │
│   │                                                                        │  │
│   │  ┌─────────────────┐  ┌────────────────────────────────────────────┐  │  │
│   │  │ Tunnel Listener │  │ Forwarding Logic                           │  │  │
│   │  │ (:9443)         │  │                                            │  │  │
│   │  │                 │  │ 1. Accept TLS connection                   │  │  │
│   │  │ Accepts mTLS    │  │ 2. Verify peer certificate                 │  │  │
│   │  │ connections     │  │ 3. Read destination header                 │  │  │
│   │  │                 │  │ 4. Connect to local agent                  │  │  │
│   │  │                 │  │ 5. Forward bidirectionally                 │  │  │
│   │  └─────────────────┘  └────────────────────────────────────────────┘  │  │
│   └───────────────────────────────────────────────────────────────────────┘  │
│          │                                                                   │
│          │ Forward to 127.0.0.1:8080                                        │
│          ▼                                                                   │
│   ┌─────────────┐                                                            │
│   │ Application │                                                            │
│   │  (Agent B)  │                                                            │
│   │  :8080      │                                                            │
│   └─────────────┘                                                            │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. eBPF Programs

#### cgroup/connect4 (`grimlock_connect4`)
- **Type**: `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`
- **Attach**: `BPF_CGROUP_INET4_CONNECT`
- **Purpose**: Intercept outgoing connections and redirect to Grimlock

```c
SEC("cgroup/connect4")
int grimlock_connect4(struct bpf_sock_addr *ctx) {
    // Check if destination is a known agent peer
    if (dst_port == AGENT_PORT && is_agent_peer(dst_ip)) {
        // Redirect to local Grimlock listener
        ctx->user_ip4 = LOCALHOST_IP;           // 127.0.0.1
        ctx->user_port = bpf_htons(15001);      // Grimlock listener
    }
    return 1;  // Allow (with modified destination)
}
```

#### sock_ops (`grimlock_sockops`)
- **Type**: `BPF_PROG_TYPE_SOCK_OPS`
- **Attach**: cgroup socket operations
- **Purpose**: Track socket lifecycle, send events to user-space

Key callbacks:
- `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` - Outgoing connection established
- `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` - Incoming connection accepted
- `BPF_SOCK_OPS_STATE_CB` - Socket state changes (for cleanup)

### 2. eBPF Maps

```
┌─────────────────────────────────────────────────────────────────┐
│                         eBPF Maps                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  agent_peers (HASH)              config_map (ARRAY)             │
│  ┌───────────────────┐           ┌───────────────────┐          │
│  │ IP → 1 (known)    │           │ 0 → {enabled, ip} │          │
│  │                   │           │                   │          │
│  │ Populated from    │           │ Global config     │          │
│  │ --peers flag      │           │                   │          │
│  └───────────────────┘           └───────────────────┘          │
│                                                                  │
│  events (RINGBUF)                stats (ARRAY)                  │
│  ┌───────────────────┐           ┌───────────────────┐          │
│  │ Connection events │           │ Counters for      │          │
│  │ → user-space      │           │ debugging         │          │
│  └───────────────────┘           └───────────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3. Grimlock Daemon (User Space - Go)

#### Components

| Component | File | Purpose |
|-----------|------|---------|
| Main | `main.go` | eBPF loading, event processing, local listener |
| Tunnel Manager | `tunnel.go` | TLS connection management, kTLS setup |
| Crypto | `crypto.go` | HKDF key derivation for kTLS |

#### Key Functions

**Local Listener (`:15001`)**
```go
func handleLocalConnection(conn net.Conn) {
    // 1. Accept redirected connection from agent
    // 2. Create dedicated TLS tunnel to peer Grimlock
    // 3. Send destination header (so peer knows where to forward)
    // 4. Bidirectional forwarding: agent ↔ tunnel
}
```

**Tunnel Listener (`:9443`)**
```go
func handleForwardingConnection(conn *tls.Conn, peerIP string) {
    // 1. Read destination header (8 bytes: IP + port)
    // 2. Connect to local agent at 127.0.0.1:port
    // 3. Bidirectional forwarding: tunnel ↔ agent
}
```

### 4. kTLS (Kernel TLS)

kTLS offloads TLS record layer to kernel after user-space handshake:

```go
// After TLS 1.3 handshake completes:

// 1. Derive symmetric keys using HKDF-Expand-Label
clientKey, clientIV := deriveTrafficKeys(clientSecret)
serverKey, serverIV := deriveTrafficKeys(serverSecret)

// 2. Configure kTLS for transmit
cryptoInfo := tls13CryptoInfo{
    Version:    TLS_1_3_VERSION,
    CipherType: TLS_CIPHER_AES_GCM_128,
    Key:        key,
    IV:         iv,
    Salt:       salt,
    RecSeq:     recordSequence,
}
syscall.SetsockoptString(fd, SOL_TLS, TLS_TX, cryptoInfo)

// 3. Configure kTLS for receive
syscall.SetsockoptString(fd, SOL_TLS, TLS_RX, cryptoInfo)
```

**Key Insight**: After kTLS is enabled, all `write()` calls on the socket are automatically encrypted by the kernel, and all `read()` calls return decrypted data.

## Data Flow

### Outgoing Request (Agent A → Agent B)

```
1. Agent A: curl http://<HOST_B_IP>:8080/a2a
       │
       ▼
2. Kernel: connect(<HOST_B_IP>, 8080) syscall
       │
       ▼
3. eBPF cgroup/connect4:
   - Is <HOST_B_IP> in agent_peers map? YES
   - Modify: connect(127.0.0.1, 15001)
       │
       ▼
4. Connection established to localhost:15001
       │
       ▼
5. Grimlock local listener accepts
   - Create TLS tunnel to <HOST_B_IP>:9443
   - TLS handshake (mTLS - verify certificates)
   - Enable kTLS on tunnel socket
   - Send destination header: [<HOST_B_IP>:8080]
       │
       ▼
6. Agent A sends HTTP request
       │
       ▼
7. Grimlock forwards through tunnel
   - kTLS encrypts in kernel
       │
       ▼
8. Encrypted data on wire to Host B:9443
```

### Incoming Request (Host B receives)

```
1. Encrypted TLS data arrives on :9443
       │
       ▼
2. Grimlock tunnel listener accepts
   - TLS handshake (verify peer certificate = agent-a)
   - Read destination header: [<HOST_B_IP>:8080]
       │
       ▼
3. Connect to local agent: 127.0.0.1:8080
       │
       ▼
4. Forward decrypted HTTP request to agent
       │
       ▼
5. Agent B processes request, sends response
       │
       ▼
6. Response flows back through tunnel (encrypted)
       │
       ▼
7. Agent A receives response (decrypted by kTLS)
```

## Protocol Format

### Destination Header (8 bytes)

Prepended to each tunneled connection:

```
┌─────────────────┬──────────────┬──────────────┐
│ Destination IP  │ Dest Port    │ Reserved     │
│ (4 bytes)       │ (2 bytes BE) │ (2 bytes)    │
└─────────────────┴──────────────┴──────────────┘
```

This tells the receiving Grimlock where to forward the connection.

## Security Model

### Certificate Management

```
┌─────────────────────────────────────────────────────────────────┐
│                    Certificate Authority (CA)                    │
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
│ CN: agent-a             │   │ CN: agent-b             │
│ SAN: <HOST_A_IP>     │   │ SAN: <HOST_B_IP>      │
│                         │   │                         │
│ agent-a.crt (public)    │   │ agent-b.crt (public)    │
│ agent-a.pem (private)   │   │ agent-b.pem (private)   │
└─────────────────────────┘   └─────────────────────────┘
```

### Identity Verification

- Both Grimlocks present certificates during TLS handshake
- Certificates validated against shared CA
- Certificate CN logged for audit trail
- Invalid certificates → connection rejected

### Trust Model

- **POC**: Pre-shared certificates with common CA
- **Future**: Could extend to SPIFFE/SPIRE for dynamic identity

## Key Technical Discoveries

### 1. sk_msg Bypasses kTLS

**Finding**: `BPF_PROG_TYPE_SK_MSG` with `bpf_msg_redirect_hash()` operates at the TCP buffer level, completely bypassing the kTLS ULP (Upper Layer Protocol) hooks.

**Impact**: Data redirected via sk_msg is sent unencrypted even if kTLS is enabled on the target socket.

**Solution**: Use `cgroup/connect4` for connection interception + user-space forwarding with standard `Write()` calls, which properly trigger kTLS encryption.

### 2. kTLS Key Derivation

Go's `crypto/tls` doesn't expose symmetric keys. We implemented TLS 1.3 HKDF-Expand-Label:

```go
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
    // TLS 1.3 key derivation
    hkdfLabel := buildHKDFLabel(label, context, length)
    return hkdf.Expand(sha256.New, secret, hkdfLabel, length)
}

func deriveTrafficKeys(trafficSecret []byte) (key, iv []byte) {
    key = hkdfExpandLabel(trafficSecret, "key", nil, 16)  // AES-128
    iv = hkdfExpandLabel(trafficSecret, "iv", nil, 12)    // GCM nonce
    return
}
```

### 3. SSH Protection Critical

eBPF programs attached to root cgroup affect ALL connections, including SSH. Always exclude port 22:

```c
// CRITICAL: Never touch SSH traffic
if (dst_port == SSH_PORT || src_port == SSH_PORT)
    return 1;  // Allow without modification
```

## Performance Considerations

| Aspect | Impact | Notes |
|--------|--------|-------|
| First connection | Higher latency | TLS handshake required |
| Subsequent data | Low overhead | kTLS in kernel |
| Memory | Moderate | eBPF maps + tunnel connections |
| CPU | Low | Hardware AES acceleration |

## Limitations (POC)

1. **IPv4 only**: No IPv6 support yet
2. **TCP only**: No UDP/QUIC

## Implemented

- **Multi-peer routing**: `connect4` records the original destination by socket
  cookie; `sock_ops` re-keys it to the agent's ephemeral source port
  (`port_dest` map); user-space resolves it on the accepted connection and routes
  to the correct peer (`origdest.go`, `channelFor`).
- **Multi-port interception**: `connect4` filters on the `agent_ports` map
  instead of a single hard-coded port, so one agent host can expose several
  services. Populated from `--agent-ports` (default `8080`); the original port
  is preserved in `orig_dest.port` and carried through to the peer-side dial.
- **Per-peer channel** (`channelFor(peer).stream`, `pool.go`): a warm pool of
  **dedicated 1:1 kTLS tunnels** — no multiplexer. The quote is amortized by
  **attestation resumption** (`tunnel.go`): the first connection full-gates and
  caches a resumption secret; subsequent ones do a cheap HMAC resume (`gate.Resume`)
  within the secret's TTL, else full-gate again. Independent connections ⇒ no
  head-of-line blocking; each splices.
- **Channel classes — fast vs. guarded, per connection** (`guard.go`,
  [channel-classes.md](channel-classes.md)): each connection is classified from its
  recovered dest port. A **fast** channel splices (kTLS zero-copy, daemon off-path)
  — for bulk. A **guarded** channel runs a userspace **enforcer pipeline** — for
  control (tool calls, payments). A **deny** channel is refused (egress chokepoint).
  Enforcement needs plaintext, so guarded ⇒ no splice is fundamental; routing each
  channel to its lane lets both coexist instead of the old daemon-global either/or.
  `--guard 8080:mcp,x402` composes both enforcers on one channel — a request
  forwards only if every enforcer permits it (the model's `⊢ Forward`).
- **Wire-level MCP capability enforcement** (`mcp.go`): as a guarded-pipeline
  member it parses the agent's MCP/JSON-RPC and blocks any `tools/call` for a tool
  not in the peer's **attested** manifest, or whose capability exceeds the grant —
  out-of-agent, on the unbypassable path. Handles JSON-RPC batches and fails closed
  on unparseable bodies. The gate binds the manifest digest; the wire enforces each
  call against it, so capability governance trusts neither endpoint's SDK. Uses the
  same `capCovers` lattice the Coq proofs (`covered_*`) are about.
- **x402 payment enforcement** (`payment.go`): the other pipeline member — blocks
  out-of-policy payments and binds each allowed one to a TDX quote (session EKM +
  epoch). Its `paymentConn` owns the response direction too (402/settlement sniff).
- **Process hardening** (`hardening.go`, `seccomp.go`): `no_new_privs`,
  **non-dumpable** (a co-located hijacked neighbor cannot ptrace / read
  `/proc/<pid>/mem` to steal kTLS or resumption secrets, and no core dump leaks
  them), and an opt-in **seccomp deny-list** (`--seccomp`) blocking dangerous
  syscalls (ptrace, `process_vm_*`, module load, mount, namespace ops) — verified
  to actually block `ptrace`. Full allow-list separation is designed in
  [privilege-separation.md](privilege-separation.md).
- **Robustness / anti-DoS** (`tunnel.go`): inbound setups are concurrency-capped
  and **load-shed** past `maxConcurrentSetups`, and every setup (dial, TLS
  handshake, gate/resume, header) is **deadline-bound** so a stalled/slowloris
  peer can't wedge a goroutine; the data phase is unbounded. A per-peer **circuit
  breaker** (`pool.go`) suppresses reconnect storms to a down peer. Concurrent
  tunnel establishes use a **per-tunnel keyLog** (a shared one would corrupt kTLS
  key derivation under warm-pool concurrency).
- **Observability** (`metrics.go`): lock-free counters (full gates, resumes,
  attest failures, load-shed, requests/bytes forwarded, payments allowed/blocked)
  exposed via expvar at `/debug/vars` when `--metrics-addr` is set.
- **Validated on a real kernel** (no TDX — see [validation.md](validation.md)):
  eBPF verifier load + `connect4`/`sock_ops` attach, the connect4 **redirect**
  (a dial to an unreachable peer lands on the local proxy), **kTLS engaged**
  (kernel crypto), and **`splice()` zero-copy** (strace-confirmed). The full
  datapath runs end-to-end (CA mode + warm-pool concurrency), and the attested
  **resumption** protocol (full-gate → cache → cheap resume, same epoch) runs over
  **real kTLS** — only the quote content is stubbed (that alone needs a TD).

## Formal & design references

- [model.md](model.md) — the authorization model · [semantics-categorical.md](semantics-categorical.md) — categorical semantics
- [threat-model.md](threat-model.md) · [multi-hop.md](multi-hop.md) · [privilege-separation.md](privilege-separation.md)
- [`../formal/`](../formal/) — machine-checked (Coq) capability + transcript proofs

## Future Enhancements

1. **SPIFFE integration**: Dynamic identity with workload attestation
2. **Policy engine**: Allow/deny rules based on agent identity
3. **Metrics/Observability**: expvar counters shipped (`--metrics-addr`); a
   Prometheus exporter + distributed tracing would extend it
4. **Per-source-IP rate limiting** on gate setups (complements the load-shed cap)
