# Grimlock: Lessons Learned

> Living document capturing technical insights from building eBPF-based mTLS tunneling

---

## 🚨 CRITICAL: Root Cgroup Lockout (2025-01-28)

### What Happened
We attached sock_ops and sk_skb programs to the **root cgroup** (`/sys/fs/cgroup`) on remote AWS hosts. This caused ALL TCP connections to go through our eBPF programs - **including SSH**. When the programs had issues, we were locked out of both hosts.

### The Mistake
```bash
# DANGEROUS: Attaches to ALL processes on the system
sudo ./grimlock --cgroup=/sys/fs/cgroup
```

### Recovery
- Had to reboot both AWS Lightsail instances via console
- eBPF programs are not persistent across reboots

### Prevention (MUST DO)

1. **Exclude SSH port in eBPF code:**
```c
#define SSH_PORT 22

// In sock_ops handler - skip SSH traffic
if (src_port == SSH_PORT || dst_port == SSH_PORT)
    return 0;
```

2. **Use container-specific cgroup instead of root:**
```bash
# SAFER: Only affects Docker containers
--cgroup=/sys/fs/cgroup/system.slice/docker.service
```

3. **Test locally in VM first** before deploying to remote hosts

4. **Have console access ready** (AWS Console, Lightsail SSH button) before testing

### Key Insight
> eBPF attached to root cgroup = affects EVERYTHING including your SSH session.
> Always exclude management ports or use scoped cgroups.

---

## 🔬 sk_msg Bypasses kTLS (ULP) - Critical Finding (2025-01-28)

### What We Discovered

sk_msg redirect operates at TCP buffer level, **BELOW** the kTLS Upper Layer Protocol.
Even with kTLS enabled on a socket, sk_msg-injected data bypasses encryption.

```
Layer Stack:
─────────────────────────────────
Application    │  tls.Conn.Write()
───────────────┼─────────────────
kTLS (ULP)     │  Encryption happens HERE (via sendmsg syscall)
───────────────┼─────────────────
TCP Socket     │  ← sk_msg operates HERE (direct buffer injection)
───────────────┼─────────────────
Network        │  Data sent (UNENCRYPTED if via sk_msg!)
─────────────────────────────────
```

### Verified Behavior

With kTLS enabled on tunnel socket:
1. Agent writes HTTP to plain socket
2. sock_ops adds both sockets to sockmap
3. redirect_map configured: agent_port → tunnel_port
4. Agent write triggers sk_msg
5. sk_msg redirects data to tunnel's TCP buffer (bypassing kTLS!)
6. Raw HTTP bytes go on wire
7. Peer receives: "tls: received record with version 5454" (HTTP bytes, not TLS)

### Why This Happens (Kernel Design)

From kernel documentation:
> "Sockmap code checks that sockets don't have an active ULP before insertion"

sk_msg/sockmap is designed as a **fast path** that bypasses normal socket processing.
This is intentional for performance, but means ULP (like kTLS) is skipped.

### The Solution: splice() Instead of sk_msg

`splice()` is a different mechanism that DOES work with kTLS:

```
sk_msg:   TCP buffer ──direct inject──► TCP buffer (BYPASSES kTLS)
splice(): fd ──kernel pipe──► fd (uses sendmsg syscall, kTLS encrypts!)
```

splice() works because:
- It uses the normal sendmsg() path
- kTLS hooks into sendmsg()
- Data is still zero-copy (kernel pipe, no user-space memory)

### Research Validation

Web search confirmed:
- Cilium's WireGuard + eBPF is per-host, not per-agent (different use case)
- No existing solution for eBPF + A2A-specific agent security
- A2A protocol has documented security gaps (arxiv:2505.12490)

### New Architecture

```
Agent → cgroup/connect4 redirect → Grimlock local socket
     → Write() → kTLS tunnel (kernel encrypts)
     → Network → Peer Grimlock → Read() → Agent B
```

Key insight: Use eBPF for interception/policy, kTLS for encrypted data path.

### Verification Test (2025-01-28)

Created `cmd/splice-test/` to verify plain socket → kTLS socket forwarding:

```
Test Results:
─────────────────────────────────────────────────────
1. Server listens on :9443 (TLS/kTLS) and :15001 (plain)
2. Client connects to both
3. Client sends through plain socket: "SPLICE_TEST_MESSAGE"
4. Server reads from plain, writes to kTLS socket
5. Client receives on TLS socket: "SPLICE_TEST_MESSAGE"
─────────────────────────────────────────────────────
Result: ✅ SUCCESS - kTLS encryption works with forwarding
```

This proves the architecture is viable. Unlike sk_msg (which bypasses kTLS),
regular socket Write() goes through the sendmsg() path where kTLS hooks in.

---

## 🔬 TLS Session Isolation (Earlier Finding)

Before discovering the kTLS bypass, we also noted TLS session isolation:

When redirecting between sockets with different TLS sessions (user-space TLS),
data encrypted with Session A's keys can't be decrypted by Session B.

This is a separate issue from the kTLS bypass, but both point to the same solution:
Agent must connect to Grimlock locally (plaintext), then Grimlock handles encryption.

### The Fix That Worked

Added SSH exclusion in grimlock.bpf.c:

```c
#define SSH_PORT 22

// In sock_ops handler - FIRST thing after extracting ports:
if (src_port == SSH_PORT || dst_port == SSH_PORT)
    return 0;

// In sk_skb verdict - safety check:
if (src_port == SSH_PORT || remote_port == SSH_PORT)
    return SK_PASS;
```

After this fix, Grimlock runs safely on the root cgroup without affecting SSH.

---

## Phase 4b: sk_skb Redirect (2025-01-28)

### Lesson 1: eBPF Tooling vs Kernel Support

**Problem**: Initial tests suggested sk_skb might not work, leading to concern about the approach.

**Root Cause**: Tooling limitations, NOT kernel limitations.

| Tool | Issue |
|------|-------|
| `bpftool` | Has no command to attach sk_skb to sockmap |
| Python direct syscalls | `os.open()` on pinned BPF objects fails with I/O error |
| Go `link.AttachRawLink` | Returns "invalid argument" for sk_skb |

**Solution**: Use raw `BPF_PROG_ATTACH` syscall directly in Go:

```go
func attachSkSkb(mapFD, progFD int, attachType ebpf.AttachType) error {
    const SYS_BPF = 321  // x86_64
    const BPF_PROG_ATTACH = 8
    
    attr := struct {
        targetFD    uint32
        attachBpfFD uint32
        attachType  uint32
        attachFlags uint32
    }{
        targetFD:    uint32(mapFD),
        attachBpfFD: uint32(progFD),
        attachType:  uint32(attachType),
        attachFlags: 0,
    }
    
    _, _, errno := syscall.Syscall(SYS_BPF, BPF_PROG_ATTACH, 
        uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
    if errno != 0 {
        return fmt.Errorf("BPF_PROG_ATTACH: %v", errno)
    }
    return nil
}
```

**Takeaway**: When eBPF features seem unsupported, verify with raw syscalls before giving up. High-level tooling often lags kernel capabilities.

---

### Lesson 2: sock_ops Cgroup Attachment Conflicts

**Problem**: Second attachment to same cgroup fails with "operation not permitted".

**Root Cause**: An existing sock_ops program was already attached (from previous Grimlock testing).

**Solution**: Detach existing programs first:
```bash
sudo bpftool cgroup detach /sys/fs/cgroup sock_ops id <ID>
```

**Takeaway**: Always check for existing BPF attachments before testing:
```bash
sudo bpftool cgroup show /sys/fs/cgroup
```

---

### Lesson 3: Go bpf2go and C Source Files

**Problem**: `go build` fails with "C source files not allowed when not using cgo".

**Root Cause**: `.bpf.c` files in the same package directory are treated as C sources by Go.

**Solution**: Move BPF C files to a subdirectory:
```
cmd/skb-test/
├── main.go
├── go.mod
├── bpf/
│   ├── redirect.bpf.c
│   └── vmlinux.h
└── bpf_bpfel.go  (generated)
```

Update go:generate directive:
```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" bpf bpf/redirect.bpf.c
```

---

### Lesson 4: sk_skb Program Types

**Key Insight**: sk_skb has TWO program types that work together:

| Program | Section | Purpose |
|---------|---------|---------|
| stream_parser | `sk_skb/stream_parser` | Returns message length (framing) |
| stream_verdict | `sk_skb/stream_verdict` | Decides redirect destination |

Both MUST be attached to the sockmap for redirect to work.

```c
SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb) {
    return skb->len;  // Pass entire buffer as one message
}

SEC("sk_skb/stream_verdict")
int stream_verdict(struct __sk_buff *skb) {
    __u32 src_port = skb->local_port;
    __u32 *target = bpf_map_lookup_elem(&redirect_map, &src_port);
    if (!target) return SK_PASS;
    return bpf_sk_redirect_hash(skb, &sock_map, target, BPF_F_INGRESS);
}
```

---

### Lesson 5: Verifying Kernel Support

**Before writing code**, verify kernel capabilities:

```bash
# Check kernel config
zcat /proc/config.gz | grep -E "BPF_STREAM_PARSER|SOCK_MSG"
# Expected: CONFIG_BPF_STREAM_PARSER=y, CONFIG_NET_SOCK_MSG=y

# Check kTLS
modprobe tls && lsmod | grep tls

# Check BPF program types
sudo bpftool feature probe | grep -E "sk_skb|sk_msg"

# Test sockmap creation
sudo bpftool map create /sys/fs/bpf/test_sockmap type sockhash key 4 value 8 entries 16
```

---

### Lesson 6: Statistics Maps for Debugging

**Best Practice**: Always include a stats map in eBPF programs:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_ESTABLISHED 0
#define STAT_PARSER_CALLS 1
#define STAT_VERDICT_CALLS 2
#define STAT_REDIRECT_OK 3

static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&stats, &idx);
    if (val) __sync_fetch_and_add(val, 1);
}
```

This provides visibility into what's happening in kernel space without relying on `bpf_printk` (which requires reading trace_pipe).

---

## Phase 3: kTLS Integration (2025-01-27)

### Lesson 7: TLS 1.3 Key Derivation

**Problem**: Go's crypto/tls doesn't expose symmetric keys needed for kTLS.

**Solution Chain**:
1. Use `tls.Config.KeyLogWriter` to capture traffic secrets
2. Parse SSLKEYLOGFILE format to extract `CLIENT_TRAFFIC_SECRET_0` and `SERVER_TRAFFIC_SECRET_0`
3. Use HKDF-Expand-Label (TLS 1.3 KDF) to derive actual keys

```go
// HKDF-Expand-Label for TLS 1.3
func hkdfExpandLabel(secret []byte, label string, ctx []byte, length int) []byte {
    fullLabel := "tls13 " + label
    hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(ctx))
    hkdfLabel[0] = byte(length >> 8)
    hkdfLabel[1] = byte(length)
    hkdfLabel[2] = byte(len(fullLabel))
    copy(hkdfLabel[3:], fullLabel)
    // ... context
    
    reader := hkdf.Expand(sha256.New, secret, hkdfLabel)
    result := make([]byte, length)
    io.ReadFull(reader, result)
    return result
}
```

---

### Lesson 8: kTLS Struct Layout

**Critical**: The kernel expects EXACT struct layout for `setsockopt(SOL_TLS, TLS_TX/RX)`:

```go
type tlsCryptoInfoAESGCM128 struct {
    Version     uint16    // TLS version (0x0304 for TLS 1.3)
    CipherType  uint16    // TLS_CIPHER_AES_GCM_128 = 51
    IV          [8]byte   // 8-byte implicit IV
    Key         [16]byte  // 16-byte AES key
    Salt        [4]byte   // 4-byte salt
    RecSeq      [8]byte   // 8-byte record sequence number
}
```

The struct must be passed as raw bytes to `setsockopt`.

---

## Phase 2: Basic eBPF (2025-01-27)

### Lesson 9: Port Byte Order

**Problem**: Port numbers appeared incorrect in eBPF events.

**Root Cause**: `remote_port` in `bpf_sock_ops` is stored weirdly:
- Upper 16 bits: actual port in network byte order
- Lower 16 bits: unused

**Solution**:
```c
__u16 remote_port = bpf_ntohs(skops->remote_port >> 16);
```

---

### Lesson 10: IP Address Byte Order on x86

**Problem**: IP addresses logged in reverse order.

**Root Cause**: On little-endian x86, IPs in kernel structs are in host byte order.

**Solution** (Go side):
```go
binary.LittleEndian.Uint32(ip[:]) // NOT BigEndian
```

---

## Architecture Insights

### Why "Pure eBPF" Matters for A2A

Traditional service mesh (ztunnel, Envoy) requires:
1. User-space proxy reads plaintext from app
2. Proxy encrypts and sends
3. Proxy on other side decrypts
4. Proxy writes to destination app

Each hop = system call overhead + context switches.

**Grimlock approach**:
- **Sender**: sk_msg redirects app → kTLS socket (kernel-to-kernel)
- **Wire**: kTLS handles encryption (kernel)
- **Receiver**: sk_skb redirects kTLS socket → app (kernel-to-kernel)

**Result**: Zero-copy data path on sender side, minimal overhead on receiver.

---

## Common Pitfalls

| Pitfall | Solution |
|---------|----------|
| "Operation not permitted" on cgroup | Check existing attachments, use correct cgroup path |
| Verifier errors with large programs | Split into smaller functions, use `__always_inline` |
| sk_skb not firing | Ensure BOTH parser AND verdict are attached |
| kTLS setup fails | Verify kernel module loaded: `modprobe tls` |
| cilium/ebpf version mismatch | Match Go version requirements (1.20+ for v0.12) |

---

## Testing Checklist

Before deploying eBPF:
- [ ] Kernel version 5.10+ (6.x preferred)
- [ ] BTF available: `/sys/kernel/btf/vmlinux`
- [ ] kTLS module: `lsmod | grep tls`
- [ ] Cgroup v2: `mount | grep cgroup2`
- [ ] No conflicting BPF programs attached
- [ ] Root/CAP_SYS_ADMIN for loading

---

## Production Integration: kTLS in Grimlock (2026-03-19)

### Lesson 11: kTLS + `tls.Conn.Write()` = Double Encryption

**Problem**: After enabling kTLS via `setsockopt(TCP_ULP)` on a tunnel socket, we continued writing through Go's `*tls.Conn`. The data was encrypted twice -- once by Go's user-space `crypto/tls`, then again by the kernel's kTLS layer.

**Symptom**: The receiving side parsed garbage (e.g., destination port showed `6491` instead of `8080`) because it decrypted one layer but the inner layer was still encrypted.

**Root Cause**: `tls.Conn.Write()` always encrypts before writing to the underlying socket. After kTLS is enabled, the kernel also encrypts on `sendmsg()`. These two layers stack.

**Solution**: After enabling kTLS, switch to the **raw `*net.TCPConn`** for all data operations. The kernel handles crypto transparently on the raw socket:

```go
// After TLS handshake + kTLS setsockopt:
tcpConn := conn.NetConn().(*net.TCPConn)
tcpConn.Write(plaintext)  // kernel encrypts via kTLS
tcpConn.Read(buf)          // kernel decrypts via kTLS

// Do NOT use:
conn.Write(plaintext)      // double encryption!
```

**Takeaway**: kTLS replaces user-space TLS on the data path. The `*tls.Conn` is only for the handshake. After kTLS is active, treat it as a dead object.

---

### Lesson 12: `tls.Conn.NetConn()` vs `reflect`/`unsafe` for TCP Socket Extraction

**Problem**: The POC used `reflect.ValueOf(conn).Elem().FieldByName("conn")` + `unsafe.Pointer` to extract the `*net.TCPConn` from a `*tls.Conn`. This breaks across Go versions since `conn` is a private field.

**Solution**: Use `tls.Conn.NetConn()` (stable public API since Go 1.18):

```go
tcpConn, ok := conn.NetConn().(*net.TCPConn)
```

This is the same underlying socket but accessed through a supported API that won't break on Go upgrades.

---

### Lesson 13: Server-Side kTLS Fails with `tls.Listen` (ENOTCONN)

**Problem**: Enabling kTLS on connections accepted via `tls.Listen()` failed with `setsockopt(TCP_ULP): transport endpoint is not connected` (ENOTCONN).

**Root Cause**: `tls.Listen` wraps the TCP listener opaquely. The `*net.TCPConn` extracted via `NetConn()` from a `tls.Listen`-accepted connection didn't give us a clean fd for `setsockopt`.

**Solution**: Use a **raw `net.Listen("tcp", ...)` instead of `tls.Listen`**. Accept the raw `*net.TCPConn`, then wrap it manually with `tls.Server()`:

```go
// Instead of tls.Listen (opaque):
tcpLn, _ := net.Listen("tcp", addr)
tcpConn, _ := tcpLn.Accept()             // raw *net.TCPConn
tlsConn := tls.Server(tcpConn, config)   // manual wrap
tlsConn.Handshake()                       // user-space handshake
enableKTLSOnTCP(tcpConn, false, ...)      // kTLS on raw fd
// Use tcpConn for data (kernel handles crypto)
```

This gives direct control over the socket fd, which is guaranteed to be the actual connected socket in `TCP_ESTABLISHED` state.

---

### Lesson 14: TCP Socket State Race -- `CLOSE_WAIT` Kills kTLS Setup

**Problem**: Server-side kTLS setup failed intermittently even after the `tls.Listen` fix. The error was still `ENOTCONN` on `setsockopt(TCP_ULP)`.

**Diagnosis**: Added `getsockopt(TCP_INFO)` to check `tcpi_state` before the failing call. Found: **`tcp_state=8` (`TCP_CLOSE_WAIT`)**, not `tcp_state=1` (`TCP_ESTABLISHED`).

**Root Cause**: The test client called `tcpConn.CloseWrite()` immediately after sending data. This sent a TCP FIN to the server, transitioning the server socket from `ESTABLISHED` to `CLOSE_WAIT` before the server could call `setsockopt(TCP_ULP)`. The kernel requires `TCP_ESTABLISHED` state for ULP attachment:

```c
// kernel: tcp_set_ulp()
if (sk->sk_state != TCP_ESTABLISHED)
    return -ENOTCONN;
```

**Timeline of the race**:
```
Client                          Server
  |-- TLS Handshake ------------>|
  |<--- TLS Handshake ----------|
  |-- Data + FIN (CloseWrite) ->|   (socket -> CLOSE_WAIT)
  |                              |-- setsockopt(TCP_ULP) -> ENOTCONN!
```

**Solution**: Enable kTLS **immediately after the TLS handshake**, before reading any data. Do not allow the client to close the connection before kTLS is established. In the real eBPF-redirected flow, applications send data normally without premature `CloseWrite()`, so this race doesn't occur with actual agent traffic.

**Takeaway**: `setsockopt(TCP_ULP, "tls")` is sensitive to socket state. It must be called while the socket is in `TCP_ESTABLISHED`. Any FIN from either side (even a half-close) transitions the state and makes kTLS setup impossible. Set up kTLS as early as possible after the handshake.

---

### Lesson 15: POC Code is a Design Reference, Not Production Code

**Problem**: The POC had patterns that were fine for a conference demo but broke in production integration:
- 4 overlapping tunnel creation methods (`GetOrCreateTunnel`, `CreateOutgoingTunnel`, `forceCreateTunnel`, `CreateDedicatedTunnel`)
- Hand-rolled `hexDecode()` and `splitFields()` duplicating `encoding/hex` and `strings.Fields`
- Connection-per-request model (new TLS handshake per request)
- Flat `package main` with no separation

**Solution for production integration**:
- Consolidate into one `dial()` + connection pool
- Use stdlib: `encoding/hex.DecodeString()`, `strings.Fields()`
- Bounded pool per peer (`chan *Tunnel` with max capacity)
- Self-contained `internal/ktls/` package with dependency injection (logger, metrics registry, audit callback passed via config)
- Clean API: `ktls.New(config)` / `manager.Start(ctx)` / `manager.Stop()`

**Takeaway**: When porting a POC to production, treat the POC as a design reference that proves the architecture works. Re-implement to production standards rather than copying code directly.

---

## Updated Testing Checklist

Before deploying kTLS:
- [ ] Kernel version 5.10+ (6.x preferred)
- [ ] BTF available: `/sys/kernel/btf/vmlinux`
- [ ] kTLS module: `lsmod | grep tls`
- [ ] ULP available: `cat /proc/sys/net/ipv4/tcp_available_ulp` should list `tls`
- [ ] Cgroup v2: `mount | grep cgroup2`
- [ ] No conflicting BPF programs attached
- [ ] Root/CAP_SYS_ADMIN for loading
- [ ] Certificates at `/etc/grimlock/ktls/` (cert.pem, key.pem, ca.pem)
- [ ] Security groups: TCP 9443 (tunnel), TCP 8080 (agent) open between peers

---

*Last updated: 2026-03-19*
