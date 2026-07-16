# Channel classes: per-connection fast vs. guarded + an enforcer pipeline

> **Implemented** (`guard.go`, `payment.go`, `mcp.go`, `main.go`; status in §9).
> Resolves the core tension in [architecture.md](architecture.md): the
> "kernel-fast zero-copy data plane" and "unbypassable wire enforcement" used to
> fight over the same egress leg as a **daemon-global either/or** (any
> `--x402-enforce`/`--mcp-enforce` routed *every* connection through a userspace
> proxy, so nothing ever spliced). The choice is now **per-connection** and the two
> enforcers **compose** on one channel.

## 1. The two classes (three, with deny)

A local connection, once its original destination is recovered, is classified:

| Class | Data plane | Daemon sees plaintext? | For |
|---|---|---|---|
| **fast** | kTLS + `splice(2)` (client egress), daemon off-path | no (client egress) | bulk: weights, RAG corpora, large results |
| **guarded** | userspace parse → enforcer pipeline → forward | yes | control: tool calls, payments, RPC |
| **deny** | connection refused | — | egress chokepoint (unlisted/non-peer) |

Enforcement inherently needs plaintext (you cannot block what you already spliced),
so *guarded ⇒ no splice* is fundamental, not an implementation limit. The point is
to route each channel to the lane that fits it, instead of forcing the whole daemon
into one lane. Bulk transfer keeps the zero-copy, no-plaintext property; control
traffic keeps unbypassable governance.

## 2. The routing rule

Classification is a pure function of the **recovered original destination** —
`origDest.Resolve(srcPort) → (peerIP, destPort, ok)` — which
`handleLocalConnection` already computes. Primary key is `destPort` (per-peer
override is a later extension):

```go
type channelClass int

const (
    classFast    channelClass = iota // splice, no inspection
    classGuarded                     // userspace enforce
    classDeny                        // refuse (egress chokepoint)
)

// egressPolicy maps a recovered destination to a class + the enforcer chain to run.
type egressPolicy struct {
    guards       map[int][]enforcerFactory // dest port → ordered enforcer chain
    fastPorts    map[int]bool              // explicit bulk (never enforced)
    denyUnlisted bool                      // unlisted port ⇒ deny (else fast)
}

func (p *egressPolicy) classify(destPort int) ([]enforcerFactory, channelClass) {
    if f := p.guards[destPort]; len(f) > 0 {
        return f, classGuarded
    }
    if p.fastPorts[destPort] {
        return nil, classFast
    }
    if p.denyUnlisted {
        return nil, classDeny
    }
    return nil, classFast // default
}
```

A port with an enforcer chain is guarded; a port with none is fast; an unlisted
port takes the default. `denyUnlisted=true` turns Grimlock into an egress
chokepoint — but note the honest boundary in §7: `connect4` currently only
redirects *known peers*, so full egress control also needs the eBPF intercept-all
change; without it, `deny` only governs intercepted A2A ports.

## 3. The enforcer interface

Two tiny interfaces. A per-connection object may implement **either or both** —
x402 needs both (it correlates a `402` challenge seen on a *response* with the
payment on the next *request*, and tracks pending settlements), MCP needs only the
request side.

```go
// requestEnforcer vets one agent request before it is forwarded. To BLOCK it
// writes a protocol-appropriate error to `deny` (x402 → HTTP 403 JSON; MCP →
// JSON-RPC error) and returns a non-nil error; the proxy then closes the channel.
// To PERMIT (including "not applicable to me") it returns nil. It must not mutate
// body — the raw bytes are forwarded verbatim.
type requestEnforcer interface {
    enforce(req *http.Request, body []byte, deny io.Writer) error
}

// responseObserver sniffs a reply on its way back to the agent; it never blocks
// (responses are already authorized). Used for x402 settlement / 402 capture.
type responseObserver interface {
    observe(resp *http.Response, body []byte)
}

// enforcerFactory builds the per-connection object(s) from the channel's
// attestation context. Returns `any`; the proxy type-asserts to the two interfaces.
type enforcerFactory func(cc channelContext) any

type channelContext struct {
    exp      attest.Exporter     // session EKM — x402 payment binding
    epoch    uint64              // attestation epoch — freshness / model @e
    manifest capability.Manifest // peer's attested manifest — MCP
    peerIP   string
    destPort int
}
```

A request is forwarded only if **every** enforcer permits it (∧ composition), which
is exactly the model's `!Γ, Δ, epoch ⊢ Forward(req, pay)` — one judgment, several
premises — instead of two hardcoded, mutually-exclusive proxies.

## 4. The unified guarded proxy

One proxy owns the bidirectional loop; enforcers are pure decision objects. This is
the current `mcpEnforcer.proxy`/`x402Enforcer.proxy` structure, generalized:

```go
func guardedProxy(agentConn, tunnelConn net.Conn, reqs []requestEnforcer, obs []responseObserver) {
    done := make(chan struct{}, 2)
    go func() { pumpResponses(tunnelConn, agentConn, obs); done <- struct{}{} }()
    go func() { pumpRequests(agentConn, tunnelConn, reqs); done <- struct{}{} }()
    <-done
    agentConn.Close()
    tunnelConn.Close()
    <-done
}

func pumpRequests(agentConn, tunnelConn net.Conn, reqs []requestEnforcer) {
    br := bufio.NewReader(agentConn)
    for {
        agentConn.SetReadDeadline(deadline())                 // slowloris bound (existing)
        req, err := http.ReadRequest(br)
        if err != nil { return }
        body, oversize := boundedBody(req)                    // 1 MiB cap (existing)
        if oversize { writeOversize(agentConn); return }
        for _, e := range reqs {
            if err := e.enforce(req, body, agentConn); err != nil { return } // e wrote the block
        }
        if forwardRequest(req, body, tunnelConn) != nil { return }
    }
}

func pumpResponses(tunnelConn, agentConn net.Conn, obs []responseObserver) {
    if len(obs) == 0 {                                        // MCP-only channel
        io.Copy(agentConn, tunnelConn); return                //   → pure passthrough (fast responses)
    }
    br := bufio.NewReader(tunnelConn)                          // x402 channel: parse-tee to sniff
    for {
        resp, err := http.ReadResponse(br, nil)
        if err != nil { return }
        body, _ := boundedBody2(resp)
        for _, o := range obs { o.observe(resp, body) }
        if writeResponse(resp, body, agentConn) != nil { return }
    }
}
```

`toolCallsIn`/fail-closed/batch handling (mcp.go) and the payment
correlation (payment.go) move verbatim into the respective `enforce`/`observe`
methods — no logic change, just relocation behind the interface.

## 5. x402 and MCP as pipeline members

```go
// paymentConn implements BOTH interfaces (shared per-connection state).
func (xe *x402Enforcer) factory() enforcerFactory {
    return func(cc channelContext) any { return &paymentConn{xe: xe, exporter: cc.exp, epoch: cc.epoch} }
}
func (pc *paymentConn) enforce(req *http.Request, body []byte, deny io.Writer) error { /* was enforceRequests body */ }
func (pc *paymentConn) observe(resp *http.Response, body []byte)                     { /* was forwardResponses body */ }

// mcpConn implements only requestEnforcer.
func (me *mcpEnforcer) factory() enforcerFactory {
    return func(cc channelContext) any { return &mcpConn{policy: me.policy, manifest: cc.manifest} }
}
func (mc *mcpConn) enforce(req *http.Request, body []byte, deny io.Writer) error { /* was enforceRequests body */ }
```

## 6. Dispatch (the `handleLocalConnection` rewrite)

```go
peerIP, destPort := recoverOrigDest(...)             // unchanged
factories, class := egress.classify(destPort)
if class == classDeny {
    metrics.egressDenied.Add(1); return              // chokepoint
}
h, err := tunnelMgr.channelFor(peerIP).stream(); ... // unchanged
writeDestHeader(h.conn, peerIP, destPort)            // unchanged

if class == classFast {                              // ── fast lane: current splice/relay path
    if spliceable(h.conn, conn) { splice } else { relay }
    return
}
// ── guarded lane: build the pipeline for THIS connection and run it
cc := channelContext{exp: h.exp, epoch: h.epoch, manifest: tunnelMgr.manifestFor(peerIP), peerIP: peerIP, destPort: destPort}
var reqs []requestEnforcer
var obs  []responseObserver
for _, f := range factories {
    g := f(cc)
    if r, ok := g.(requestEnforcer);  ok { reqs = append(reqs, r) }
    if o, ok := g.(responseObserver); ok { obs = append(obs, o) }
}
guardedProxy(conn, h.conn, reqs, obs)
```

The fast lane is byte-for-byte the existing splice code; the guarded lane is the
existing proxy structure with a chain instead of one hardcoded enforcer.

## 7. What it resolves — and what it does not

**Resolves**
- **Splice ⟂ enforce coexist.** Bulk ports splice; control ports enforce; same daemon.
- **Composition.** `--guard 8080:mcp,x402` runs both premises on one channel — the model's single judgment, realized.
- **Egress scope.** `--egress-default deny` refuses unlisted destinations (subject to §7 caveat), making Grimlock a chokepoint rather than an A2A shim.
- **Model↔code.** The pipeline *is* `⊢ Forward` (conjoined premises), not two special cases.

**Does not (honest boundaries)**
- **Server-side RX asymmetry.** Fast channels are zero-copy on the *client egress* (kTLS-TX + splice); the receiving Grimlock still decrypts in userspace. Kernel RX kTLS is a separate, harder change (buffer sync with Go's TLS). Fast-lane confidentiality/zero-copy is a client-egress property — state it as such.
- **Full egress control needs an eBPF change.** `connect4` only redirects known peers (`is_agent_peer`); a hijacked agent dialing a *non-peer* is never intercepted. `classDeny` governs only intercepted ports until `connect4` is switched to intercept-all-then-classify. The framework supports it (`denyUnlisted`); realizing it is a follow-on.

## 8. Config

Enforcer *policies* stay where they are (`--x402-*` limits, `--mcp-policy-*`
grant); new flags *attach* them to ports:

```
--guard 8080:mcp            # port 8080 = guarded by MCP capability enforcement
--guard 9000:x402           # port 9000 = guarded by x402
--guard 8080:mcp,x402       # both, composed on one channel
--fast 5000                 # port 5000 = bulk (never enforced)
--egress-default fast|deny  # unlisted intercepted ports (default: fast)
```

**Backward compatible:** the old global `--x402-enforce`/`--mcp-enforce` map to
"guard *all* agent ports with that enforcer," so existing invocations behave as
today (guarded everywhere, nothing splices) — the new value is opt-in per port.

## 9. Status

1. **Interfaces + `guardedProxy` — DONE.** `requestEnforcer`/`responseHandler`/
   `finisher` in `guard.go`; `paymentConn`/`mcpConn` refactored into
   `enforce`/`handleResponses`/`finish`. Behavior-preserving — the existing x402
   and MCP tests pass unchanged (they now drive `pumpRequests`/`handleResponses`).
2. **Per-port routing + fast lane — DONE.** `egressPolicy.classify`, the
   `--guard`/`--fast`/`--egress-default` flags, and the classify dispatch in
   `handleLocalConnection`. Bulk ports splice; control ports enforce; both compose
   (`--guard 8080:mcp,x402`). Backward compatible: a global `--*-enforce` with no
   `--guard` guards all agent ports (today's behavior). Unit-tested
   (`guard_test.go`): classify, backward-compat mapping, scoping+deny, composition.
3. **Egress chokepoint — PARTIAL.** `--egress-default deny` refuses unlisted
   *intercepted* ports. Making it total needs the `connect4` intercept-all change
   (§7) — a follow-on.

Decisions taken: `--guard PORT:ENFORCERS` flag scheme; per-port classes with the
A2A scope this iteration (the `connect4` intercept-all is the follow-on); egress-only
enforcement (sound under the attestation assumption — the client daemon is measured).
