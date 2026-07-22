# Grimlock Threat Model

> Companion to [model.md](model.md). The model says *what* is authorized; this
> document says *against whom*, *under what assumptions*, and *what is explicitly
> out of scope*. Every claim here is tied to a model rule/theorem or marked as an
> assumption or residual.

## 1. System and Trusted Computing Base (TCB)

Grimlock interposes transparently between two AI agents: eBPF (`cgroup/connect4`,
`sockops`) redirects an agent's outbound connection into the local Grimlock
daemon, which establishes a mutually-attested TLS 1.3 + kTLS tunnel to the peer
daemon, which forwards to the peer agent.

**In the TCB (must be correct for any guarantee):**

| Component | Why trusted | How justified |
|---|---|---|
| Intel TDX module + CPU | Root of measurement + quote signing | Hardware assumption (§6) |
| The Grimlock daemon image | Terminates TLS, holds keys, decides `Forward` | **Measured** into the TD (MRTD/RTMR), pinned by the peer |
| eBPF verifier | Proves memory-safety + termination of `connect4`/`sockops` | Sound (incomplete) static analysis — free partial verification |
| `go-tdx-guest` verify/validate path | Appraises peer quotes | Audited dependency; assumption |
| Intel PCS/PCCS roots | PCK chain / TCB status | PKI trust anchor (§6) |

**Explicitly NOT in the TCB:**

- **The network** — fully adversarial (Dolev-Yao). The TLS handshake is
  `InsecureSkipVerify` (ephemeral cert, no PKI); *all* trust comes from the
  post-handshake gate, not the channel.
- **The agent behind either Grimlock** — see §3. This is deliberate.
- **The x402 facilitator / chain** — Grimlock binds and enforces *policy*; it
  trusts the facilitator for cryptographic settlement validity (stated in
  `x402-attested-payments.md`).

**TCB size goal:** the security decision (`Forward`) is a small, fixed-shape
admission check (`model.md §12`). §7 (privilege separation) proposes isolating it
so the provable kernel is also the *only* privileged component.

## 2. Adversary model

We consider three adversaries, composably:

1. **Network adversary (Dolev-Yao).** Full control of the wire: read, drop,
   reorder, inject, replay, and *terminate* TLS (active MITM). Cannot break
   cryptographic primitives (§6).
2. **Malicious agent.** The application behind a Grimlock is arbitrarily
   compromised: it may attempt over-spend, privilege escalation, replay, or
   exfiltration through the tunnel. It does **not** control its local Grimlock or
   the TD.
3. **Malicious platform (bounded).** An adversary controlling a *host* may run
   its own TD. Whether it is admitted depends on the measurement + instance
   policy (§3, T3). A platform that breaks TDX itself is out of scope (§6).

## 3. Trust boundaries — the central design decision

> **Grimlock is attested; the agent behind it is not (by default).**

The gate proves *"a genuine Grimlock enforcer with measurement `M`, instance key
`K`, and manifest `Man` terminates this session"* — **not** that the agent is
uncompromised. This is a **feature, not a gap**, and it is the reason the payment
and capability guarantees are meaningful:

- **Payment enforcement survives agent compromise.** The spend policy is checked
  *outside* the (possibly hijacked) agent, in the attested daemon (`payment.go`).
  A compromised agent cannot raise its own cap or route around the 402
  correlation — that is the core novelty.
- **Capability governance is over what the agent *advertises*.** The manifest is
  the agent's claim; the peer's policy bounds it (T4). A lying agent can only
  *narrow* its own advertised capabilities, never exceed the peer's grant.

**Closing the boundary (implemented).** The agent's measurement is a **first-class
bound field**: `--attest-agent-measurement` advertises it and folds it into the
quote transcript (distinct from the Grimlock TD's own `MR_TD`), and
`--attest-peer-agent-measurement` pins the required peer value. To make it
*hardware-rooted*, set it equal to a TD **RTMR** the agent extends at launch
(co-located agent + Grimlock in one TD). For a **remote** agent (separate TD /
host), nested/linked attestation is required — **out of scope** for the current
single-daemon design and flagged as future work.

When agent and Grimlock share a TD, the enforcement point must survive a
**hijacked but code-intact** neighbor (the threat model here — prompt injection,
not a kernel-level compromise). Grimlock runs as a separate process and is set
**non-dumpable** (`hardening.go`), so a same-uid neighbor cannot `ptrace` it or
read `/proc/<pid>/mem` to extract kTLS/resumption secrets and forge continuity;
`--seccomp` additionally blocks `ptrace`/`process_vm_*`. A *kernel*-level
compromise of the shared TD is out of scope (it would require the full allow-list
jail / a separate TD — [privilege-separation.md](privilege-separation.md)).

## 4. Assets and security goals

| Asset | Goal | Realized by |
|---|---|---|
| Session confidentiality/integrity | TLS 1.3 + kTLS AEAD | channel |
| Peer authenticity | only a policy-compliant TD is accepted | gate: T1, T2, T3 |
| Least privilege | no tool call outside the granted capability ideal | T4 |
| Spend control | no payment outside policy; no replay | T5 |
| Non-repudiation / audit | tamper-evident record of every decision | receipts (§7 upgrade) |
| Freshness | trust is bounded-stale; payments bind their epoch | epochs, resumption TTL |

## 5. Threats and mitigations

Status: **✓ closed**, **◐ partial**, **○ open/next**. Each links to a model rule.

| # | Threat | Mitigation | Status |
|---|---|---|---|
| A | **Relay / cuckoo** — replay a valid quote from another real TD | Quote's `REPORT_DATA = EKM(transcript)`; a quote bound to another session's exporter fails `R-bind` | ✓ (T2, lemma L1) |
| B | **Active MITM, own non-compliant TD** | Measurement pinning (`Verifier`) rejects it | ✓ (T3) |
| C | **Active MITM, own *golden-image* TD** | Instance key `K` bound + `--attest-allow-instance-key` (`Policy says K⇒TrustedPeer`) | ✓ with allowlist; ◐ closed-membership-by-measurement without it (stated) |
| D | **Unauthenticated TLS MITM** | TLS trust is *not* relied on; gate is the sole trust root; CertificateVerify binds `K` to the session | ✓ |
| E | **Manifest swap / call smuggling** — advertise one capability set, serve another; or hide a call from the enforcer | Digest bound into `REPORT_DATA` + **wire enforcement** (`--mcp-enforce`): every `tools/call` checked against the attested manifest, out-of-agent. The parser handles JSON-RPC **batches** and **fails closed** on any body it cannot classify (an unparseable body may hide a call) | ✓ unattested/over-grant/batched/unparseable calls blocked on the wire (SDK check now defense-in-depth) |
| F | **Capability escalation** — call a tool outside the grant | `covered` = prefix-ideal membership; fail-closed | ✓ (T4; Coq-proved, `formal/`) |
| G | **Over-spend / policy evasion by agent** | Enforced in the attested daemon, not the agent | ✓ (T5) |
| H | **Payment replay** — resubmit an `X-PAYMENT` | Linear 402-challenge + single-use EIP-3009 nonce; both consumed once | ✓ (T5) |
| I | **Cross-epoch payment re-bind** | Epoch bound into the payment transcript | ✓ (@e) |
| J | **Stale-trust forwarding** — serve on a tunnel whose attestation lapsed | Bounded at BOTH ends by the TTL: client drops stale tunnels + re-gates; server expires its resume-secret cache AND closes any tunnel that has served for the interval (§8.2) | ✓ both-ends TTL bound |
| K | **Routing mailbox ABA** — reused source port reads stale dest | Consume-on-read (`Lookup`+`Delete`); live conn owns its port | ✓ (linear token) |
| L | **Transcript field smuggling** — collide two bindings | Injective length-prefixed encoding | ✓ (L2; property-tested + Coq-proved) |
| M | **Gate DoS** — force expensive quote gen by an unauthenticated flood | Concurrency-capped load-shed + per-setup deadlines (§8.1); per-IP rate limit still ○ | ◐ |
| N | **Cross-restart replay** — epoch/nonce state resets on daemon restart | See §8.3 | ○ |
| O | **Instance-key revocation lag** — compromised instance stays allowlisted | See §8.4 | ○ |
| P | **kTLS handoff corruption** — a stray post-handshake record desyncs `RecSeq=0` | `SessionTicketsDisabled` + enable-before-data; assert still to add | ◐ |

## 6. Cryptographic and platform assumptions

The model is **conditionally sound**: proofs are parametric over these. They are
assumptions, not theorems, and are stated honestly (this is the standard boundary
— see `formal/README`).

1. **TDX is sound**: the CPU/module faithfully measures the TD and signs quotes;
   a TD's private state is confidential and integrity-protected. (Excludes TDX
   micro-architectural breaks, physical attacks, and vulnerable TCB levels — the
   last is *partially* checkable via `--attest-get-collateral`.)
2. **TLS 1.3 exporter is a PRF** keyed by a secret known only to the endpoints
   (RFC 8446 §7.5 / RFC 9266) → `EKM` is session-unique and unforgeable (L1).
3. **Signatures (quote ECDSA, EIP-3009) are UF-CMA**; **SHA-256 is
   collision-resistant** → transcript injectivity lifts to binding integrity (L2).
4. **Allowed instance keys are provisioned correctly** (the allowlist / enrolling
   CA is trusted).
5. **The peer's `go-tdx-guest` verification path is correct.**

## 7. Residual risks / out of scope (stated, not hidden)

- **Agent code integrity** (unless RTMR-extended, §3).
- **Side channels**: TDX timing/cache side channels; payment amount/timing
  metadata leaks over the encrypted channel. Not addressed.
- **Post-compromise audit forgery**: the receipt hash chain is tamper-*evident*
  against outsiders but a key-holding compromised daemon could forge *future*
  entries. Mitigation: a TD-sealed signing key + external transparency witnesses
  (Merkle STH) — planned upgrade to `receipt.go`.
- **Availability under partition**: Grimlock chooses **safety over availability**
  (fail-closed: no fresh attestation ⇒ refuse). Declared, not a bug.
- **Multi-hop trust composition** (A→B→C): the `hand-off` rule supports it, the
  implementation does not yet — future work.

## 8. Detailed analyses of the open items

### 8.1 Gate DoS (threat M)
**Attack.** The gate runs a mutual quote *generation* (≈ tens of ms + QGS
round-trip) and *verification* (PCK-chain crypto) after the TLS handshake, before
the peer is authenticated. A handshake flood forces unbounded quote work.
**Mitigation (implemented).** A bounded semaphore (`setupSem`, `maxConcurrentSetups`)
caps *concurrent* inbound setups: excess connections wait briefly and are then
**load-shed** (dropped, `setup_shed` metric) rather than queued unboundedly, so
CPU/QGS pressure is capped. Every inbound setup is **deadline-bound**
(`setupTimeout`), so a slowloris peer that stalls mid-handshake/gate is cut,
freeing its slot. The slot is held only for the expensive setup, then released
before the (unbounded) data phase. **Still open (○):** a per-source-IP rate limit,
and the asymmetric option of verifying the client's quote before generating the
server's (so a peer that can't produce a valid quote never triggers server
quote-gen) — a larger change that trades the barrier's mutual simultaneity.

### 8.2 Per-request freshness (threat J)
Freshness is bounded **at both ends** by the re-attestation interval / resumption
TTL:
- **Client:** a warm tunnel whose attestation is older than the TTL is dropped,
  and a connection whose resumption secret has lapsed does a **full gate**
  (re-checking measurement) rather than a cheap resume.
- **Server:** its resumption-secret cache **expires** per TTL, so a client cannot
  resume on a stale attestation (it is forced to full-gate); and a validly
  established tunnel is **closed once it has served for the TTL**
  (`handleForwardingConnection` sets the data-phase deadline to the interval), so
  the server never serves on one attestation past the window — independent of the
  client honouring its own max-idle.

So any served byte rode an attestation no older than the TTL, enforced by both
sides. The epoch (resumption generation) is additionally bound into *payments*
(audit + cross-epoch replay). A per-request epoch equality check on the server is
*not* added, because it races with concurrent tunnels of different generations
(a resumed tunnel legitimately carries an older generation than a concurrent fresh
full-gate); the both-ends TTL bound is the sound formulation.

### 8.3 Cross-restart replay (threat N)
Epoch counters and per-session nonces reset when the daemon restarts. An adversary
who captured a prior session cannot replay it (new session ⇒ new EKM), but a
**durable monotone counter** (or a nonce seeded from a TD-monotonic source /
sealed state) is needed to guarantee epochs never repeat across restarts, so that
audit epochs are globally monotone. Low effort, real.

### 8.4 Instance-key revocation (threat O)
The allowlist is static per process. Revoking a compromised instance key requires
a config reload today. A production fleet needs **revocation propagation** (a
short-TTL allowlist fed by a CA/CRL/OCSP-analog, or gossip) so a compromised
instance is excluded fleet-wide within a bounded window. This is a distributed-
systems addition (§ multi-instance), not a single-node change.

---

## 9. What an attacker must do to succeed (summary)

To cause an unauthorized `Forward`, an adversary must break **at least one**
assumption in §6, **or** exploit an **open** item in §5 (M/N/O/J/P). No purely
network adversary, and no compromised *agent*, can do it — that is the point:
security rests on the attested daemon and the TDX root, not on the network or the
application.
