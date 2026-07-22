# Grimlock Authorization Model

> The formal spine of the system. Grimlock is **proof-carrying authorization over
> session-scoped principals**: the daemon forwards a byte iff it can construct a
> proof that the root policy authorizes it. Attestation, channel binding,
> capability governance, payment, and freshness are not five subsystems — they
> are the same judgment with different principals and evidence.

This document is the specification; the code is an implementation of it. Where
they disagree, this document is the intended truth and the code is a bug.

---

## 1. Thesis

Every actor is a **principal**. Every cryptographic object (a TDX quote, a TLS
exporter value, an EIP-3009 signature, a manifest digest) is **evidence** that a
principal `says` something or `speaks-for` another. The forwarding decision is a
single judgment:

```
  !Γ_persistent ,  Δ_linear ,  epoch = now   ⊢   Forward(req, pay)
```

- `!Γ` — durable facts, reusable within an epoch (measurement, manifest, policy).
- `Δ`  — one-shot resources, consumed exactly once (nonces, the 402 challenge,
         the on-chain payment nonce, the routing mailbox).
- `epoch = now` — the live attestation epoch; stale epochs are not admissible.

The split (persistent vs linear vs epoch) is what makes the logic faithful to a
system that has revocation and one-shot evidence, while staying monotone enough
to prove.

---

## 2. Principals

```
  P, Q ::= K            instance key (a TLS endpoint's ephemeral public key)
         | M            measurement vector (MRTD, RTMR0..3, TEE_TCB_SVN)
         | Policy       the local root of trust (operator-configured)
         | role         TrustedPeer | Enforcer | Server | Client
         | P ∧ Q        conjunction ("speaks as both")
         | P | S        P scoped to session S      ← channel binding
         | P @ e        P at epoch e               ← freshness
```

`S` is the **session principal**: the TLS 1.3 channel, identified by its exporter
master secret. `P | S` means "P, *as observed on this specific channel*." This is
the load-bearing constructor — see §6.

`e ∈ ℕ` is a monotone per-session **epoch**. Re-attestation increments it. The
current admissible epoch of `S` is `now(S)`; the verifier rejects `e < now(S)`.
Because epochs only increase, "revocation" is monotone: nothing is removed, an old
credential's principal `(·|S@e)` simply no longer unifies with an `@now`
obligation.

---

## 3. Statements

```
  φ ::= measured(M, K)              this TD has measurement M and instance key K
      | ok                          this principal vouches for the channel
      | requires(tool, C)           tool needs capability C
      | grants(↓G)                  this policy grants the downward-closure of G
      | permit(call tool)           a tool call is permitted
      | authorized(pay, req)        a payment is authorized for a request
```

---

## 4. Judgments

- `P says φ` — P asserts φ.
- `P ⇒ Q`   — *speaks-for*: everything P says, Q says (delegation).

```
  (hand-off)        P says φ ,  P ⇒ Q
                    ─────────────────────
                          Q says φ
```

Persistent statements are written `! (P says φ)`; they may be used any number of
times within their epoch. Linear statements are consumed by the rule that uses
them.

---

## 5. Inference rules

```
  (R-bind)   quote q with q.REPORT_DATA = EKM_S( T(e, M, K, H(man_self), H(man_peer)) )
             ───────────────────────────────────────────────────────────────────────
                          ! (HW | S) says measured(M, K) @ e

  (R-trust)  ! (HW|S) says measured(M,K)@e   ,   M ∈ Golden   ,   Policy says (K ⇒ TrustedPeer)
             ──────────────────────────────────────────────────────────────────────────────────
                          ! (TrustedPeer | S) says ok @ e

  (R-cap)    ! (Server|S) says requires(tool, C)@e   ,   Policy says grants(↓G)   ,   C ∈ ↓G
             ──────────────────────────────────────────────────────────────────────────────────
                          ! Policy says permit(call tool) @ e

  (R-pay)    (Enforcer|S) says authorized(pay, req)@e            [linear]
             matchesChallenge(pay, challenge)  ∧  withinPolicy(pay)
             consume(challenge)  ,  consume(pay.nonce)
             ──────────────────────────────────────────────────────────────────
                          Δ ⊢ authorized(pay, req) @ e

  (R-forward)  ! (TrustedPeer|S) says ok @now
               ! Policy says permit(call req.tool) @now
               Δ ⊢ authorized(pay, req) @now
               consume(routing-token for req)         [linear: the cookie→port mailbox]
             ─────────────────────────────────────────────────────────────────────────
                          Forward(req, pay)
```

`HW` is the TDX hardware root (Intel TDX roots, validated by `go-tdx-guest`).
`T(...)` is the canonical injective transcript encoding (§7). `EKM_S` is the
RFC 9266 TLS exporter for session `S`.

---

## 6. Channel binding is the `| S` constructor (soundness)

ABLP/DCC `says`-logics assume principals are stable keys. Here principals are
**scoped to a TLS session by channel binding**: `(HW|S) says measured(M,K)` is
derivable *only* from a quote whose `REPORT_DATA = EKM_S(...)`. The TLS exporter
**is** the `| S` constructor.

The embedding (crypto evidence → logical credential) is **sound** iff:

- **L1 (exporter PRF).** `EKM_S` is a PRF over the exporter master secret, known
  only to the endpoints of `S` (RFC 8446 §7.5 / RFC 9266). ⟹ a quote bound to
  `EKM_{S'}` for `S' ≠ S` cannot discharge `R-bind` for `S` (relay/cuckoo
  defeated).
- **L2 (injective encoding).** `T(·)` is injective: distinct field-tuples map to
  distinct byte strings (§7). ⟹ no cross-purpose or cross-field collision.

These two lemmas are the entire cryptographic obligation of the model.

---

## 7. Canonical transcript `T`

A single injective TLV encoding replaces every ad-hoc `sha256(a ‖ b ‖ …)` in the
codebase. Each field is length-prefixed and domain-tagged:

```
  field(label, bytes) = u32(len(label)) ‖ label ‖ u32(len(bytes)) ‖ bytes
  T(f1, …, fn)        = u8(version) ‖ field(f1) ‖ … ‖ field(fn)
```

**Injectivity** is provable by induction on the length prefixes (parsing
uniqueness). This is lemma **L2**; it must be a property-tested (and ideally
machine-checked) invariant, because every "the quote commits to X" claim depends
on it.

The session transcript `T_S` is the ordered sequence of fields folded into the
gate and payment bindings. The **proof term is the transcript**: the ordered
derivation that produced `Forward` *is* `T_S` — `Γ_S` (the conclusion multiset)
is its forgetful image. The implementation keeps the ordered, evidence-carrying
form, so ordering and freshness are structural, not a second layer.

---

## 8. Subsystem mapping

Every subsystem is one instance of the judgment:

| Subsystem | Kind | Statement | Evidence |
|---|---|---|---|
| eBPF redirect (`connect4`/`sockops`) | linear | *defines* `S`; mints the routing token | `cookie_dest → port_dest` (consume-on-read) |
| Attestation gate (`internal/attest`) | persistent | `(HW\|S) says measured(M,K)@e` | TDX quote over `EKM_S` |
| Measurement policy (`TDXVerifier`) | persistent | `M ∈ Golden ⟹ (·\|S) ⇒ TrustedPeer` | MRTD/RTMR/TCB pins |
| Instance allowlist (Policy) | persistent | `Policy says (K ⇒ TrustedPeer)` | instance-key allowlist / CA |
| Channel binding (EKM) | — | the `\|S` constructor | `TLS-Exporter` (RFC 9266) |
| Capability manifest (`internal/capability`) | persistent | `(Server\|S) says requires(tool,C)@e` | manifest digest in `REPORT_DATA` |
| Client policy (`Policy.Check`) | persistent | `grants(↓G)`, `C ∈ ↓G ⟹ permit` | dot-prefix covering (the lattice ≤) |
| x402 payment (`payment.go`) | linear | `(Enforcer\|S) says authorized(pay,req)@e` | quote over payment transcript + EIP-3009 |
| Re-attestation (`tunnel.go`) | epoch | resumption-secret TTL lapses → next connection full-gates (advances `now(S)`) | resume vs full gate |
| Receipt log (`receipt.go`) | — | the logged proof | hash chain → transparency log |

---

## 9. Security properties (as invariants / theorems)

- **T1 (no forward without fresh attestation).** `Forward(req,pay)` reachable ⟹
  ∃ `M ∈ Golden`, `K` with `Policy says K⇒TrustedPeer`, and a quote bound to
  `EKM_S` at `now`. *Safety invariant over the LTS.*
- **T2 (cuckoo/relay resistance).** A quote bound to `EKM_{S'}`, `S'≠S`, cannot
  discharge `R-bind` for `S`. *From L1.*
- **T3 (no same-image impersonation without authorization).** Even with
  `M ∈ Golden`, `R-trust` needs `Policy says K⇒TrustedPeer`. Measurement
  authenticates *code*; `K` authenticates *instance*; the policy *authorizes* the
  instance. (Without the `K` premise, an active MITM running the same golden image
  is admitted — see §11.)
- **T4 (capability non-escalation).** `permit(call tool)` ⟹ `tool.cap ∈ ↓G`;
  monotone in `G`. *Lattice property; machine-checkable in Coq/Lean.*
- **T5 (payment integrity / no replay).** Each `authorized(pay)` consumes the
  linear 402-challenge and the on-chain nonce ⟹ no double-authorization.
  *From linearity.*
- **T6 (mutual injective agreement).** Both endpoints derive `Forward` only if the
  ACK barrier passed ⟹ they agree on `(S, e, M_self, M_peer, H(man_self),
  H(man_peer))`. *Distributed property; Tamarin.*

---

## 10. Verification plan

The runtime is a **typed admission checker**, not a theorem prover: `Forward` has
fixed shape (one premise per credential kind), so `Authorize` is a decidable,
~linear conjunction check over current, scoped credentials. The *proofs* are
offline and split by fragment:

- **Coq — persistent, local. DONE.** The capability join-semilattice, `R-cap`
  non-escalation (T4), and transcript injectivity (L2) — axiom-free
  ([../formal/Grimlock.v](../formal/Grimlock.v)).
- **Tamarin — linear, mutual. DONE.** Machine-checked symbolic models
  ([../formal/](../formal/), `make tamarin`), all lemmas verified, wellformedness
  clean, mutation-tested for non-vacuity: the gate's **EKM-binding** gives quote
  relay/cuckoo-resistance (T2) and the **mutual ACK barrier** gives the
  both-or-neither honest-risk property (T6 — a party forwards only if the peer
  also accepted it); the **resumption handshake** gives mutual + **injective**
  (no-replay, T5) agreement on the session bind plus RS secrecy, proved even
  against an adversary that reveals every session exporter.
- **TLA+ / PlusCal — liveness (optional).** Self-healing of the warm pool
  (convergence + closure, Dijkstra self-stabilization), no lost wake-ups in the
  establish / resume / drop-on-stale / epoch transitions.

---

## 11. Gap status (each residual is a missing edge in *one* proof)

1. **Same-image MITM — CLOSED.** The instance key `K` (SHA-256 of the TLS SPKI,
   proven-of-possession by TLS 1.3 CertificateVerify) is folded into the gate
   transcript, and `--attest-allow-instance-key` realizes `Policy says
   K⇒TrustedPeer`. Empty allowlist = closed-membership-by-measurement (stated, not
   silent). `gate.go` / `tunnel.go`.
2. **Manifest linkage — CLOSED (Go side, on the wire).** The manifest digest is
   bound into the gate transcript and scoped to `S`, and Grimlock now **enforces
   every `tools/call` on the wire** against that attested manifest (`mcp.go`,
   `--mcp-enforce`): a call to a tool not in the attested set, or whose capability
   exceeds the grant, is blocked out-of-agent before it reaches the peer. So the
   *enforced* authority is the *attested* authority without trusting either
   endpoint's SDK. An in-SDK `H(live)==attested` check remains available as
   defense-in-depth but is no longer load-bearing.
3. **Payment freshness — CLOSED (for payments).** The attestation epoch is the
   resumption-secret generation (`resumeCache`, bumped on each full gate); it is
   bound into every payment transcript, so a payment commits to which attestation
   covered it and cannot be re-bound under a different epoch. Trust-credential
   freshness for *forwarding* is bounded by the resumption TTL: once it lapses the
   next connection full-gates (re-checking measurement) rather than resuming.
4. **Routing-token linearity — CLOSED.** `origDest.Resolve` is consume-on-read
   (Lookup+Delete); the token is taken exactly once (`origdest.go`).
5. **No silent fallbacks — CLOSED.** Payment binding requires the session
   exporter (no sha512 fallback), and `--x402-bind` hard-requires `--attest` + a
   TD at startup. kTLS→user-space TLS remains a *logged* datapath choice (EKM
   binds either way), not a security fallback.
6. **kTLS handoff invariant — open (P1).** `R-bind` assumes a clean channel; the
   offload assumes `recSeq == 0` (held by `SessionTicketsDisabled` + enabling kTLS
   before any app data). A defensive assert is still desirable.

---

## 12. Implementation shape (as built)

The model is realized **proportionately**, not as a generic theorem prover. For a
fixed single-hop decision `Forward` has exactly one premise per credential kind,
so a generic `Credential`/`SessionContext`/`Authorize(ctx, goal)` engine would be
over-engineering — itself a form of debt. Instead:

- **`internal/authz` is the canonical transcript `T`** — the *one* injective
  encoding through which every binding is constructed (`gate.go` REPORT_DATA and
  `payment.go` payment binding). This is the concrete unification: `T_S` is a real
  object; nothing hand-concatenates digests anymore. Lemma **L2** is property-
  tested (`transcript_test.go`).
- The premises are enforced at their natural points, each fail-closed:
  - `R-bind`/`R-trust`/identity → the gate barrier (`gate.go`): measurement
    (`Verifier`), capability (`CheckPeerAttachment`), instance key
    (`CheckPeerIdentity`), all mutual.
  - `R-cap` → `internal/capability` (the prefix join-semilattice), bound into the
    gate transcript.
  - `R-pay` (linear) → `payment.go`: `MatchesChallenge` + policy + the
    epoch-bound, session-bound `reportData`; the receipt `Proof` is the witness.
  - routing-token linearity → `origdest.go` (consume-on-read).

This keeps the runtime a **typed admission pipeline** (the model's "checker, not
prover") without a baroque framework. If a future multi-hop / delegation feature
arrives (where `hand-off` chains are dynamic), promoting these to an explicit
`Credential`/`Authorize` is the natural next step — but it is not warranted for
the current single-hop topology.

---

## 13. Prior art and the delta

- **ABLP** — *A Calculus for Access Control in Distributed Systems* (Abadi,
  Burrows, Lampson, Plotkin): the `says`/`speaks-for` calculus.
- **DCC** — Abadi, *Access Control in a Core Calculus of Dependency*: the `says`
  monad; proof terms.
- **Nexus NAL** — Schneider, Walsh, Sirer: an OS combining **hardware attestation
  with a `says`-logic**. Closest prior art.
- **FLAM** — Arden, Liu, Myers (CSF'15): principals-as-lattice unifying
  authorization and information flow.
- **PCA** — Appel, Felten: the reference monitor checks a proof.
- **RA-TLS** — binds the endpoint key into `REPORT_DATA` (basis of the `K`
  premise).
- **Channel binding** — RFC 9266 `tls-exporter`; **cuckoo attack** — Parno '08.

**Delta.** The `says`-logic is not the contribution. The contribution is the
**composition**: *session- and epoch-scoped principals via TLS channel binding*,
the **substructural (linear) treatment of payments and routing**, and
**transparent eBPF interposition** that lets unmodified A2A agents inherit this
authorization. The novelty over Nexus is session/epoch scoping for transparent
inter-agent trust; over FLAM, the cryptographic realization of the principals;
over RA-TLS, the payment + capability fragments folded into one judgment.

---

## 14. Notation

| Symbol | Meaning |
|---|---|
| `P says φ` | principal P asserts φ |
| `P ⇒ Q` | P speaks-for Q (delegation) |
| `P \| S` | P scoped to session S (channel binding) |
| `P @ e` | P at epoch e (freshness) |
| `!φ` | persistent (reusable within epoch) |
| `Δ ⊢ φ` | φ derived using linear (one-shot) resources |
| `↓G` | downward closure of granted set G (capability ideal) |
| `EKM_S` | RFC 9266 TLS exporter for session S |
| `T(·)` | canonical injective transcript encoding |
| `Golden` | the set of accepted measurement vectors |
