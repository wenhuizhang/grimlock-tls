# Grimlock — machine-checked core (Coq)

`Grimlock.v` is a **complete, axiom-free** Coq 8.20 development of the parts of
the authorization model ([../docs/model.md](../docs/model.md)) that need **no**
cryptographic assumption. Every theorem below is proved to `Qed` and reports
`Closed under the global context` (no `Admitted`, no axioms).

## What is proved

| Theorem | Model ref | Meaning |
|---|---|---|
| `transcript_injective` | L2 | distinct binding-field sequences → distinct encodings (so "the quote commits to exactly these fields" is sound) |
| `covered_monotone` | T4 | adding grants never removes a permission (monotonicity) |
| `covered_attenuation` | T4 / §7 | a delegate holding a **subset** of grants permits no more — the multi-hop non-escalation property |
| `no_grant_denied` | T4 | no covering grant ⇒ denied (**fail-closed**) |
| `covered_refine` | T4 | a broad grant permits every more-specific request beneath it |

These mirror the Go implementation: `transcript_*` ↔ `internal/authz`,
`covered_*` ↔ `internal/capability` (the dot-prefix covering).

**Bound to the code, not just mirrored.** `internal/capability/property_test.go`
and `internal/authz/property_test.go` assert each of these theorems
(`covered_monotone`, `covered_attenuation`, `covered_refine`, no-grant-denied,
transcript injectivity) on the **actual Go functions** over tens of thousands of
random inputs, plus an independent-oracle differential and targeted
concatenation-ambiguity cases. Mutation-checked: making `capCovers` over- or
under-permissive, or dropping the transcript length prefix, **falsifies** the
corresponding property — so the proofs constrain the shipped implementation, not
a paper abstraction.

## The assumption boundary (honest)

This development deliberately proves **only** the crypto-free core. The security
of quotes, the TLS exporter, signatures, and hash collision-resistance are the
**stated assumptions** of [../docs/threat-model.md §6](../docs/threat-model.md);
they belong in Tamarin (protocol) / EasyCrypt (computational), not here. That
split is intentional — the capability lattice and transcript injectivity are the
theorems that are *fully dischargeable now with zero axioms*, so they are the
ones proved in Coq. The protocol-level security (below) is machine-checked in
Tamarin, under the standard symbolic (Dolev-Yao) crypto assumptions.

## Protocol proofs (Tamarin)

Symbolic models of the two attestation handshakes, all lemmas machine-verified
(`make tamarin`):

| Model | Lemma | Meaning |
|---|---|---|
| `resumption.spthy` | `resume_agreement` | a client that accepts a resume agrees with the server on the **same session bind** — unless RS is compromised. Agreement on the bind **is** relay/cuckoo resistance, and holds even if the adversary reveals every session exporter (knowing the EKM does not help without RS). |
| `resumption.spthy` | `resume_injective` | **injective** agreement (no replay): each client acceptance maps to a *unique* server run on the same `(RS, bind)` — a captured tag cannot drive two acceptances. |
| `resumption.spthy` | `rs_secret` | the resumption secret stays secret unless explicitly compromised. |
| `gate.spthy` | `gate_binding` | a party that accepts a peer quote on session `ekm` agrees the peer **quoted for that same `ekm`** — unless the peer's attestation key is stolen. A quote captured from another session (different `ekm`) is never accepted → relay/cuckoo resistance of the gate. |
| `gate.spthy` | `mutual_barrier` | a party **forwards only if the peer also accepted it** (reached `GateOK` on the same `ekm`) — the honest-risk "both-or-neither" property; neither side emits data on a peer it, or that, rejected. |

Both models carry an `executable` (exists-trace) lemma so the protocol is proved
non-vacuous, and pass all wellformedness checks. Roles are fixed per session
(dialer = client, listener = server), matching the implementation; the adversary
is full Dolev-Yao with exporter- and key-reveal rules.

**The lemmas have teeth** — mutation-tested: collapsing the directional
`client`/`server` tags (enabling reflection), unbinding a tag/quote from its
session, or dropping the ACK check each **falsifies** the corresponding lemma, so
none is vacuously true and each security mechanism is provably load-bearing.

## Modeling notes

- Capabilities are modeled as **segment lists** (`["fs";"read"]`), and dot-prefix
  covering as **list prefix** — a faithful abstraction of the string dot-prefix
  in `internal/capability`.
- The transcript length prefix is modeled as a **single self-delimiting symbol**
  rather than the real fixed-width 4-byte big-endian length. The injectivity
  argument is identical (a self-delimiting injective length code); this keeps the
  proof axiom-free and self-contained.

## Check it

```sh
make          # coqc Grimlock.v  → Grimlock.vo
make axioms   # prints "Closed under the global context" for each theorem
make tamarin  # prove resumption.spthy + gate.spthy (all lemmas "verified")
make clean
```

Requires `coqc` ≥ 8.16 (developed on 8.20.1) and, for `make tamarin`,
`tamarin-prover` (developed on 1.10.0).
