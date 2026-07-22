# Multi-hop delegation (A → B → C)

> Where the `says`-logic earns its keep. Single-hop needs only four checks; the
> logic pays off when authority is **delegated and attenuated** across a chain.
> The core algebra is implemented and machine-proved; this document specifies the
> onward-tunnel protocol that carries it on the wire.

## What is already real

- **Capability attenuation** — `capability.Attenuate(upstream, local)` computes the
  onward grant as the generating set of `↓upstream ∩ ↓local` (`internal/capability`),
  and `AttenuateChain` folds it across a chain. Tested, and its soundness is the
  Coq theorem `covered_attenuation` (`formal/Grimlock.v`): **no hop escalates
  beyond any earlier grant.** This is the `hand-off` rule as code.
- Everything a single hop needs (gate, EKM binding, instance key, agent
  measurement, epoch, payment binding) is production code.

## The onward-tunnel protocol (design)

B is simultaneously a **server** to A and a **client** to C. When A's request must
reach C, B does not blindly relay: it opens its own attested tunnel to C and
forwards under an **attenuated** authorization.

```
A ──attested tunnel S_AB──▶ B ──attested tunnel S_BC──▶ C
        grant G_A                       grant G_B = Attenuate(G_A, policy_B)
```

Per hop, B:

1. **Terminates and re-originates.** `S_AB` and `S_BC` are independent attested
   sessions with independent EKMs. B is measured+instance-authorized to *both*
   A and C (each end runs the normal gate). There is no transitive TLS — trust is
   re-established, not forwarded.
2. **Attenuates the grant.** The capability B advertises onward to C is
   `Attenuate(G_A, policy_B)` — never more than A granted B, never more than B's
   own policy. C's policy attenuates again. Authority is monotone-decreasing
   (proved).
3. **Carries the provenance, bound.** B's quote to C commits (via the gate
   transcript) to a **hop attachment** recording `⟨H(S_AB-context), G_onward⟩`, so
   C's audit sees the *chain*, not just its immediate predecessor. A downstream
   auditor can replay the chain of quotes and verify each attenuation step.
4. **Delegates payment linearly.** A `Pay` authorized for A→B is **not** reusable
   for B→C (linear resource, no diagonal — `semantics-categorical.md §7`). B→C
   requires either B's own payment or an explicit, freshly-bound **delegated
   payment credential** whose transcript commits to the upstream payment's binding
   hash (so a single logical payment can be traced across hops without being
   double-spent). Design: `reportData` gains an optional `upstream-binding` field;
   the facilitator settles once, the chain references it.

### Why this is sound by construction

- **Capability**: `AttenuateChain` ⇒ `↓G_final ⊆ … ⊆ ↓G_A`; a compromised
  intermediate can only *narrow*. (Coq `covered_attenuation`.)
- **Trust**: each hop is an independent gate; a bad intermediate fails its own
  measurement/instance/agent checks and the chain stops there.
- **Payment**: linearity forbids silent reuse; each linear step needs a fresh,
  bound authorization.
- **Provenance**: each quote commits to the prior hop's context, so the chain is
  auditable end-to-end.

## Categorical reading

The chain is **morphism composition** (`semantics-categorical.md §7`): hop
delegations `d₁, d₂` compose to `d₂ ∘ d₁`, attenuation is functorial (maps into
sub-ideals), and linear resources don't duplicate across the composite. The
multi-hop guarantees are theorems of the category — obtained by composing the
same generators, not new per-hop code to audit.

## Build status

- **Done:** attenuation algebra (`Attenuate`/`AttenuateChain`, tested,
  Coq-proved), and the single-hop primitives it composes.
- **Next (real build, needs the onward tunnel):** B-as-client re-origination with
  the hop attachment + delegated-payment field. Bounded by the existing gate +
  transcript machinery — no new crypto, only wiring B's client path to carry the
  attenuated grant and provenance.
