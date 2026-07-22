# Categorical Semantics of the Grimlock Authorization Logic

> The deepest unifying object. [model.md](model.md) gives the *proof theory*
> (a substructural `says`-logic with a persistent `!`-fragment and a linear
> `Δ`-fragment). This document gives its *denotational semantics*: a single
> **symmetric monoidal closed category** in which persistent facts, one-shot
> resources, session-scoping, and multi-hop delegation are all one structure.
> This is what makes "composition is free" a theorem rather than a slogan.

## 1. Why a category

The logic already unified five subsystems into one judgment. But a proof theory
still leaves two questions a reviewer will ask:

1. *When are two derivations "the same"?* (Needed to say a refactor is sound.)
2. *Why does composition — across requests, across hops — preserve everything?*

A **denotational model** answers both: interpret propositions as **objects**,
derivations as **morphisms**, and "the same proof" as "equal morphisms." Then
composition of authorizations is literally composition of morphisms `∘`, and its
good behaviour (associativity, coherence) is inherited from the category, for
free. The right category for our persistent/linear split is a **symmetric
monoidal closed category (SMCC) with a linear–non-linear (LNL) adjunction**
(Benton's model of DILL) — the standard semantics of exactly the logic we chose.

## 2. The category `𝒢`

- **Objects** `A, B, …` — resource/proposition types: `Trust`, `Cap(c)`,
  `Pay`, `Route`, `Forwarded`, and the unit `I` ("no resource").
- **Morphisms** `f : A → B` — *evidence transformers*: a derivation that, given
  evidence of `A`, produces evidence of `B`. Identity `id_A` and composition
  `g ∘ f` (do `f`, then `g`).
- **Equality of morphisms** — two derivations are equal iff they induce the same
  transformer. This is the semantics of "these two implementations authorize the
  same thing."

Composition `∘` is the interpretation of the logic's **cut** rule. That cut
eliminates (proofs compose) is exactly that `𝒢` is a category (associativity +
identities). *This is the "composition is free" claim, made precise.*

## 3. Two fragments: linear (⊗) and persistent (!)

`𝒢` is **symmetric monoidal**: a tensor `A ⊗ B` ("hold `A` and `B`, each spent
once") with unit `I`, symmetric and associative up to coherent isomorphism. The
tensor is the home of the **linear** resources:

```
Pay      -- an authorized payment (one 402-challenge + one EIP-3009 nonce, consumed)
Route    -- the cookie→port routing token (taken once)
Nonce_e  -- a gate freshness nonce
```

Crucially, in the monoidal fragment there is **no diagonal** `A → A ⊗ A` and **no
projection** `A ⊗ B → A`: you cannot duplicate or discard a linear resource. That
is precisely why a payment cannot be double-spent and a routing token cannot be
replayed — the *category has no morphism* that would let you.

The **persistent** facts live in a cartesian sub-part. Let `𝒞` be a cartesian
closed category (products `×` with diagonal `Δ_A : A → A×A` and projections —
i.e. *copyable, discardable* facts) and let

```
        F
   𝒞  ⇄  𝒢         F ⊣ G,   ! := F ∘ G   (a comonad on 𝒢)
        G
```

be a symmetric monoidal adjunction (the LNL structure). Then `!A` is the
"infinitely reusable `A`," carrying a comonoid structure `!A → I` (discard) and
`!A → !A ⊗ !A` (duplicate). The persistent facts sit here:

```
!Measured(M)     !ManifestLinked(Man)     !Grant(↓G)     !Trust
```

They may be used by *every* request in an epoch — that is the categorical content
of "reuse within an epoch."

> **One picture:** the `!`/`Δ` split from `model.md §0` is exactly the
> `𝒞`-fragment vs the `𝒢`-tensor. The logic's two zones are the two halves of an
> LNL model.

## 4. The generators (Grimlock as a presented category)

`𝒢` is *presented* by the model's rules as generating morphisms:

| Rule | Morphism |
|---|---|
| `R-bind` (quote over EKM) | `bind : QuoteEvidence ⊸ !Measured(M) ⊗ !Instance(K)` |
| `R-trust` (measurement + allowlist) | `trust : !Measured(M) ⊗ !Allowed(K) → !Trust` |
| `R-cap` (prefix covering) | `cap_c : !Grant(↓G) → !Cap(c)` for `c ∈ ↓G` |
| `R-pay` (challenge + policy) | `pay : Challenge ⊗ Nonce → Pay` (linear: inputs consumed) |
| routing | `route : Cookie ⊸ Route` |
| **`R-forward`** | `fwd : !Trust ⊗ !Cap(req) ⊗ Pay ⊗ Route ⊸ Forwarded` |

`Forward` is admissible for a request iff there is a morphism `I → Forwarded`
built from these generators — i.e. the daemon can *construct the arrow*. The
persistent inputs (`!Trust`, `!Cap`) can be supplied by `!`-duplication; the
linear inputs (`Pay`, `Route`) are supplied exactly once. `fwd` being a `⊸`
(linear hom) that *consumes* `Pay ⊗ Route` is the categorical statement of "each
forward spends one payment and one routing token."

## 5. Closed structure = delegation (`speaks-for`)

`𝒢` is **closed**: for objects `A, B` there is an internal hom `A ⊸ B` with the
natural bijection

```
    Hom(C ⊗ A, B)  ≅  Hom(C, A ⊸ B)          (currying)
```

`A ⊸ B` is a *first-class delegable authority*: "given `A`, produce `B`." This is
the semantics of `P ⇒ Q` (`speaks-for`): a delegation is a morphism you can pass
around and apply later. `hand-off` (`P says φ, P⇒Q ⊢ Q says φ`) is **evaluation**
`(A ⊸ B) ⊗ A → B`. Delegation being a *value in the category* is what lets
multi-hop authority be built and attenuated (§7).

## 6. Session and epoch as a grading

Trust is not global; it is scoped to `(S, e)`. Model this as a **graded** (indexed)
monoidal category: a lax monoidal functor

```
    ⟦-⟧ : (Sessions × Epochs, ≤)  →  𝒢
```

from the poset of sessions and (monotone) epochs into `𝒢`. An object `A@⟨S,e⟩`
lives in the fibre over `(S,e)`. The grading gives freshness *for free*:

- `!Trust @⟨S,e⟩` and `!Trust @⟨S,e'⟩` are objects in **different fibres** for
  `e ≠ e'`; there is no coincidental morphism between them, so a stale credential
  cannot feed a current `fwd`. (This is `model.md`'s "different principal for
  different epoch," categorified.)
- Re-attestation is the transition morphism `!Trust@⟨S,e⟩ → !Trust@⟨S,e+1⟩` along
  `e ≤ e+1`; **make-before-break** (build `e+1` before discarding `e`) is exactly
  its factorization through the drain state.
- The EKM channel binding is the *fibration itself*: `⟦-⟧` is only defined on the
  fibre `S` for a party that possesses `EKM_S`. Nothing outside the session even
  has objects there — the categorical form of "no cross-session evidence."

## 7. The payoff: multi-hop is composition

For a chain `A → B → C`, hop-1 yields a delegation `d₁ : I ⊸ (Cap_B ⊸ Forwarded_B)`
and hop-2 a delegation `d₂ : Cap_B ⊸ (Cap_C ⊸ Forwarded_C)`. The end-to-end
authority is the **composite**

```
    d₂ ∘ d₁  :  I  ⊸  (Cap_C ⊸ Forwarded_C)
```

built by ordinary morphism composition and internal-hom evaluation. Two structural
facts fall out with no extra work:

1. **Attenuation is functorial.** Capability along the chain is the composite of
   the `cap_c` morphisms; since each maps into a *sub-ideal* (`c ∈ ↓G`),
   composition can only shrink authority — `↓(G_C) ⊆ ↓(G_B) ⊆ ↓(G_A)`. There is
   no morphism that *grows* the ideal, so **no hop can escalate** what an earlier
   hop granted. (This is T4, made compositional.)
2. **Linear resources don't duplicate across hops.** `Pay` and `Route` are
   tensor objects with no diagonal, so a payment authorized for hop A→B cannot be
   silently reused for B→C — a fresh `Pay` is required at each linear step.

This is the concrete reason the `says`-logic (not four `if`s) is worth it: the
multi-hop guarantees are *theorems of the category*, obtained by composing the
same generators, rather than new code to audit per hop.

## 8. Soundness of the interpretation

Let `⟦-⟧` send each proposition to its object and each derivation to its morphism.
Standard LNL/SMCC soundness gives:

```
    Γ ; Δ ⊢ φ    (derivable)    ⟹    a morphism   ⟦!Γ⟧ ⊗ ⟦Δ⟧ → ⟦φ⟧   exists in 𝒢
```

and **cut is composition**, so provable-equal derivations denote equal morphisms.
The security property `model.md §9` "`Forward` ⟹ (fresh, bound, authorized …)"
is then the statement that **every** morphism `I → Forwarded@⟨S,e⟩` factors
through the generators `bind, trust, cap, pay` at `⟨S,e⟩` — a *structural*
property of the presented category, discharged once. The implementation is sound
iff the Go `authorize` pipeline (`model.md §12`) realizes only these generators
and their composites — which is why the runtime is a *typed admission check*, not
an arbitrary program: it must be a morphism of `𝒢`.

## 9. What this buys, concretely

- **Multi-hop for free** (§7) — the single biggest reason to keep the logic.
- **A refactor oracle**: any code change that preserves the *morphism* it denotes
  is provably behaviour-preserving; one that doesn't, isn't.
- **No-duplication by construction**: double-spend / token-replay are *absent
  morphisms*, not runtime checks that could be forgotten.
- **A clean statement of freshness** as a grading, unifying epochs, re-attestation
  (make-before-break), and channel binding (the fibration) in one structure.

## 10. Prior art

- **Benton**, *A mixed linear and non-linear logic* (LNL models) — the SMCC + CCC
  adjunction used here.
- **Seely / Bierman** — categorical models of linear logic and the `!` comonad.
- **Melliès** — categorical semantics of linear logic (reference treatment).
- **Abadi, "Access control in a core calculus of dependency" (DCC)** — the `says`
  monad, whose categorical reading meets this one at the persistent fragment.
- **Curry–Howard–Lambek** — the proofs-as-morphisms correspondence this rests on.
