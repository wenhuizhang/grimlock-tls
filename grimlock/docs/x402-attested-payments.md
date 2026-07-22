# Attested x402 Agent Payments

> System-design notes for the NDSS direction: Grimlock as a transparent,
> attestation-gated enforcement point for x402 (HTTP 402) agent payments.
> Companion to `attestation.md` / `attestation-design.md`.

## The gap this closes

Agent-payment protocols establish *what* a payment is and *whether a user
authorized it*, but not that the **software executing the payment is the
authorized, unmodified agent** — and they cannot stop a **genuine-but-hijacked**
agent (prompt injection) from overspending. The agent's code is unmodified, so
its measurement is unchanged and hardware attestation of the *agent* passes;
A402/AP2/TIVA still authorize the payment.

Grimlock's answer: enforce the spend policy in a **separate measured component
(its own TD)** that the agent's traffic must pass through (eBPF interception
makes it **unbypassable**), and bind each payment to a fresh attestation. Attest
the agent **and** enforce policy outside it.

## Architecture

```
┌ Agent TD (MRTD_agent — LLM, hijack-prone) ┐
│   plain HTTP x402: GET/POST + X-PAYMENT     │  (zero code change)
└───────────────────────┬─────────────────────┘
        eBPF connect4 redirect (UNBYPASSABLE)
                        ▼
┌ Grimlock Enforcer TD (MRTD_policy — small, audited) ┐
│  parse X-PAYMENT → policy gate (F2)                 │  block (403) | forward
│  on allow: bind quote REPORT_DATA=H(domain‖payment) │  (F1)
│  receipt: payment + decision + quote + settle tx    │  (F4, hash-chained)
└───────────────────────┬─────────────────────────────┘
        attested kTLS tunnel → peer Grimlock → payee/facilitator
```

## Mechanisms

### F2 — out-of-agent spend policy (`internal/x402/policy.go`)
The `Enforcer` checks each `X-PAYMENT`: per-payment cap, per-epoch **velocity**,
recipient (`payTo`) allowlist, network allowlist. Denied → the payment is
**blocked with a 403 and never reaches the wire**. Because the enforcer is a
separate measurement on the unbypassable path, a hijacked agent cannot raise its
own limits or route around it. *This is the core novelty vs A402/AP2/TIVA.*

### F1 — per-payment attestation binding (`payment.go`, `internal/x402/binding.go`)
For each allowed payment, Grimlock generates a TDX quote whose
`REPORT_DATA = EKM(transcript)` — the session exporter applied to the one
canonical transcript (`internal/authz`, [model.md](model.md)) committing to:
the **attestation epoch**, the exact HTTP request (`method`/`host`/`path`),
`BindingHash(payment)` (which length-prefix-commits to `network, scheme, from,
to, value, nonce`), the **402-challenge digest**, and the **policy digest**. The
EIP-3009 nonce is single-use and the 402 challenge is consumed once, so the
binding is unique per payment *and* tied to *this* session, epoch, request, and
policy. Binding requires attested mode + a TD (enforced at startup — there is no
non-session-bound fallback). An auditor recomputes the transcript and, with the
session exporter, verifies the quote (signature + PCK chain to Intel root +
measurement policy) — proving *a genuine, policy-matching TD authorized exactly
this payment on this channel*. Reuses the `internal/attest` `TDXVerifier`.

### F4 — tamper-evident receipts (`receipt.go`)
Every decision is a `Receipt` appended to a **hash-chained, append-only** JSONL
log: each entry commits to the previous entry's hash, so any later edit/removal
breaks the chain (`VerifyChain`). A receipt binds: payment terms, policy
decision, the F1 binding quote, and the on-chain **settlement tx** — sniffed from
the response's `X-PAYMENT-RESPONSE` header without altering the response bytes
(a passthrough tee). Non-repudiable and externally verifiable.

## x402 wire handling

Types mirror the canonical x402 **v1** schema (`x402-foundation/x402`); Grimlock
only **parses** (never signs/settles), so it pulls no EVM/crypto deps:
- `402` challenge body → `PaymentRequiredResponse{accepts: []PaymentRequirements}`
- request `X-PAYMENT` → `PaymentPayload{payload.authorization{from,to,value,nonce,…}}`
- response `X-PAYMENT-RESPONSE` → `SettleResponse{success, transaction, …}`

The request direction is parsed and re-emitted (`http.ReadRequest`/`req.Write`)
because enforcement must gate it; responses pass through byte-for-byte and are
only sniffed.

## Flags

| Flag | Meaning |
|---|---|
| `--x402-enforce` | Enable transparent x402 enforcement on agent HTTP |
| `--x402-max-payment` | Per-payment cap (token smallest unit) |
| `--x402-max-epoch` / `--x402-epoch` | Velocity cap and window |
| `--x402-allow-payto` | Recipient allowlist (comma-separated) |
| `--x402-allow-networks` | Network allowlist (e.g. `base,base-sepolia`) |
| `--x402-bind` | Bind each allowed payment to a TDX quote (default true; **requires `--attest` + a TD**, else startup fails — pass `--x402-bind=false` to enforce policy without binding) |
| `--x402-receipt-log` | Append-only receipt log path (empty = stderr) |

## Evaluation plan (NDSS systems track)
- **Security:** the 4-attack catalog — relay (EKM gate), **hijacked-agent overspend** (F2), drift/TOCTOU (continuous re-attest), key theft (in-TD key) — show each blocked, and that A402/AP2/TIVA don't block #2/#3.
- **Performance:** per-payment overhead (parse + policy + binding quote), throughput with attestation-resumption amortization (payments/sec), receipt-log cost; vs no-enforcement and vs A402.
- **Real deployment:** cloud TDX (Azure DCe / GCP C3-confidential) + Base-Sepolia USDC via a facilitator; the two demo agents now *paying* each other.

## Status / limits
- Implemented + unit-tested without a TD: parsing, F2 policy (incl. velocity),
  F1 binding (stub quoter), F4 receipts + chain + settlement sniff.
- The binding quote is generated **inline per payment** (adds quote-gen latency
  ~tens of ms on a real TD) — measured in eval; could be amortized.
- **Facilitator client** (`/verify`,`/settle`) is not yet built — Grimlock
  currently observes settlement from `X-PAYMENT-RESPONSE` rather than driving it.
- Full HTTP-proxy fidelity (chunked/keep-alive/exotic) is prototype-grade; fine
  for A2A JSON-RPC + x402, noted for eval.

## Implementation map
| File | Role |
|---|---|
| `internal/x402/types.go` | canonical v1 wire types |
| `internal/x402/parse.go` | decode `X-PAYMENT` / 402 / settle; `Amount`/`PayTo` |
| `internal/x402/policy.go` | **F2** spend policy + velocity enforcer |
| `internal/x402/binding.go` | **F1** `BindingHash` |
| `cmd/grimlock/payment.go` | HTTP-aware enforcement proxy, binding quote, response sniff |
| `cmd/grimlock/receipt.go` | **F4** hash-chained receipt log |
| `cmd/grimlock/main.go` | `--x402-*` flags, wiring |
