# Validation status — what's proven, and where

The datapath's kernel mechanisms are **not** TDX-gated; they are ordinary Linux
features and are validated here on a real kernel. TDX is required only for the
attestation **quote** content. This page records exactly what has been exercised,
with reproducible commands, so "production ready" is a claim backed by evidence
rather than assertion.

## Validated on a real kernel (Linux 6.18, no TDX)

All of the following run in-repo. The kernel-privileged ones are root-gated (they
`t.Skip` as non-root); build the test binary once and run it under sudo:

```
go test -c -o /tmp/grim.test ./cmd/grimlock/
sudo /tmp/grim.test -test.run 'TestEBPF|TestKTLS|TestSplice' -test.v
```

| Mechanism | Test | What it proves |
|---|---|---|
| **eBPF verifier load + attach** | `TestEBPF_LoadAndAttach` | `connect4` + `sock_ops` load into the kernel (verifier accepts them) and attach to a cgroup. |
| **connect4 redirect (behavioral)** | `TestEBPF_Connect4Redirects` | With `config.enabled` + `agent_ports` + `agent_peers` populated, a dial to an **unreachable** peer (`192.0.2.1:8080`) **lands on `127.0.0.1:15001`** — the kernel actually rewrote the destination. |
| **kTLS engages** | `TestKTLS_Engages` | After `enableKTLS`, the tunnel data plane is a raw `*net.TCPConn` — the kernel (not userspace) does the TLS crypto. |
| **splice zero-copy** | `TestSplice_TCPToTCP` | `relay` between two `*net.TCPConn` moves bytes with **`splice()`** — confirmed by `strace -e trace=splice` showing `splice(...) = 19` (socket→pipe→socket, no userspace copy). |

The full request path runs end-to-end in CA mode and under warm-pool concurrency
(`TestE2E_CAModeForwards`, `TestE2E_CAModePoolConcurrent`), and — importantly —
the **attestation gate + resumption protocol runs over real kTLS**
(`TestE2E_AttestedResumption` passes with kTLS engaged): first connection
full-gates and caches a secret, the second resumes (no quote) and inherits the
same epoch. Only the quote *content* is stubbed; mode negotiation, EKM binding,
the HMAC resume handshake, and the cross-kTLS/userspace framing are all real.

Reproduce the splice syscalls directly:

```
strace -f -e trace=splice -o /tmp/splice.trace /tmp/grim.test -test.run TestSplice_TCPToTCP
grep 'splice(' /tmp/splice.trace     # → splice(...) = 19  (the payload size)
```

## Still needs a TDX TD (quotes only)

- **Real quote generation/verification**: `configfs-tsm` quote gen, ECDSA + PCK
  chain to the Intel root, measurement-policy evaluation. The `Quoter`/`Verifier`
  interfaces are wired and exercised with stubs; on a TD, swap in `ConfigfsQuoter`
  + `TDXVerifier` (already implemented) — no protocol change.
- That is the **only** remaining hardware dependency. eBPF, kTLS, and splice are
  proven above without it.

## Out of scope of this repo (deliberate boundaries)

- **x402 facilitator client** (`/verify`, `/settle`) — Grimlock observes
  settlement from `X-PAYMENT-RESPONSE`; it does not drive the facilitator.
- **sock_ops re-keying (behavioral)** — `sock_ops` is verified + attached above;
  its `cookie_dest → port_dest` bridge for multi-peer routing is covered by the
  `origdest` unit tests rather than a kernel behavioral test.
