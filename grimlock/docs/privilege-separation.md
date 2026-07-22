# Privilege Separation

> Align the systems architecture with the formal one: shrink the TCB to the thing
> we can actually prove. The Forward decision is a small, pure, fixed-shape
> function; it should run as an isolated, minimally-privileged component, not
> woven through a daemon that also holds keys and moves bytes.

## Current TCB (one blast radius)

Today one process does everything: loads/attaches eBPF (needs `CAP_BPF` /
`CAP_NET_ADMIN`), terminates TLS and holds the ephemeral key, generates/verifies
TDX quotes, **decides** `Forward`, and moves bytes. A compromise of any part
compromises all of it.

## The certified core is already pure

The authorization *appraisals* are already side-effect-free functions with no I/O
and no keys — exactly the certified core:

| Appraisal | Package | Purity |
|---|---|---|
| measurement policy | `attest.TDXVerifier.Verify` | pure over (quote bytes, expected rd) |
| capability covering / attenuation | `capability.Check` / `Attenuate` | pure; Coq-proved (`formal/`) |
| payment policy | `x402.Enforcer.Evaluate` + challenge match | pure over the payment |
| transcript binding | `authz` transcript | pure; Coq-proved injective |

The impure parts — socket I/O, TLS, `configfs-tsm` quote generation, eBPF — are
the *data/evidence-gathering* plane. This is the natural cut.

## Target architecture

```
        ┌─────────────────────────┐        ┌──────────────────────────────┐
        │  unprivileged MOVER      │  IPC   │  certified CORE (jailed)     │
        │  eBPF I/O, TLS, sockets, │◀──────▶│  the pure appraisals +       │
        │  quote gen, byte relay   │ evidence│  Forward decision; no keys,  │
        │  (data plane)            │ verdict │  no sockets (control plane)  │
        └─────────────────────────┘        └──────────────────────────────┘
```

The mover collects evidence (peer quote, exporter value, manifest, payment) and
asks the core for a verdict over a typed message; the core runs only the pure
appraisals and returns accept/deny + the proof (receipt witness). The core needs
**no** ambient authority — it can be `seccomp`-jailed to a handful of syscalls,
run in a separate user namespace, a separate process, or even its own TD.

## Linux mechanisms (in increasing isolation)

1. **`no_new_privs`** — *implemented* (`hardening.go`): a compromised daemon
   cannot escalate by exec'ing a setuid/file-capability binary. Safe, irreversible.
2. **Capability drop after attach** — the daemon needs `CAP_BPF`/`CAP_NET_ADMIN`
   only during eBPF attach; drop the bounding set + effective caps afterward.
   (Per-thread in Go; do via `libcap`/`prctl(PR_CAPBSET_DROP)` on all runtime
   threads, or fork the attach into a short-lived privileged child.)
3. **`seccomp-bpf` filter** — after setup, restrict syscalls to the working set
   (`SECCOMP_FILTER_FLAG_TSYNC` for all threads). The Go runtime's syscall set
   must be profiled on the target — hence this is validated on the deployment
   host, not shipped blind.
4. **Process split** — run the core as a separate, jailed process communicating
   over a `socketpair`; the mover holds keys/sockets, the core holds none.
5. **TD split** — the strongest: the core in its own TD, so even the mover's TD
   compromise cannot forge a verdict.

## Why this matters for the paper

The formal artifact (`formal/`) proves the *core's* decision. Privilege
separation makes that core a **real isolated component**, so "we proved the
authorization kernel" is a statement about a thing with a small, enforced TCB —
not about a function buried in a large privileged process. The systems
architecture then *mirrors* the formal one.

## Status

- **Implemented (safe, in-process):** `no_new_privs`.
- **Deployment-validated (needs the target host / TDX env):** capability drop,
  seccomp filter, process/TD split. These require profiling the Go runtime's
  syscall set and testing the daemon under restriction on the real host, so they
  are done on the deployment environment rather than shipped unvalidated.
