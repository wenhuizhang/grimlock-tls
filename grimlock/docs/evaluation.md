# Evaluation (no TDX required)

Microbenchmarks that quantify the two headline systems claims — a kernel-fast
data plane and amortized attestation — plus the interception tax. All run on this
host (Linux 6.18, loopback) via Go benchmarks in `cmd/grimlock/`; the eBPF one is
root-gated. Numbers are medians of ≥3 runs; treat them as **order-of-magnitude**,
not vendor figures (loopback, single box, warm caches).

Reproduce:

```
go test ./cmd/grimlock/ -run '^$' -bench 'BenchmarkDataPlane|BenchmarkSetup' -benchmem
go test -c -o /tmp/grim.test ./cmd/grimlock/ && \
  sudo /tmp/grim.test -test.run '^$' -test.bench BenchmarkConnect4_Overhead -test.benchtime=3000x
```

## 1. Data plane — splice vs. userspace copy (the "kernel fast path")

`BenchmarkDataPlane_Splice` vs `_UserCopy` move 8 MiB through the production
`relay` over identical loopback TCP; the only difference is whether the concrete
`*net.TCPConn` is visible (so `io.Copy` takes `splice(2)`) or hidden behind a
wrapper (forcing a userspace buffer copy).

| Path | Throughput (median) | Range | Notes |
|---|---|---|---|
| **splice(2)** | **~3.35 GB/s** | 2.9–3.7 GB/s | zero userspace copy (strace-confirmed), no plaintext in userspace |
| userspace copy | ~2.16 GB/s | 1.3–2.6 GB/s | bytes traverse the Go heap; wider tail (GC/scheduler) |

**Reading it honestly.** ~1.55× median throughput, and — as important for a data
plane — a **tighter distribution** (splice avoids the heap entirely, so no GC/copy
tail). On loopback the two TCP traversals dominate, so this *understates* the
cross-NIC benefit; the durable wins are (a) bytes never enter userspace
(confirmed via `strace`, `splice(...) = 19`), so the daemon sees no plaintext and
spends ~no CPU on data movement, and (b) lower tail latency. See
[validation.md](validation.md) for the strace evidence.

## 2. Attestation setup — resume vs. full gate (amortization)

`BenchmarkSetup_FullGate` vs `_Resume` establish an attested tunnel over real
TLS + kTLS. The quote is a **stub** (~0), so these measure the *protocol* cost
only; a real TDX quote (~tens of ms) is **additive to the full gate and absent
from resume**.

| Path | Establish latency (protocol only) | + real TDX quote |
|---|---|---|
| full gate | ~2.0 ms | **+ quote-gen (~tens of ms)** |
| **resume** | **~1.81 ms** | — (no quote) |

**Reading it honestly.** At the protocol level resumption is ~10% cheaper (it
swaps a quote-exchange round-trip for an HMAC). The decisive win is what the stub
hides: resumption removes quote generation from the critical path entirely, so on
a real TD a warm (resumed) connection is roughly an **order of magnitude** faster
to establish than a full gate. This is the amortization the design buys while
keeping every tunnel spliceable (no multiplexer).

## 3. Interception tax — connect4 overhead

`BenchmarkConnect4_Overhead` (root-gated) compares `connect()/close()` latency
with and without the `connect4` program attached to the process's cgroup.

| | Latency per connect/close |
|---|---|
| baseline (no eBPF) | ~34–40 µs |
| **connect4 attached** | ~30–34 µs (within noise) |

**Reading it honestly.** The hook adds **no measurable per-connection overhead**:
its work (a handful of map lookups + guards) is sub-microsecond, dwarfed by the
~35 µs `connect()/close()` syscall cost. Unbypassable interception is effectively
free on the connection-setup path, and touches nothing on the data path (that's
`splice`, §1).

## What this does not measure (needs a TD or more hardware)

- **Real quote-gen/verify latency** — the one TD-measured constant (cited, not
  measured here); it is additive to §2's full gate only.
- **Cross-NIC throughput** — loopback understates §1; a two-host run over a real
  NIC would show the splice/no-copy benefit more strongly.
- **Sustained multi-connection CPU** — the "~no data-plane CPU" claim from §1 is
  argued from zero-copy (strace) rather than measured under many concurrent flows.
