# Evaluation harness

Each research question has a directory with a `README.md` (the question, method, and
baselines) and a `run.sh` (the experiment). Results are written to `results/`, which
is not committed.

The harness runs now, without a trusted domain, in a smoke mode that exercises the
real code paths with a stub quoter over real sessions and loopback where a second
host is absent. When a trusted domain, root, or a second host is available, the same
scripts run the full experiment. A step that needs a capability it does not have
prints what it needs rather than passing silently, so once the trusted domain is up
`./run.sh` produces the full result with no change to the scripts.

Run one question, or all:

```
eval/RQ1_security/run.sh
for d in eval/RQ*/; do "$d/run.sh"; done
```

Enable full modes:

```
sudo -v                      # root steps (interception, seccomp, kernel checks)
GRIMLOCK_TDX=1  ...          # real attestation quotes on a trusted domain
GRIMLOCK_PEER=host ...       # cross-host data-plane and end-to-end runs
```

## Research questions

- RQ1 security. Does Grimlock block the attacks that the baseline controls do not?
  This is the paper's core result. The attack harness drives each attack through the
  production enforcement paths.
- RQ2 data plane. What is the throughput and CPU cost of a fast channel (kernel
  splice) versus a guarded channel versus an unenforced connection?
- RQ3 amortization. How much does resumption save over a full attestation gate, and
  how does the amortized cost fall across successive connections?
- RQ4 enforcement. What per-request latency does the guarded pipeline add for
  payments, for tool capabilities, and for both composed?
- RQ5 mechanisms. Do the kernel mechanisms behave as claimed on a real kernel:
  interception redirects, kernel TLS engages, and the data path splices?
- RQ6 end to end. What latency does Grimlock add to a realistic agent-to-agent paid
  tool call, and do the security properties hold live?

## What is smoke now and what needs the trusted domain

| Question | Smoke now | Full needs |
|---|---|---|
| RQ1 | attacks A1 to A3, A5 to A11 (stub quote, real paths) | A4, A10 need root; A5, A6 real-quote variants need a TD |
| RQ2 | loopback throughput and CPU | cross-host over a real NIC |
| RQ3 | protocol cost of gate vs resume | the real quote-generation constant |
| RQ4 | full result | none |
| RQ5 | (needs root now) | none beyond root |
| RQ6 | CA-mode datapath end to end | a TD, a facilitator, and a testnet |
