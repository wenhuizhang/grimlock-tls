# RQ1. Does Grimlock block the attacks that baseline controls do not?

This is the paper's core result (Table 2). Each attack is attempted through the
production enforcement paths and must be blocked. Where a baseline is meaningful, the
same attack is shown to succeed without Grimlock.

## Method

The attack harness is a set of Go tests (`cmd/grimlock/attack_test.go`) that drive
the real enforcers, the attestation gate, the resumption cache, and the hardening.
Each test prints a one-line verdict and asserts the outcome. Interception (A4) and
seccomp (A10) have end-to-end forms that need root; A5 and A6 use a stub quoter over
real sessions in smoke mode and have real-quote forms on a trusted domain.

## Attacks

| Id | Attack | Grimlock defense | Baseline that fails | Smoke |
|---|---|---|---|---|
| A1 | Hijacked agent overspends | out-of-agent payment policy | unenforced proxy forwards | yes |
| A2 | Capability escalation | out-of-agent capability check | unenforced proxy forwards | yes |
| A3 | Call smuggling in a batch | fail-closed parser | naive parser fails open | yes |
| A4 | Route around the enforcer | socket interception | app guardrail | needs root |
| A5 | Quote relay across sessions | session-exporter binding | naive quote check | yes (real quote on TD) |
| A6 | Non-golden measurement | gate appraisal, fail closed | plain mTLS accepts | yes (real quote on TD) |
| A7 | Serve past the interval | both-ends interval bound | none | yes |
| A8 | Payment replay | single-use challenge | facilitator only | yes |
| A9 | Manifest swap | wire check vs attested manifest | SDK check | yes |
| A10 | Co-located secret extraction | non-dumpable, seccomp | ordinary process | needs root |
| A11 | Handshake flood | load-shed and deadlines | unbounded gate | yes |

## Baselines

An unenforced proxy (forwards everything), a naive single-message parser (A3), and
plain mutual TLS with no attestation binding (A5, A6). On a trusted domain we add a
representative payment-authorization protocol as the baseline for A1 and A8.

## Run

```
./run.sh                 # smoke: A1 to A3, A5 to A11
sudo -v && ./run.sh      # adds A4 and A10 end to end
GRIMLOCK_TDX=1 ./run.sh  # adds the real-quote forms of A5 and A6
```

Expected: every attack blocked by Grimlock; the baselines block only the subset that
does not depend on the agent being faithful.
