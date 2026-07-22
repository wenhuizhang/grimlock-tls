# RQ6. What does Grimlock add to a realistic paid tool call?

The end-to-end question. Two agents run a task that invokes a priced tool and pays for
it. We report the latency Grimlock adds by request type and confirm the security
properties hold live.

## Method

Smoke mode confirms the full datapath composes without a trusted domain: two tunnel
managers, a real mutual-TLS session with kernel TLS where the kernel supports it, and
a forwarded request to a local echo agent (`TestE2E_CAModeForwards`,
`TestE2E_CAModePoolConcurrent`), plus the attested resumption path over a real session
(`TestE2E_AttestedResumption`). This shows the mechanism end to end; it does not use
real quotes or a settlement path.

Full mode runs the two demo agents on a trusted domain with a real facilitator and a
testnet, and reports:
- added latency for setup, tool listing, a tool call, and a payment;
- a baseline run without Grimlock for the same task;
- that A1, A2, and A8 hold live during the run.

## Metrics

Per-request-type latency added by Grimlock, against a no-Grimlock baseline, and the
security outcomes observed during the run.

## Run

```
./run.sh                                   # smoke: CA-mode datapath end to end
GRIMLOCK_TDX=1 GRIMLOCK_PEER=host ./run.sh # full: agents, facilitator, testnet
```
