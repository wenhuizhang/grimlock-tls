# RQ4. What does per-request enforcement cost on a guarded channel?

A guarded channel adds a userspace check per request. We measure that added latency
for a payment, for a tool-capability check, and for both composed on one connection,
so the paper can report the cost that falls on control traffic.

## Method

`BenchmarkEnforce_X402`, `_MCP`, and `_Composed` (`cmd/grimlock/bench_enforce_test.go`)
call the production `enforce` path on a parsed request and report nanoseconds and
allocations per request. This is a full result now; it needs no trusted domain.

## Metrics

Per-request latency and allocations for each policy and for the composition. Compare
against the fast-lane passthrough, which does no per-request work.

## Run

```
./run.sh
```
