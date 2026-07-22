# RQ2. What does the data plane cost: fast vs guarded vs unenforced?

A fast channel enables kernel TLS and moves bytes with a zero-copy splice, with the
enforcer off the path. A guarded channel parses in userspace. We measure throughput
and CPU for both and for a direct connection, in both directions of the kernel-TLS
path so the receive-side asymmetry is measured rather than hidden.

## Method

`BenchmarkDataPlane_Splice` and `_UserCopy` move a fixed payload through the
production relay over identical loopback sockets, differing only in whether the
splice fast path is taken. Loopback understates the benefit because the two local
traversals dominate; a cross-host run over a real NIC is the full form, enabled with
`GRIMLOCK_PEER`.

## Metrics

Throughput (GB/s) and CPU. Report the guarded lane against the fast lane and against
a direct connection. State the loopback caveat wherever a loopback number appears.

## Run

```
./run.sh                         # loopback throughput
GRIMLOCK_PEER=host ./run.sh      # cross-host over a real NIC (full)
```
