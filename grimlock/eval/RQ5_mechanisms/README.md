# RQ5. Do the kernel mechanisms behave as claimed on a real kernel?

The design rests on three kernel mechanisms: socket interception that redirects, a
kernel-TLS data path that engages, and a zero-copy splice. These are not TDX
features; they run on a stock kernel. We validate each behaviorally under root.

## Method

Root-gated Go tests exercise the real kernel:
- interception: a connection to an unreachable governed peer lands on the local proxy,
  which shows the redirect fired (`TestEBPF_Connect4Redirects`).
- verifier acceptance and attach (`TestEBPF_LoadAndAttach`).
- kernel TLS engages, so the tunnel data plane is a raw socket (`TestKTLS_Engages`).
- the relay moves bytes with splice (`TestSplice_TCPToTCP`, confirmed under strace).

## Metrics

Each is a pass or fail on the running kernel, plus the strace evidence for splice.

## Run

```
sudo -v && ./run.sh
```

This is a full result on any recent kernel; it does not need a trusted domain.
