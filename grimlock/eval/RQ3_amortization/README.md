# RQ3. How much does resumption amortize attestation?

The first connection to a peer runs a full attestation gate; later connections within
the interval resume with a keyed exchange in place of a quote. We measure the setup
latency of each and the amortized cost across successive connections.

## Method

`BenchmarkSetup_FullGate` and `_Resume` establish an attested tunnel over real TLS and
kernel TLS. In smoke mode the quote is a stub, so these measure the protocol cost,
that is the round trips and the keyed exchange, without the quote-generation constant.
On a trusted domain the same benchmark includes the real quote-generation cost, which
is the one hardware-measured value; add it to the full gate to get the deployed setup
latency.

## Metrics

Setup latency for full gate, resume, and a plain TLS handshake. The amortized cost
across the first N connections. On a trusted domain, the real quote-generation and
verification cost, reported as a constant.

## Run

```
./run.sh                     # protocol cost of gate vs resume (stub quote)
GRIMLOCK_TDX=1 ./run.sh      # adds the real quote-generation constant
```
