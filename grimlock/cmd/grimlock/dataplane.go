// Control plane vs data plane.
//
// The CONTROL plane runs ONCE to decide whether bytes may flow: the eBPF
// redirect, the attestation gate (measurement + instance key + agent measurement
// + capability), and — per request — the x402 payment authorization. It is the
// only place trust is established.
//
// The DATA plane is this file: once a flow is authorized, the daemon gets out of
// the steady-state path. For an authorized non-payment flow over a *dedicated*
// kTLS tunnel both endpoints are *net.TCPConn (the agent's redirected socket and
// the raw kTLS tunnel socket), so relay() lands on Go's splice(2) fast path — the
// kernel moves bytes socket-to-socket with no userspace copy. Steady-state cost
// is then ≈ a kernel splice, not a userspace proxy.
//
// TRADEOFF (a real architectural finding). Multiplexing and zero-copy are in
// tension: a mux (yamux) stream must be demultiplexed in userspace, so it cannot
// splice; a dedicated tunnel can splice but pays one quote per flow. So:
//   - dedicated + splice  → amortize nothing, but zero-copy data plane (best for
//                            few high-throughput flows);
//   - mux                 → amortize the quote across many streams, but userspace
//                            copy (best for many small requests).
// The per-peer channel already negotiates mux; a throughput-aware policy could
// prefer dedicated+splice for bulk flows. x402-enforced flows are always parsed
// (necessarily on the path).

package main

import (
	"io"
	"net"
)

// relay copies src→dst until EOF. When both ends are *net.TCPConn (the dedicated
// kTLS case) Go's io.Copy dispatches to splice(2) — a zero-copy kernel
// socket-to-socket move; otherwise it falls back to a buffered copy.
func relay(dst, src net.Conn) (int64, error) {
	return io.Copy(dst, src)
}

// spliceable reports whether the zero-copy fast path applies to a pair of conns
// (both raw TCP). Used for observability so an operator can see when a flow is on
// the kernel fast path vs a userspace copy.
func spliceable(a, b net.Conn) bool {
	_, ok1 := a.(*net.TCPConn)
	_, ok2 := b.(*net.TCPConn)
	return ok1 && ok2
}
