package main

import (
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair returns the two ends of a connected loopback TCP connection.
func tcpPair(tb testing.TB) (dial, accept net.Conn) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	dial, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}
	return dial, <-ch
}

// opaqueConn hides the *net.TCPConn identity so io.Copy cannot take the splice
// fast path (via ReadFrom), forcing a userspace buffer copy over the same socket.
// This isolates the splice benefit on an otherwise identical transport.
type opaqueConn struct{ net.Conn }

func benchRelay(b *testing.B, wrap func(net.Conn) net.Conn) {
	inDial, inAcc := tcpPair(b)   // producer writes inDial; relay reads inAcc
	outDial, outAcc := tcpPair(b) // relay writes outDial; consumer drains outAcc
	defer inDial.Close()
	defer inAcc.Close()
	defer outDial.Close()
	defer outAcc.Close()

	go relay(wrap(outDial), wrap(inAcc)) // outDial <- inAcc (the production data plane)

	const chunk = 8 << 20 // 8 MiB
	payload := make([]byte, chunk)
	b.SetBytes(chunk)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		done := make(chan struct{})
		go func() { io.CopyN(io.Discard, outAcc, chunk); close(done) }()
		if _, err := inDial.Write(payload); err != nil {
			b.Fatal(err)
		}
		<-done
	}
}

// BenchmarkDataPlane_Splice measures the production relay between two *net.TCPConn
// (client-side topology: agent socket ↔ kTLS tunnel socket) — kernel splice(2).
func BenchmarkDataPlane_Splice(b *testing.B) {
	benchRelay(b, func(c net.Conn) net.Conn { return c })
}

// BenchmarkDataPlane_UserCopy is the same transport with the splice path defeated
// (userspace buffer copy) — the daemon-on-the-path cost splice avoids.
func BenchmarkDataPlane_UserCopy(b *testing.B) {
	benchRelay(b, func(c net.Conn) net.Conn { return opaqueConn{c} })
}

// BenchmarkSetup_FullGate measures attested tunnel establishment running a full
// gate every time (real TLS + kTLS + mutual quote-exchange protocol; the quote
// itself is a stub, so this is the protocol cost WITHOUT the ~tens-of-ms TD
// quote-gen that is additive on a real TD).
func BenchmarkSetup_FullGate(b *testing.B) {
	client := attestedManagers(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		client.resume = newResumeCache(time.Hour) // empty cache ⇒ client proposes modeFull
		b.StartTimer()

		_, closer, _, err := client.CreateDedicatedTunnel("127.0.0.1")
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		closer.Close()
		b.StartTimer()
	}
}

// BenchmarkSetup_Resume measures establishment via the resumption handshake (no
// quote) after a single priming full gate. The gap vs FullGate is the protocol
// saving; on a real TD, resumption additionally saves the whole quote-gen cost.
func BenchmarkSetup_Resume(b *testing.B) {
	client := attestedManagers(b)
	_, closer, _, err := client.CreateDedicatedTunnel("127.0.0.1") // prime the cache (both ends)
	if err != nil {
		b.Fatal(err)
	}
	closer.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, closer, _, err := client.CreateDedicatedTunnel("127.0.0.1")
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		closer.Close()
		b.StartTimer()
	}
}
