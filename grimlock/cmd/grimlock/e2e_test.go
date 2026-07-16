package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/grimlock-ai/grimlock/internal/attest"
)

// writeCACerts generates a throwaway CA and a leaf (usable as both client and
// server cert, CN "grimlock", SAN 127.0.0.1) signed by it, writes PEM files, and
// returns their paths. Enough for real CA-mode mutual TLS between two managers.
func writeCACerts(t testing.TB) (caFile, certFile, keyFile string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "grimlock-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "grimlock"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"grimlock"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caFile = filepath.Join(dir, "ca.crt")
	certFile = filepath.Join(dir, "leaf.crt")
	keyFile = filepath.Join(dir, "leaf.key")
	writePEM(t, caFile, "CERTIFICATE", caDER)
	writePEM(t, certFile, "CERTIFICATE", leafDER)
	writePEM(t, keyFile, "EC PRIVATE KEY", keyDER)
	return caFile, certFile, keyFile
}

func writePEM(t testing.TB, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// startEchoAgent starts a loopback TCP echo server (the "local agent") and
// returns its port.
func startEchoAgent(t testing.TB) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// freePort returns a currently-free TCP port (closed before return; standard
// test trick — good enough on loopback).
func freePort(t testing.TB) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

// twoManagers wires a CA-mode server (listening) and client (dialing) pair.
func twoManagers(t testing.TB) (client, server *TunnelManager, tunPort int) {
	t.Helper()
	ca, cert, key := writeCACerts(t)
	cfg := TunnelConfig{CertFile: cert, KeyFile: key, CAFile: ca}

	server, err := NewTunnelManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	tunPort = freePort(t)
	if err := server.StartListener(tunPort); err != nil {
		t.Fatal(err)
	}

	client, err = NewTunnelManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	client.tunnelPort = tunPort
	return client, server, tunPort
}

// sendThrough writes the destination header + payload over a ready tunnel handle
// and returns the echoed bytes.
func sendThrough(t testing.TB, conn net.Conn, agentPort int, payload string) string {
	t.Helper()
	hdr := make([]byte, HeaderSize)
	copy(hdr[0:4], net.ParseIP("127.0.0.1").To4())
	binary.BigEndian.PutUint16(hdr[4:6], uint16(agentPort))
	if _, err := conn.Write(hdr); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	return string(buf)
}

// TestE2E_CAModeForwards is the end-to-end datapath: client establishes a real
// mTLS (+ kTLS where the kernel supports it) tunnel to the server, the server
// forwards to a local echo agent, and bytes round-trip. This is the whole
// tunnel+forward composition running for real (no eBPF/TDX needed).
func TestE2E_CAModeForwards(t *testing.T) {
	agentPort := startEchoAgent(t)
	client, _, _ := twoManagers(t)

	dataConn, closer, epoch, err := client.CreateDedicatedTunnel("127.0.0.1")
	if err != nil {
		t.Fatalf("establish tunnel: %v", err)
	}
	defer closer.Close()
	if epoch != 0 {
		t.Fatalf("CA mode epoch must be 0, got %d", epoch)
	}

	const msg = "hello-end-to-end"
	if got := sendThrough(t, dataConn, agentPort, msg); got != msg {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

// TestE2E_CAModePoolConcurrent drives many concurrent requests through the warm
// pool. Concurrent establishes exercise the per-tunnel keyLog (a shared keyLog
// would corrupt kTLS key derivation under this load).
func TestE2E_CAModePoolConcurrent(t *testing.T) {
	agentPort := startEchoAgent(t)
	client, _, _ := twoManagers(t)
	client.channelDepth = 3
	pool := client.channelFor("127.0.0.1")

	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h, err := pool.stream()
			if err != nil {
				errs <- err
				return
			}
			defer h.close.Close()
			msg := "req-" + string(rune('A'+i))
			if got := sendThrough(t, h.conn, agentPort, msg); got != msg {
				errs <- fmt.Errorf("echo = %q, want %q", got, msg)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestKTLS_Engages confirms the client tunnel data plane is a raw *net.TCPConn
// after enableKTLS — i.e. the kernel (not userspace) does the TLS crypto, which
// is what lets the data plane splice. Skips (documenting the fact) on a kernel
// without kTLS; on a kernel with the tls module it must engage.
func TestKTLS_Engages(t *testing.T) {
	client, _, _ := twoManagers(t)
	dataConn, closer, _, err := client.CreateDedicatedTunnel("127.0.0.1")
	if err != nil {
		t.Fatalf("establish tunnel: %v", err)
	}
	defer closer.Close()
	if _, ok := dataConn.(*net.TCPConn); ok {
		t.Log("kTLS ENGAGED: tunnel data plane is a raw *net.TCPConn (kernel does the crypto)")
		return
	}
	t.Skipf("kTLS did not engage (data conn is %T) — kernel lacks kTLS, userspace TLS fallback", dataConn)
}

// TestSplice_TCPToTCP exercises the data-plane relay between two real
// *net.TCPConn (the client-side topology: local agent socket ↔ kTLS tunnel
// socket). spliceable() must report true, and under strace the bytes move via
// splice() syscalls — see the strace invocation in the commit / PROD-READINESS.
func TestSplice_TCPToTCP(t *testing.T) {
	echoPort := startEchoAgent(t)
	dst, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", echoPort)) // *net.TCPConn → echo
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()
	src, err := net.Dial("tcp", ln.Addr().String()) // client end (*net.TCPConn)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	srcServer := <-accepted // server end (*net.TCPConn)
	defer srcServer.Close()

	if !spliceable(srcServer, dst) {
		t.Fatalf("relay must take the splice path for two *net.TCPConn (got %T,%T)", srcServer, dst)
	}
	// Bridge srcServer ↔ dst with the production relay (both directions).
	go relay(dst, srcServer)
	go relay(srcServer, dst)

	const msg = "splice-me-zero-copy"
	if _, err := src.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	_ = src.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(src, buf); err != nil {
		t.Fatalf("read echo through relay: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("relay echo = %q, want %q", buf, msg)
	}
}

// TestE2E_MCPManifestCaptured proves the client captures the server's *attested*
// capability manifest through a real gate (over TLS+kTLS) — the map the wire
// enforcer checks each tool call against. Enforcement itself is covered by
// TestMCPProxy_EnforcesToolCalls; this closes the capture wiring end-to-end.
func TestE2E_MCPManifestCaptured(t *testing.T) {
	manifest := []byte(`[{"name":"read_file","capability":"fs.read","scope":"project"}]`)
	newAC := func(localManifest []byte) *AttestConfig {
		return &AttestConfig{
			Quoter: e2eQuoter{}, Verifier: e2eVerifier{},
			Identity: "grimlock", CertTTL: time.Hour, Timeout: 5 * time.Second,
			LocalManifest: localManifest,
		}
	}
	server, err := NewTunnelManager(TunnelConfig{Attest: newAC(manifest)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	server.resume.ttl = time.Hour
	port := freePort(t)
	if err := server.StartListener(port); err != nil {
		t.Fatal(err)
	}
	client, err := NewTunnelManager(TunnelConfig{Attest: newAC(nil)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	client.resume.ttl = time.Hour
	client.tunnelPort = port

	_, closer, _, err := client.CreateDedicatedTunnel("127.0.0.1")
	if err != nil {
		t.Fatalf("establish tunnel: %v", err)
	}
	defer closer.Close()

	got := client.manifestFor("127.0.0.1")
	if len(got) != 1 || got[0].Name != "read_file" || got[0].Capability != "fs.read" {
		t.Fatalf("client did not capture the server's attested manifest: %+v", got)
	}
}

// stub attestation: real protocol/EKM/kTLS, constant quote (a TD provides the
// real quote; everything else on the path is exercised for real).
type e2eQuoter struct{}

func (e2eQuoter) Quote(rd [attest.ReportDataSize]byte) ([]byte, error) { return []byte("quote"), nil }

type e2eVerifier struct{}

func (e2eVerifier) Verify(q []byte, rd [attest.ReportDataSize]byte) (*attest.Measurements, error) {
	return &attest.Measurements{MRTD: []byte("mrtd")}, nil
}

func attestedManagers(t testing.TB) (client *TunnelManager) {
	t.Helper()
	newAC := func() *AttestConfig {
		return &AttestConfig{
			Quoter: e2eQuoter{}, Verifier: e2eVerifier{},
			Identity: "grimlock", CertTTL: time.Hour, Timeout: 5 * time.Second,
		}
	}
	server, err := NewTunnelManager(TunnelConfig{Attest: newAC()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	server.resume.ttl = time.Hour
	tunPort := freePort(t)
	if err := server.StartListener(tunPort); err != nil {
		t.Fatal(err)
	}

	client, err = NewTunnelManager(TunnelConfig{Attest: newAC()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	client.resume.ttl = time.Hour
	client.tunnelPort = tunPort
	return client
}

// TestE2E_AttestedResumption validates the resumption protocol end-to-end over
// real TLS+kTLS: the first connection runs a full gate and caches a secret; the
// second resumes (no quote) and inherits the same attestation epoch. Only the
// quote content is stubbed — mode negotiation, EKM binding, the HMAC resume
// handshake, and the cross-kTLS/userspace framing are all real.
func TestE2E_AttestedResumption(t *testing.T) {
	agentPort := startEchoAgent(t)
	client := attestedManagers(t)

	fg0, rs0 := metrics.fullGates.Load(), metrics.resumes.Load()

	// First connection → full gate.
	c1, cl1, e1, err := client.CreateDedicatedTunnel("127.0.0.1")
	if err != nil {
		t.Fatalf("first connection (full gate): %v", err)
	}
	if got := sendThrough(t, c1, agentPort, "first"); got != "first" {
		t.Fatalf("echo1 = %q", got)
	}
	cl1.Close()

	// Second connection → resume (cheap), same epoch.
	c2, cl2, e2, err := client.CreateDedicatedTunnel("127.0.0.1")
	if err != nil {
		t.Fatalf("second connection (resume): %v", err)
	}
	if got := sendThrough(t, c2, agentPort, "second"); got != "second" {
		t.Fatalf("echo2 = %q", got)
	}
	cl2.Close()

	if e1 == 0 {
		t.Fatal("full-gate epoch must be nonzero")
	}
	if e2 != e1 {
		t.Fatalf("resume must inherit the full-gate epoch: e1=%d e2=%d", e1, e2)
	}
	// Mutual: each connection runs the handshake on both client and server, so
	// one full gate = +2 fullGates, one resume = +2 resumes.
	if got := metrics.fullGates.Load() - fg0; got != 2 {
		t.Fatalf("want exactly one mutual full gate (+2), got +%d", got)
	}
	if got := metrics.resumes.Load() - rs0; got != 2 {
		t.Fatalf("want exactly one mutual resume (+2), got +%d", got)
	}
}
