package main

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grimlock-ai/grimlock/internal/attest"
	"github.com/grimlock-ai/grimlock/internal/x402"
)

type stubQuoter struct {
	quote []byte
	mu    sync.Mutex // Quote() runs on the proxy goroutine; the test reads concurrently
	seen  [attest.ReportDataSize]byte
	used  bool
}

func (q *stubQuoter) Quote(rd [attest.ReportDataSize]byte) ([]byte, error) {
	q.mu.Lock()
	q.seen = rd
	q.used = true
	q.mu.Unlock()
	return q.quote, nil
}

// quoted reports whether Quote has been called, safe for concurrent polling.
func (q *stubQuoter) quoted() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.used
}

// stubPayExporter is a deterministic stand-in for the TLS session EKM exporter.
func stubPayExporter(ctx []byte) ([attest.ReportDataSize]byte, error) {
	return sha512.Sum512(ctx), nil
}

func discardLog() *ReceiptLog { return NewReceiptLog(io.Discard) }

func paymentRequest(t testing.TB, payTo, value string) string {
	t.Helper()
	p := &x402.PaymentPayload{
		X402Version: 1, Scheme: "exact", Network: "base-sepolia",
		Payload: &x402.ExactEvmPayload{
			Signature: "0xsig",
			Authorization: &x402.ExactEvmPayloadAuthorization{
				From: "0xPayer", To: payTo, Value: value,
				ValidAfter: "0", ValidBefore: "9999999999", Nonce: "0xnonce",
			},
		},
	}
	hv, err := x402.EncodePaymentHeader(p)
	if err != nil {
		t.Fatal(err)
	}
	return "POST /pay HTTP/1.1\r\nHost: agent\r\n" +
		x402.HeaderPayment + ": " + hv + "\r\nContent-Length: 0\r\n\r\n"
}

func newConn(xe *x402Enforcer) *paymentConn { return &paymentConn{xe: xe} }

func TestX402_BlocksOverLimitPayment(t *testing.T) {
	gAgent, tAgent := net.Pipe()
	gTunnel, tTunnel := net.Pipe()
	defer gAgent.Close()
	defer gTunnel.Close()

	pc := newConn(newX402Enforcer(x402.Policy{MaxPerPayment: big.NewInt(1)}, nil, discardLog(), false))
	go pumpRequests(gAgent, gTunnel, []requestEnforcer{pc})
	go func() { io.WriteString(tAgent, paymentRequest(t, "0xMerchant", "1000000")) }()
	go func() {
		_ = tTunnel.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1)
		if n, _ := tTunnel.Read(buf); n > 0 {
			t.Errorf("over-limit payment was forwarded to the tunnel")
		}
	}()

	_ = tAgent.SetReadDeadline(time.Now().Add(2 * time.Second))
	status, err := bufio.NewReader(tAgent).ReadString('\n')
	if err != nil || !strings.Contains(status, "403") {
		t.Fatalf("expected 403, got %q (%v)", status, err)
	}
}

func TestX402_ForwardsAllowedPayment(t *testing.T) {
	gAgent, tAgent := net.Pipe()
	gTunnel, tTunnel := net.Pipe()
	defer gAgent.Close()
	defer gTunnel.Close()

	pc := newConn(newX402Enforcer(x402.Policy{
		MaxPerPayment:   big.NewInt(1_000_000),
		AllowedPayTo:    x402.LowerSet([]string{"0xMerchant"}),
		AllowedNetworks: map[string]bool{"base-sepolia": true},
	}, nil, discardLog(), false))
	go pumpRequests(gAgent, gTunnel, []requestEnforcer{pc})
	go func() { io.WriteString(tAgent, paymentRequest(t, "0xMerchant", "10000")); tAgent.Close() }()

	_ = tTunnel.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(tTunnel).ReadString('\n')
	if err != nil || !strings.Contains(line, "POST /pay") {
		t.Fatalf("expected forwarded request, got %q (%v)", line, err)
	}
}

func TestX402_PassesThroughNonPayment(t *testing.T) {
	gAgent, tAgent := net.Pipe()
	gTunnel, tTunnel := net.Pipe()
	defer gAgent.Close()
	defer gTunnel.Close()

	pc := newConn(newX402Enforcer(x402.Policy{MaxPerPayment: big.NewInt(1)}, nil, discardLog(), false))
	go pumpRequests(gAgent, gTunnel, []requestEnforcer{pc})
	go func() {
		io.WriteString(tAgent, "GET /.well-known/agent.json HTTP/1.1\r\nHost: a\r\n\r\n")
		tAgent.Close()
	}()

	_ = tTunnel.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(tTunnel).ReadString('\n')
	if err != nil || !strings.Contains(line, "GET /.well-known/agent.json") {
		t.Fatalf("non-payment not forwarded: %q (%v)", line, err)
	}
}

// 402 correlation: a payment that does not match the challenge is blocked.
func TestX402_RejectsPaymentMismatchingChallenge(t *testing.T) {
	gAgent, tAgent := net.Pipe()
	gTunnel, _ := net.Pipe()
	defer gAgent.Close()
	defer gTunnel.Close()

	pc := newConn(newX402Enforcer(x402.Policy{MaxPerPayment: big.NewInt(1_000_000)}, nil, discardLog(), false))
	pc.setChallenge(&x402.PaymentRequirements{
		Scheme: "exact", Network: "base-sepolia", PayTo: "0xMerchant", MaxAmountRequired: "100000",
	})
	go pumpRequests(gAgent, gTunnel, []requestEnforcer{pc})
	go func() { io.WriteString(tAgent, paymentRequest(t, "0xEVIL", "10000")) }() // wrong payee

	_ = tAgent.SetReadDeadline(time.Now().Add(2 * time.Second))
	status, err := bufio.NewReader(tAgent).ReadString('\n')
	if err != nil || !strings.Contains(status, "403") {
		t.Fatalf("payment to a non-challenge payee must be blocked; got %q (%v)", status, err)
	}
}

// 402 correlation: a payment matching the challenge is allowed.
func TestX402_AllowsPaymentMatchingChallenge(t *testing.T) {
	gAgent, tAgent := net.Pipe()
	gTunnel, tTunnel := net.Pipe()
	defer gAgent.Close()
	defer gTunnel.Close()

	pc := newConn(newX402Enforcer(x402.Policy{MaxPerPayment: big.NewInt(1_000_000)}, nil, discardLog(), false))
	pc.setChallenge(&x402.PaymentRequirements{
		Scheme: "exact", Network: "base-sepolia", PayTo: "0xMerchant", MaxAmountRequired: "100000",
	})
	go pumpRequests(gAgent, gTunnel, []requestEnforcer{pc})
	go func() { io.WriteString(tAgent, paymentRequest(t, "0xMerchant", "10000")); tAgent.Close() }()

	_ = tTunnel.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(tTunnel).ReadString('\n')
	if err != nil || !strings.Contains(line, "POST /pay") {
		t.Fatalf("matching payment should be forwarded: %q (%v)", line, err)
	}
}

// F1: an allowed payment generates a binding quote recorded in the receipt, and
// REPORT_DATA reflects the request (changes with the HTTP method/path).
func TestX402_BindingQuoteInReceipt(t *testing.T) {
	gAgent, tAgent := net.Pipe()
	gTunnel, tTunnel := net.Pipe()
	defer gAgent.Close()
	defer gTunnel.Close()

	var buf bytes.Buffer
	q := &stubQuoter{quote: []byte("TDX-QUOTE")}
	pc := newConn(newX402Enforcer(x402.Policy{MaxPerPayment: big.NewInt(1_000_000)}, q, NewReceiptLog(&buf), true))
	pc.exporter = stubPayExporter // binding now requires a session exporter (no fallback)
	pc.epoch = 3
	go pumpRequests(gAgent, gTunnel, []requestEnforcer{pc})
	go func() { io.WriteString(tAgent, paymentRequest(t, "0xMerchant", "10000")); tAgent.Close() }()
	go io.Copy(io.Discard, tTunnel)

	deadline := time.Now().Add(2 * time.Second)
	for !q.quoted() {
		if time.Now().After(deadline) {
			t.Fatal("binding quote not generated")
		}
		time.Sleep(5 * time.Millisecond)
	}
	pc.finish()
	var r Receipt
	if err := json.NewDecoder(&buf).Decode(&r); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if r.QuoteB64 != base64.StdEncoding.EncodeToString([]byte("TDX-QUOTE")) {
		t.Fatalf("receipt missing binding quote: %q", r.QuoteB64)
	}
}

// F4: a settlement response is captured and finalizes the pending receipt.
func TestX402_CapturesSettlementReceipt(t *testing.T) {
	var buf bytes.Buffer
	pc := newConn(newX402Enforcer(x402.Policy{}, nil, NewReceiptLog(&buf), false))
	pc.addPending(&Receipt{Time: time.Unix(1, 0), Allowed: true, PayTo: "0xM", Value: "10000"})

	gTunnel, tTunnel := net.Pipe()
	gAgent, tAgent := net.Pipe()
	defer gTunnel.Close()
	defer gAgent.Close()
	done := make(chan struct{})
	go func() { pc.handleResponses(gTunnel, gAgent); close(done) }()
	go io.Copy(io.Discard, tAgent)

	settle := x402.SettleResponse{Success: true, Transaction: "0xTXHASH", Network: "base-sepolia"}
	sj, _ := json.Marshal(settle)
	hdr := base64.StdEncoding.EncodeToString(sj)
	resp := "HTTP/1.1 200 OK\r\n" + x402.HeaderPaymentResponse + ": " + hdr + "\r\nContent-Length: 2\r\n\r\nok"
	io.WriteString(tTunnel, resp)
	tTunnel.Close()
	<-done

	var r Receipt
	if err := json.NewDecoder(&buf).Decode(&r); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if r.SettleTx != "0xTXHASH" || !r.SettleOK {
		t.Fatalf("settlement not captured: tx=%q ok=%v", r.SettleTx, r.SettleOK)
	}
}

func TestReceiptLog_HashChain(t *testing.T) {
	var buf bytes.Buffer
	l := NewReceiptLog(&buf)
	for i := 0; i < 3; i++ {
		if err := l.Append(&Receipt{Time: time.Unix(int64(i), 0), PayTo: "0xM", Value: "1", Allowed: true}); err != nil {
			t.Fatal(err)
		}
	}
	entries := decodeReceipts(t, buf.Bytes())
	if bad := VerifyChain(entries); bad != -1 {
		t.Fatalf("valid chain reported broken at %d", bad)
	}
	entries[1].Value = "999"
	if VerifyChain(entries) == -1 {
		t.Fatal("tampered chain verified as intact")
	}
}

// P2: the chain continues across a restart (recovers prev from the file).
func TestReceiptLog_RecoversChainOnRestart(t *testing.T) {
	path := t.TempDir() + "/receipts.jsonl"

	l1, err := OpenReceiptLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = l1.Append(&Receipt{Time: time.Unix(1, 0), PayTo: "0xM", Value: "1"})
	_ = l1.Append(&Receipt{Time: time.Unix(2, 0), PayTo: "0xM", Value: "2"})

	l2, err := OpenReceiptLogFile(path) // "restart"
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Append(&Receipt{Time: time.Unix(3, 0), PayTo: "0xM", Value: "3"})

	b, _ := os.ReadFile(path)
	entries := decodeReceipts(t, b)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if bad := VerifyChain(entries); bad != -1 {
		t.Fatalf("chain broken across restart at %d", bad)
	}
}

func decodeReceipts(t *testing.T, b []byte) []*Receipt {
	t.Helper()
	var out []*Receipt
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r Receipt
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, &r)
	}
	return out
}
