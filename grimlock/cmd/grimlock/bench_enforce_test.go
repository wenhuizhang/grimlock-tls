package main

// Enforcement-overhead benchmarks for the evaluation (eval/RQ4_enforcement). They
// measure the per-request latency the guarded pipeline adds for payments, for tool
// capabilities, and for both composed on one connection, so the paper can report the
// cost that falls on control traffic. Run: go test -bench BenchmarkEnforce -benchmem.

import (
	"bufio"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/grimlock-ai/grimlock/internal/capability"
	"github.com/grimlock-ai/grimlock/internal/x402"
)

func parseHTTP(b *testing.B, raw string) (*http.Request, []byte) {
	b.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		b.Fatalf("parse request: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	req.Body.Close()
	return req, body
}

func benchEnforce(b *testing.B, reqs []requestEnforcer, req *http.Request, body []byte) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, e := range reqs {
			_ = e.enforce(req, body, io.Discard)
		}
	}
}

// One payment check (allowed path: decode, policy, correlate, record without a quote).
func BenchmarkEnforce_X402(b *testing.B) {
	xe := newX402Enforcer(x402.Policy{
		MaxPerPayment: big.NewInt(1_000_000),
		AllowedPayTo:  x402.LowerSet([]string{"0xMerchant"}),
	}, nil, discardLog(), false)
	req, body := parseHTTP(b, paymentRequest(b, "0xMerchant", "100"))
	benchEnforce(b, []requestEnforcer{newConn(xe)}, req, body)
}

// One capability check (allowed tool call against the attested manifest).
func BenchmarkEnforce_MCP(b *testing.B) {
	mc := &mcpConn{
		policy:   capability.NewPolicy([]string{"fs.read"}, nil),
		manifest: capability.Manifest{{Name: "read_file", Capability: "fs.read"}},
	}
	req, body := parseHTTP(b, httpPost(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`))
	benchEnforce(b, []requestEnforcer{mc}, req, body)
}

// Both checks composed on one connection, over a tool-call request. The payment
// check finds no payment header and passes; the capability check runs. This is the
// cost a channel guarded by both policies adds to a control request.
func BenchmarkEnforce_Composed(b *testing.B) {
	xe := newX402Enforcer(x402.Policy{MaxPerPayment: big.NewInt(1_000_000)}, nil, discardLog(), false)
	mc := &mcpConn{
		policy:   capability.NewPolicy([]string{"fs.read"}, nil),
		manifest: capability.Manifest{{Name: "read_file", Capability: "fs.read"}},
	}
	req, body := parseHTTP(b, httpPost(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`))
	benchEnforce(b, []requestEnforcer{newConn(xe), mc}, req, body)
}
