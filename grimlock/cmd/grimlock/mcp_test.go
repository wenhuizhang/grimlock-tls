package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/grimlock-ai/grimlock/internal/capability"
)

func TestToolCallsIn(t *testing.T) {
	cases := []struct {
		body    string
		nCalls  int
		ok      bool
		comment string
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`, 1, true, "single call"},
		{`[{"method":"tools/call","params":{"name":"x"}},{"method":"tools/list"}]`, 1, true, "batch: one call + one non-call"},
		{`[{"method":"tools/call","params":{"name":"a"}},{"method":"tools/call","params":{"name":"b"}}]`, 2, true, "batch: two calls"},
		{`{"method":"initialize","params":{"caps":[1,2]}}`, 0, true, "non-tool method with array params: allowed"},
		{``, 0, true, "empty body"},
		{`   `, 0, true, "whitespace only"},
		{`{bad`, 0, false, "unparseable ⇒ fail closed"},
		{`"just a string"`, 0, false, "valid JSON but not an object ⇒ fail closed"},
		{`[{"method":"tools/call","params":{"name":"a"}}, 42]`, 0, false, "bad batch element ⇒ fail closed"},
		{`{"method":"tools/call"}`, 1, true, "call with no params ⇒ one call, empty name (blocked later)"},
	}
	for _, c := range cases {
		calls, ok := toolCallsIn([]byte(c.body))
		if ok != c.ok || len(calls) != c.nCalls {
			t.Errorf("%s: toolCallsIn(%q) = %d calls ok=%v, want %d ok=%v", c.comment, c.body, len(calls), ok, c.nCalls, c.ok)
		}
	}
}

func TestMCPAuthorize(t *testing.T) {
	manifest := capability.Manifest{
		{Name: "read_file", Capability: "fs.read"},
		{Name: "delete_all", Capability: "fs.delete"},
	}
	pol := capability.NewPolicy([]string{"fs.read"}, nil)
	mc := &mcpConn{policy: pol, manifest: manifest}

	if err := mc.authorize("read_file"); err != nil {
		t.Errorf("in-grant attested tool should pass: %v", err)
	}
	if err := mc.authorize("delete_all"); err == nil {
		t.Error("over-grant tool (fs.delete) must be blocked")
	}
	if err := mc.authorize("launch_missiles"); err == nil {
		t.Error("tool not in the attested manifest must be blocked")
	}
	// Fail-closed: enforced policy but no manifest ⇒ block everything.
	if err := (&mcpConn{policy: pol}).authorize("read_file"); err == nil {
		t.Error("missing attested manifest must fail closed")
	}
}

// callRaw routes one HTTP POST with the given JSON-RPC body through a fresh
// enforcer proxy to a mock echo peer, returning whether the peer received it
// (forwarded) and whether the agent got a JSON-RPC error.
func callRaw(t *testing.T, me *mcpEnforcer, manifest capability.Manifest, body string) (forwarded, jsonrpcErr bool) {
	t.Helper()
	agentC, agentP := tcpPair(t)
	peerP, peerC := tcpPair(t)
	defer agentC.Close()
	go guardedProxy(agentP, peerP, []requestEnforcer{&mcpConn{policy: me.policy, manifest: manifest}}, nil)

	fwd := make(chan struct{}, 1)
	go func() {
		br := bufio.NewReader(peerC)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		io.ReadAll(req.Body)
		req.Body.Close()
		fwd <- struct{}{}
		resp := `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`
		fmt.Fprintf(peerC, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"+
			"Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(resp), resp)
	}()

	req, _ := http.NewRequest("POST", "http://peer/mcp", strings.NewReader(body))
	if err := req.Write(agentC); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(agentC), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	select {
	case <-fwd:
		forwarded = true
	default:
	}
	return forwarded, bytes.Contains(rb, []byte(`"error"`))
}

func callTool(t *testing.T, me *mcpEnforcer, manifest capability.Manifest, tool string) (forwarded, jsonrpcErr bool) {
	t.Helper()
	return callRaw(t, me, manifest, fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q}}`, tool))
}

// TestMCPProxy_EnforcesToolCalls proves the wire enforcer forwards in-grant
// attested calls and blocks over-grant / unattested ones with a JSON-RPC error —
// out-of-agent, before the call reaches the peer.
func TestMCPProxy_EnforcesToolCalls(t *testing.T) {
	manifest := capability.Manifest{
		{Name: "read_file", Capability: "fs.read"},
		{Name: "delete_all", Capability: "fs.delete"},
	}
	me := newMCPEnforcer(capability.NewPolicy([]string{"fs.read"}, nil))

	if fwd, jerr := callTool(t, me, manifest, "read_file"); !fwd || jerr {
		t.Errorf("read_file should be forwarded without error (forwarded=%v jsonrpcErr=%v)", fwd, jerr)
	}
	if fwd, jerr := callTool(t, me, manifest, "delete_all"); fwd || !jerr {
		t.Errorf("delete_all (over-grant) must be blocked (forwarded=%v jsonrpcErr=%v)", fwd, jerr)
	}
	if fwd, jerr := callTool(t, me, manifest, "launch_missiles"); fwd || !jerr {
		t.Errorf("unattested tool must be blocked (forwarded=%v jsonrpcErr=%v)", fwd, jerr)
	}
}

// TestMCPProxy_BatchBypassBlocked is the regression test for the JSON-RPC batch
// bypass: an over-grant tools/call wrapped in a batch array (which previously
// failed OPEN and was forwarded unenforced) must now be blocked, and an
// unparseable body must fail closed.
func TestMCPProxy_BatchBypassBlocked(t *testing.T) {
	manifest := capability.Manifest{
		{Name: "read_file", Capability: "fs.read"},
		{Name: "delete_all", Capability: "fs.delete"},
	}
	me := newMCPEnforcer(capability.NewPolicy([]string{"fs.read"}, nil))

	// Over-grant call smuggled in a batch → BLOCKED (the bug).
	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"}}]`
	if fwd, jerr := callRaw(t, me, manifest, batch); fwd || !jerr {
		t.Errorf("batched over-grant call must be blocked (forwarded=%v jsonrpcErr=%v)", fwd, jerr)
	}
	// Batch of only in-grant calls → forwarded.
	okBatch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}]`
	if fwd, jerr := callRaw(t, me, manifest, okBatch); !fwd || jerr {
		t.Errorf("batched in-grant call should be forwarded (forwarded=%v jsonrpcErr=%v)", fwd, jerr)
	}
	// Batch where ONE of several calls is over-grant → whole request blocked.
	mixed := `[{"method":"tools/call","params":{"name":"read_file"}},{"method":"tools/call","params":{"name":"delete_all"}}]`
	if fwd, jerr := callRaw(t, me, manifest, mixed); fwd || !jerr {
		t.Errorf("batch with one over-grant call must be blocked (forwarded=%v jsonrpcErr=%v)", fwd, jerr)
	}
	// Unparseable body → fail closed (blocked, not forwarded).
	if fwd, jerr := callRaw(t, me, manifest, `{not valid json`); fwd || !jerr {
		t.Errorf("unparseable body must fail closed (forwarded=%v jsonrpcErr=%v)", fwd, jerr)
	}
}
