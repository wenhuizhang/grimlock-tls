// Wire-level MCP capability enforcement — a member of the guarded-channel pipeline
// (guard.go). It parses the agent's MCP traffic (JSON-RPC 2.0 over HTTP) and, for
// every tools/call, checks the called tool against the peer's ATTESTED manifest
// (the tool→capability map) and the client's capability grant — OUTSIDE the
// (possibly hijacked) agent. A call to a tool not in the attested manifest, or
// whose capability exceeds the grant, is blocked with a JSON-RPC error and never
// reaches the wire; capability governance is thus as strong as payment enforcement
// (no SDK trust required).
//
// Transport assumption: MCP over Streamable HTTP (JSON-RPC body in an HTTP POST).
// toolCallsIn handles JSON-RPC BATCHES and FAILS CLOSED on any body it cannot
// classify — an unparsed body may smuggle a tool call past enforcement.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/grimlock-ai/grimlock/internal/capability"
)

// mcpEnforcer is shared across connections: the capability grant. The per-peer
// attested manifest is bound per connection (in mcpConn).
type mcpEnforcer struct {
	policy capability.Policy
}

func newMCPEnforcer(p capability.Policy) *mcpEnforcer {
	return &mcpEnforcer{policy: p}
}

// factory builds a per-connection MCP enforcer bound to the peer's attested manifest.
func (me *mcpEnforcer) factory() enforcerFactory {
	return func(cc channelContext) any {
		return &mcpConn{policy: me.policy, manifest: cc.manifest}
	}
}

// mcpConn is the per-connection MCP request enforcer.
type mcpConn struct {
	policy   capability.Policy
	manifest capability.Manifest
}

// enforce authorizes every tools/call in a (possibly batched) request body; one
// denial blocks the whole request.
func (mc *mcpConn) enforce(req *http.Request, body []byte, deny io.Writer) error {
	calls, ok := toolCallsIn(body)
	if !ok {
		// Fail closed: a body we cannot classify may hide a tool call.
		metrics.mcpBlocked.Add(1)
		log.Printf("[MCP] BLOCK unparseable JSON-RPC body (fail-closed)")
		writeMCPBlocked(deny, nil, "unparseable MCP request (fail-closed)")
		return errors.New("unparseable MCP request")
	}
	for _, c := range calls {
		if aerr := mc.authorize(c.name); aerr != nil {
			metrics.mcpBlocked.Add(1)
			log.Printf("[MCP] BLOCK tools/call %q: %v", c.name, aerr)
			writeMCPBlocked(deny, c.id, aerr.Error())
			return aerr
		}
	}
	if n := len(calls); n > 0 {
		metrics.mcpAllowed.Add(uint64(n))
		log.Printf("[MCP] ALLOW %d tools/call(s)", n)
	}
	return nil
}

// authorize enforces the capability lattice for one tool call: the tool must be in
// the attested manifest AND its capability must be covered by the grant.
func (mc *mcpConn) authorize(name string) error {
	if mc.policy.Enforced() && len(mc.manifest) == 0 {
		return errors.New("peer advertised no attested manifest (fail-closed)")
	}
	tool, ok := mc.manifest.Tool(name)
	if !ok {
		return fmt.Errorf("tool %q is not in the attested manifest", name)
	}
	return mc.policy.CheckTool(tool)
}

// mcpCall is one tools/call found in a request body.
type mcpCall struct {
	name string
	id   json.RawMessage
}

// toolCallsIn returns every tools/call in a JSON-RPC request body, handling BOTH a
// single message and a BATCH (a JSON array, which JSON-RPC 2.0 permits). ok=false
// means the body is not JSON-RPC we can fully classify; the caller MUST fail closed
// (an unparsed body may smuggle a tool call). A non-invoking method (initialize,
// tools/list, a notification) yields no call and is allowed through; a tools/call
// with malformed/absent params yields an empty tool name, which authorize blocks.
func toolCallsIn(body []byte) (calls []mcpCall, ok bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, true // no body ⇒ no tool call (e.g. an SSE GET)
	}
	var msgs []json.RawMessage
	if trimmed[0] == '[' { // JSON-RPC batch
		if json.Unmarshal(trimmed, &msgs) != nil {
			return nil, false
		}
	} else {
		msgs = []json.RawMessage{trimmed}
	}
	for _, raw := range msgs {
		var head struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(raw, &head) != nil {
			return nil, false // a message we cannot parse ⇒ fail closed
		}
		if head.Method != "tools/call" {
			continue // non-invoking method: allowed (its params shape is irrelevant)
		}
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(head.Params, &p) // malformed/absent ⇒ name "" ⇒ blocked by authorize
		calls = append(calls, mcpCall{name: p.Name, id: head.ID})
	}
	return calls, true
}

// writeMCPBlocked returns a JSON-RPC error to the agent (HTTP 200; a JSON-RPC error
// is application-level). The tool call is never forwarded.
func writeMCPBlocked(w io.Writer, id json.RawMessage, reason string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	resp, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": -32001, "message": "capability denied by Grimlock: " + reason},
	})
	fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(resp), resp)
}
