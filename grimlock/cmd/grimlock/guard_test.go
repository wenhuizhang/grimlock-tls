package main

import (
	"testing"

	"github.com/grimlock-ai/grimlock/internal/capability"
	"github.com/grimlock-ai/grimlock/internal/x402"
)

func TestEgressClassify(t *testing.T) {
	f := func(channelContext) any { return &mcpConn{} }
	p := &egressPolicy{
		guards:    map[int][]enforcerFactory{8080: {f}},
		fastPorts: map[int]bool{5000: true},
	}
	if _, c := p.classify(8080); c != classGuarded {
		t.Error("8080 (has enforcers) should be guarded")
	}
	if _, c := p.classify(5000); c != classFast {
		t.Error("5000 (fast-listed) should be fast")
	}
	if _, c := p.classify(9999); c != classFast {
		t.Error("unlisted port defaults to fast")
	}

	p.denyUnlisted = true
	if _, c := p.classify(9999); c != classDeny {
		t.Error("unlisted port with denyUnlisted should be denied")
	}
	if _, c := p.classify(8080); c != classGuarded {
		t.Error("guarded overrides deny")
	}
	if _, c := p.classify(5000); c != classFast {
		t.Error("fast overrides deny")
	}

	var np *egressPolicy // nil ⇒ everything fast (no policy configured)
	if _, c := np.classify(1); c != classFast {
		t.Error("nil policy should classify fast")
	}
}

func TestBuildEgressPolicy_BackwardCompat(t *testing.T) {
	// A globally-enabled enforcer with no --guard guards ALL agent ports (today's
	// behavior).
	xe := newX402Enforcer(x402.Policy{}, nil, discardLog(), false)
	me := newMCPEnforcer(capability.NewPolicy([]string{"fs.read"}, nil))

	p := buildEgressPolicy([]int{8080, 9090}, xe, me, nil, nil, "fast")
	for _, port := range []int{8080, 9090} {
		if _, c := p.classify(port); c != classGuarded {
			t.Errorf("port %d should be guarded", port)
		}
		if len(p.guards[port]) != 2 {
			t.Errorf("port %d should chain both enforcers, got %d", port, len(p.guards[port]))
		}
	}
}

func TestBuildEgressPolicy_ScopingAndDeny(t *testing.T) {
	xe := newX402Enforcer(x402.Policy{}, nil, discardLog(), false)
	me := newMCPEnforcer(capability.NewPolicy([]string{"fs.read"}, nil))

	// --guard 8080:mcp scopes MCP to 8080; x402 is unreferenced ⇒ guards all ports.
	// --fast 5000; --egress-default deny.
	p := buildEgressPolicy([]int{8080, 9090}, xe, me, []string{"8080:mcp"}, []string{"5000"}, "deny")

	if _, c := p.classify(8080); c != classGuarded {
		t.Error("8080 should be guarded")
	}
	if _, c := p.classify(5000); c != classFast {
		t.Error("5000 should be fast")
	}
	if _, c := p.classify(1234); c != classDeny {
		t.Error("unlisted port should be denied under egress-default deny")
	}
	if !p.denyUnlisted {
		t.Error("denyUnlisted should be set")
	}
}

// TestBuildPipeline_Composition proves x402 + MCP compose on one channel: two
// request enforcers, and the x402 paymentConn supplies the response handler.
func TestBuildPipeline_Composition(t *testing.T) {
	xe := newX402Enforcer(x402.Policy{}, nil, discardLog(), false)
	me := newMCPEnforcer(capability.NewPolicy([]string{"fs.read"}, nil))

	reqs, rh := buildPipeline([]enforcerFactory{xe.factory(), me.factory()}, channelContext{})
	if len(reqs) != 2 {
		t.Fatalf("want 2 request enforcers (x402 + mcp), got %d", len(reqs))
	}
	if rh == nil {
		t.Error("x402 should supply the response handler")
	}
}
