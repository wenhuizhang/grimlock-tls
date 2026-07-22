// Channel classes + the composable enforcer pipeline (docs/channel-classes.md).
//
// Each local connection is classified from its recovered original destination:
//   - fast    : kTLS + splice(2), daemon off-path (bulk transfer) — handled in main
//   - guarded : userspace parse → enforcer pipeline (control: tool calls, payments)
//   - deny    : refused (egress chokepoint)
//
// A guarded channel runs a pipeline of per-connection enforcers over the agent's
// requests; a request is forwarded only if EVERY enforcer permits it (∧), which is
// the model's `⊢ Forward` with conjoined premises rather than two hardcoded,
// mutually-exclusive proxies. Enforcement needs plaintext, so guarded ⇒ no splice
// is fundamental — the point is to route each channel to the lane that fits it.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/grimlock-ai/grimlock/internal/attest"
	"github.com/grimlock-ai/grimlock/internal/capability"
)

// A per-connection enforcer object may implement any of these. requestEnforcer is
// the composable request-side check; responseHandler owns the reverse direction
// (at most one per channel — it re-emits verbatim while sniffing, e.g. x402
// settlement); finisher runs post-close cleanup (e.g. flushing pending receipts).
type requestEnforcer interface {
	// enforce vets one request. To BLOCK it writes a protocol-appropriate error to
	// deny and returns non-nil; the proxy then closes the channel. To PERMIT
	// (including "not applicable to me") it returns nil. It must not mutate body.
	enforce(req *http.Request, body []byte, deny io.Writer) error
}
type responseHandler interface {
	handleResponses(tunnelConn, agentConn net.Conn)
}
type finisher interface {
	finish()
}

// channelContext is the per-connection attestation context handed to each factory.
type channelContext struct {
	exp      attest.Exporter     // session EKM — x402 payment binding
	epoch    uint64              // attestation epoch — freshness / model @e
	manifest capability.Manifest // peer's attested manifest — MCP
	peerIP   string
	destPort int
}

// enforcerFactory builds the per-connection enforcer object from the context. The
// returned value may implement requestEnforcer, responseHandler, and/or finisher.
type enforcerFactory func(cc channelContext) any

const (
	guardMaxBody     = 1 << 20          // cap a single guarded request body (anti memory-DoS)
	guardReadTimeout = 10 * time.Minute // bound a stalled request read; reset per request
)

// ---- channel classification ----

type channelClass int

const (
	classFast channelClass = iota
	classGuarded
	classDeny
)

// egressPolicy maps a recovered destination port to a class + enforcer chain.
type egressPolicy struct {
	guards       map[int][]enforcerFactory // dest port → ordered enforcer chain (guarded)
	fastPorts    map[int]bool              // explicit bulk (never enforced)
	denyUnlisted bool                      // unlisted port ⇒ deny (else fast)
}

func (p *egressPolicy) classify(destPort int) ([]enforcerFactory, channelClass) {
	if p == nil {
		return nil, classFast
	}
	if f := p.guards[destPort]; len(f) > 0 {
		return f, classGuarded
	}
	if p.fastPorts[destPort] {
		return nil, classFast
	}
	if p.denyUnlisted {
		return nil, classDeny
	}
	return nil, classFast
}

// buildPipeline instantiates the per-connection enforcers for a guarded channel.
func buildPipeline(factories []enforcerFactory, cc channelContext) (reqs []requestEnforcer, rh responseHandler) {
	for _, f := range factories {
		g := f(cc)
		if r, ok := g.(requestEnforcer); ok {
			reqs = append(reqs, r)
		}
		if h, ok := g.(responseHandler); ok {
			rh = h // at most one handler owns the reverse direction
		}
	}
	return reqs, rh
}

// ---- the guarded proxy ----

// guardedProxy runs the request pipeline (agent→tunnel) and the response direction
// (tunnel→agent) over one connection, then runs any finishers.
func guardedProxy(agentConn, tunnelConn net.Conn, reqs []requestEnforcer, rh responseHandler) {
	done := make(chan struct{}, 2)
	go func() {
		if rh != nil {
			rh.handleResponses(tunnelConn, agentConn)
		} else {
			io.Copy(agentConn, tunnelConn) // no observer: pure passthrough
		}
		done <- struct{}{}
	}()
	go func() { pumpRequests(agentConn, tunnelConn, reqs); done <- struct{}{} }()
	<-done
	agentConn.Close()
	tunnelConn.Close()
	<-done
	for _, r := range reqs {
		if f, ok := r.(finisher); ok {
			f.finish()
		}
	}
}

func pumpRequests(agentConn, tunnelConn net.Conn, reqs []requestEnforcer) {
	br := bufio.NewReader(agentConn)
	for {
		// Bound how long a single request may take to arrive (slowloris); reset per
		// request, so legitimate idle keep-alive between calls is tolerated up to this.
		_ = agentConn.SetReadDeadline(time.Now().Add(guardReadTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		// Bounded read: never buffer more than guardMaxBody of a single request.
		body, err := io.ReadAll(io.LimitReader(req.Body, guardMaxBody+1))
		req.Body.Close()
		if err != nil {
			return
		}
		if len(body) > guardMaxBody {
			writeGuardOversize(agentConn)
			return
		}
		blocked := false
		for _, e := range reqs {
			if err := e.enforce(req, body, agentConn); err != nil { // e wrote the block
				blocked = true
				break
			}
		}
		if blocked {
			return
		}
		if forwardRequest(req, body, tunnelConn) != nil {
			return
		}
	}
}

// forwardRequest re-emits an inspected request (body restored) to the tunnel,
// normalizing to a fixed-length body.
func forwardRequest(req *http.Request, body []byte, w io.Writer) error {
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil
	return req.Write(w)
}

func writeGuardOversize(w io.Writer) {
	const body = "{\"error\":\"request body exceeds Grimlock limit\"}\n"
	fmt.Fprintf(w, "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

// ---- config: build the egress policy from flags ----

// multiFlag collects a repeatable string flag (--guard/--fast).
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// buildEgressPolicy maps ports to classes. A --guard PORT:ENFORCERS scopes an
// (enabled) enforcer to that port; a globally-enabled enforcer that no --guard
// mentions guards all agent ports (backward compat). --fast marks bulk ports;
// egressDefault chooses fast vs deny for unlisted intercepted ports.
func buildEgressPolicy(agentPorts []int, xe *x402Enforcer, me *mcpEnforcer, guards, fasts []string, egressDefault string) *egressPolicy {
	if egressDefault != "" && egressDefault != "fast" && egressDefault != "deny" {
		log.Fatalf("--egress-default must be fast or deny, got %q", egressDefault)
	}
	p := &egressPolicy{
		guards:       map[int][]enforcerFactory{},
		fastPorts:    map[int]bool{},
		denyUnlisted: egressDefault == "deny",
	}
	factoryFor := func(name string) enforcerFactory {
		switch name {
		case "x402":
			if xe != nil {
				return xe.factory()
			}
		case "mcp":
			if me != nil {
				return me.factory()
			}
		}
		log.Fatalf("--guard references enforcer %q which is not enabled (need --%s-enforce)", name, name)
		return nil
	}
	referenced := map[string]bool{}
	for _, g := range guards {
		port, names := parseGuardSpec(g)
		for _, n := range names {
			p.guards[port] = append(p.guards[port], factoryFor(n))
			referenced[n] = true
		}
	}
	if xe != nil && !referenced["x402"] {
		for _, port := range agentPorts {
			p.guards[port] = append(p.guards[port], xe.factory())
		}
	}
	if me != nil && !referenced["mcp"] {
		for _, port := range agentPorts {
			p.guards[port] = append(p.guards[port], me.factory())
		}
	}
	for _, f := range fasts {
		port, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			log.Fatalf("--fast %q: not a port number", f)
		}
		p.fastPorts[port] = true
	}
	return p
}

func parseGuardSpec(s string) (port int, names []string) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		log.Fatalf("--guard %q: want PORT:ENFORCERS (e.g. 8080:mcp,x402)", s)
	}
	port, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		log.Fatalf("--guard %q: bad port %q", s, parts[0])
	}
	for _, n := range strings.Split(parts[1], ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		log.Fatalf("--guard %q: no enforcers listed", s)
	}
	return port, names
}
