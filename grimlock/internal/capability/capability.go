// Package capability checks an MCP server's tool manifest against a client
// policy at the Grimlock tunnel gate, so privilege escalation is blocked before
// any agent/tool traffic is forwarded.
//
// The manifest is the (name, capability, scope) set the peer's MCP server
// advertises (from the governed MCP SDK's capability_manifest()). The gate binds
// the manifest's digest into the attestation quote (so the measured server
// cannot advertise one manifest and serve another) and runs Policy.Check before
// authorizing the tunnel.
package capability

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Tool is one manifest entry.
type Tool struct {
	Name       string `json:"name"`
	Capability string `json:"capability"`
	Scope      string `json:"scope"`
}

// Manifest is a peer's advertised tool set.
type Manifest []Tool

// ParseManifest decodes the JSON manifest ([{name,capability,scope}, ...]).
func ParseManifest(b []byte) (Manifest, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse capability manifest: %w", err)
	}
	return m, nil
}

// Policy is what a client permits from a peer. Empty AllowedCapabilities or
// AllowedScopes means that dimension is not enforced.
type Policy struct {
	AllowedCapabilities map[string]bool
	AllowedScopes       map[string]bool
}

// NewPolicy builds a Policy from capability/scope lists.
func NewPolicy(capabilities, scopes []string) Policy {
	return Policy{AllowedCapabilities: toSet(capabilities), AllowedScopes: toSet(scopes)}
}

// Enforced reports whether the policy restricts anything.
func (p Policy) Enforced() bool {
	return len(p.AllowedCapabilities) > 0 || len(p.AllowedScopes) > 0
}

// CheckManifestBytes parses and checks a raw peer manifest, FAILING CLOSED: under
// an enforced policy an empty or missing manifest is rejected (a peer that won't
// advertise its tools cannot be trusted -- e.g. an auto-pull that failed and left
// the manifest empty). Use this at the enforcement point rather than Check, which
// trivially passes an empty manifest.
func (p Policy) CheckManifestBytes(b []byte) error {
	m, err := ParseManifest(b)
	if err != nil {
		return err
	}
	if p.Enforced() && len(m) == 0 {
		return errors.New("peer advertised no capability manifest (fail-closed under enforced policy)")
	}
	return p.Check(m)
}

// Check returns an error describing every tool that exceeds the policy
// (privilege escalation), or nil if the whole manifest is within policy. This is
// the STATIC gate check (whole manifest); CheckTool is the per-call check.
func (p Policy) Check(m Manifest) error {
	var bad []string
	for _, t := range m {
		if err := p.CheckTool(t); err != nil {
			bad = append(bad, t.Name+": "+err.Error())
		}
	}
	if bad != nil {
		sort.Strings(bad)
		return fmt.Errorf("privilege escalation in %d tool(s): %s", len(bad), strings.Join(bad, "; "))
	}
	return nil
}

// CheckTool appraises a single tool against the policy — the runtime, per-call
// check used to enforce individual MCP tool invocations on the wire. Returns nil
// if the tool's capability (and scope, if enforced) is within the grant.
func (p Policy) CheckTool(t Tool) error {
	var reasons []string
	if len(p.AllowedCapabilities) > 0 {
		if t.Capability == "" {
			reasons = append(reasons, "no capability declared")
		} else if !covered(t.Capability, p.AllowedCapabilities) {
			reasons = append(reasons, fmt.Sprintf("capability %q exceeds policy", t.Capability))
		}
	}
	if len(p.AllowedScopes) > 0 {
		if t.Scope == "" {
			reasons = append(reasons, "no scope declared")
		} else if !p.AllowedScopes[t.Scope] {
			reasons = append(reasons, fmt.Sprintf("scope %q not granted", t.Scope))
		}
	}
	if reasons != nil {
		return errors.New(strings.Join(reasons, ", "))
	}
	return nil
}

// Tool returns the manifest entry with the given name.
func (m Manifest) Tool(name string) (Tool, bool) {
	for _, t := range m {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// capCovers reports whether grant g covers request r under the dot-prefix order:
// g equals r, or g is a dot-prefix of r (granting "fs" covers "fs.read";
// "fs.read" covers only itself and refinements beneath it).
func capCovers(g, r string) bool {
	return r == g || strings.HasPrefix(r, g+".")
}

// covered: a requested capability is permitted if some grant covers it.
func covered(requested string, granted map[string]bool) bool {
	for g := range granted {
		if capCovers(g, requested) {
			return true
		}
	}
	return false
}

// Attenuate returns the capability grant a delegate may pass ONWARD across one
// hop: the generating set of ↓upstream ∩ ↓local — the intersection of what it was
// granted (upstream) with what its own policy allows (local). For a comparable
// pair the intersection is the ideal of the *more specific* capability; disjoint
// pairs contribute nothing. By the Coq theorem covered_attenuation
// (formal/Grimlock.v) the result's ideal is a subset of both, so no hop can
// escalate beyond any earlier grant. This is the multi-hop `hand-off` rule.
func Attenuate(upstream, local []string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(c string) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, a := range upstream {
		for _, b := range local {
			switch {
			case capCovers(a, b): // a ⊒ b  ⇒  ↓a ∩ ↓b = ↓b
				add(b)
			case capCovers(b, a): // b ⊒ a  ⇒  ↓b ∩ ↓a = ↓a
				add(a)
			}
		}
	}
	sort.Strings(out)
	return out
}

// AttenuateChain folds Attenuate across a delegation chain A→B→C→…: the first
// hop's grant, narrowed by each subsequent hop's local policy. The result — what
// the final hop may exercise — is monotonically non-increasing at every step, so
// authority only ever shrinks along the chain.
func AttenuateChain(grants ...[]string) []string {
	if len(grants) == 0 {
		return nil
	}
	acc := grants[0]
	for _, g := range grants[1:] {
		acc = Attenuate(acc, g)
	}
	return acc
}

// CoveredBy reports whether request r is permitted by grant set G (exported form
// of the covering test, used to check attenuation results).
func CoveredBy(r string, G []string) bool {
	for _, g := range G {
		if capCovers(g, r) {
			return true
		}
	}
	return false
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		if it = strings.TrimSpace(it); it != "" {
			m[it] = true
		}
	}
	return m
}
