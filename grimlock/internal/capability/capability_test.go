package capability

import "testing"

func manifest() Manifest {
	return Manifest{
		{Name: "read", Capability: "fs.read", Scope: "workspace"},
		{Name: "search", Capability: "net.http.get", Scope: "network"},
		{Name: "del", Capability: "fs.delete", Scope: "system"},
	}
}

func TestPolicy_BlocksEscalation(t *testing.T) {
	p := NewPolicy([]string{"fs.read", "net.http.get"}, []string{"workspace", "network"})
	err := p.Check(manifest())
	if err == nil {
		t.Fatal("expected escalation (del: fs.delete/system) to be flagged")
	}
}

func TestPolicy_AllowsInPolicyManifest(t *testing.T) {
	p := NewPolicy([]string{"fs.read", "net.http.get"}, []string{"workspace", "network"})
	if err := p.Check(manifest()[:2]); err != nil {
		t.Fatalf("expected the in-policy subset to pass: %v", err)
	}
}

func TestPolicy_PrefixGrantCoversChildren_SiblingNot(t *testing.T) {
	p := NewPolicy([]string{"fs"}, []string{"workspace"})
	if err := p.Check(Manifest{{Name: "w", Capability: "fs.write", Scope: "workspace"}}); err != nil {
		t.Fatalf("granting 'fs' should cover fs.write: %v", err)
	}
	p2 := NewPolicy([]string{"fs.read"}, []string{"workspace"})
	if err := p2.Check(Manifest{{Name: "w", Capability: "fs.write", Scope: "workspace"}}); err == nil {
		t.Fatal("granting 'fs.read' must NOT cover sibling fs.write")
	}
}

func TestPolicy_UnenforcedDimensionSkipped(t *testing.T) {
	// Only scopes enforced; capability dimension empty -> not checked.
	p := Policy{AllowedScopes: map[string]bool{"workspace": true, "network": true}}
	if err := p.Check(manifest()[:2]); err != nil {
		t.Fatalf("scope-only policy should pass the workspace/network tools: %v", err)
	}
	if p.Check(manifest()) == nil {
		t.Fatal("system-scoped tool should still be blocked by the scope policy")
	}
}

func TestCheckManifestBytes_FailsClosedOnEmpty(t *testing.T) {
	enforced := NewPolicy([]string{"fs.read"}, []string{"workspace"})
	// Empty bytes (e.g. failed auto-pull) and empty array must be rejected.
	if enforced.CheckManifestBytes(nil) == nil {
		t.Fatal("empty manifest bytes must fail closed under an enforced policy")
	}
	if enforced.CheckManifestBytes([]byte(`[]`)) == nil {
		t.Fatal("empty manifest array must fail closed under an enforced policy")
	}
	// A valid in-policy manifest passes.
	if err := enforced.CheckManifestBytes([]byte(`[{"name":"r","capability":"fs.read","scope":"workspace"}]`)); err != nil {
		t.Fatalf("in-policy manifest should pass: %v", err)
	}
	// Unenforced policy: empty is fine (nothing to enforce).
	if err := (Policy{}).CheckManifestBytes(nil); err != nil {
		t.Fatalf("unenforced policy should not reject empty: %v", err)
	}
}

func TestParseManifest(t *testing.T) {
	m, err := ParseManifest([]byte(`[{"name":"read","capability":"fs.read","scope":"workspace"}]`))
	if err != nil || len(m) != 1 || m[0].Capability != "fs.read" {
		t.Fatalf("parse failed: %v %#v", err, m)
	}
	if mm, err := ParseManifest(nil); err != nil || mm != nil {
		t.Fatalf("empty manifest should parse to nil: %v %#v", err, mm)
	}
}
