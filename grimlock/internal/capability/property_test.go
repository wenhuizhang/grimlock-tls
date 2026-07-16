package capability

import (
	"math/rand"
	"strings"
	"testing"
)

// Property tests binding the Go capability implementation to the machine-checked
// laws in ../../formal/Grimlock.v. Each asserts the EXACT theorem proved in Coq
// holds on the real code, over many random inputs — closing the model↔code gap
// (the Coq models the dot-prefix lattice; these check the Go `capCovers`/`Attenuate`
// realize it). Deterministic seeds keep failures reproducible.

var capSegs = []string{"fs", "net", "read", "write", "exec", "a", "b", "c"}

func randCap(rng *rand.Rand) string {
	n := 1 + rng.Intn(4)
	p := make([]string, n)
	for i := range p {
		p[i] = capSegs[rng.Intn(len(capSegs))]
	}
	return strings.Join(p, ".")
}

func randGrants(rng *rand.Rand) []string {
	n := rng.Intn(5)
	g := make([]string, n)
	for i := range g {
		g[i] = randCap(rng)
	}
	return g
}

const propIters = 50000

// covered_monotone: adding grants never removes a permission.
func TestProp_CoveredMonotone(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < propIters; i++ {
		G := randGrants(rng)
		Gp := append(append([]string{}, G...), randGrants(rng)...) // G ⊆ Gp
		r := randCap(rng)
		if CoveredBy(r, G) && !CoveredBy(r, Gp) {
			t.Fatalf("monotonicity violated: r=%q covered by %v but not superset %v", r, G, Gp)
		}
	}
}

// covered_attenuation: a delegate holding Attenuate(U,L) permits no more than
// EITHER U or L — the multi-hop non-escalation property.
func TestProp_AttenuationNoEscalation(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < propIters; i++ {
		U, L := randGrants(rng), randGrants(rng)
		A := Attenuate(U, L)
		r := randCap(rng)
		if CoveredBy(r, A) && !(CoveredBy(r, U) && CoveredBy(r, L)) {
			t.Fatalf("attenuation escalated: r=%q permitted by %v, but coveredU=%v coveredL=%v (U=%v L=%v)",
				r, A, CoveredBy(r, U), CoveredBy(r, L), U, L)
		}
	}
}

// refCovers is an INDEPENDENT reference for dot-prefix covering (index-based, not
// strings.HasPrefix like the implementation), used as an oracle so this suite
// catches any divergence of capCovers from the intended semantics on its own. The
// one-directional laws above are trivially satisfied by a "grant everything"
// implementation; this differential test is what pins the EXACT relation.
func refCovers(g, r string) bool {
	if r == g {
		return true
	}
	return len(r) > len(g) && r[:len(g)] == g && r[len(g)] == '.'
}

// no_grant_denied + exact semantics: CoveredBy(r,G) holds IFF some grant in G
// covers r under the independent reference (so no covering grant ⇒ denied —
// fail-closed — and nothing outside the dot-prefix relation is ever permitted).
func TestProp_MatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < propIters; i++ {
		G := randGrants(rng)
		r := randCap(rng)
		want := false
		for _, g := range G {
			if refCovers(g, r) {
				want = true
				break
			}
		}
		if CoveredBy(r, G) != want {
			t.Fatalf("CoveredBy(%q,%v)=%v, independent reference=%v", r, G, CoveredBy(r, G), want)
		}
	}
}

// covered_refine: a broad grant covers every more-specific request beneath it.
func TestProp_CoveredRefine(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	for i := 0; i < propIters; i++ {
		g := randCap(rng)
		r := g + "." + randCap(rng) // strictly beneath g
		if !CoveredBy(r, []string{g}) {
			t.Fatalf("refinement violated: broad grant %q must cover %q beneath it", g, r)
		}
	}
}
