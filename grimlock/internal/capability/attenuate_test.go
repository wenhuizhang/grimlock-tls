package capability

import (
	"reflect"
	"testing"
)

func TestAttenuate(t *testing.T) {
	cases := []struct {
		name            string
		upstream, local []string
		want            []string
	}{
		{"narrow-to-more-specific", []string{"fs"}, []string{"fs.read"}, []string{"fs.read"}},
		{"symmetric", []string{"fs.read"}, []string{"fs"}, []string{"fs.read"}},
		{"disjoint", []string{"fs"}, []string{"net"}, nil},
		{"per-branch", []string{"fs", "net"}, []string{"fs.read", "net.tcp"}, []string{"fs.read", "net.tcp"}},
		{"exact", []string{"fs.read"}, []string{"fs.read"}, []string{"fs.read"}},
		{"empty-upstream", nil, []string{"fs"}, nil},
	}
	for _, c := range cases {
		if got := Attenuate(c.upstream, c.local); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Attenuate(%v,%v)=%v want %v", c.name, c.upstream, c.local, got, c.want)
		}
	}
}

// TestAttenuate_SubsetOfBoth: every onward capability is covered by BOTH the
// upstream grant and the local policy — the soundness of the intersection
// (the runtime witness of Coq's covered_attenuation).
func TestAttenuate_SubsetOfBoth(t *testing.T) {
	upstream := []string{"fs", "net.tcp"}
	local := []string{"fs.read", "fs.write", "net", "db"}
	for _, c := range Attenuate(upstream, local) {
		if !CoveredBy(c, upstream) {
			t.Errorf("onward cap %q not covered by upstream grant", c)
		}
		if !CoveredBy(c, local) {
			t.Errorf("onward cap %q not covered by local policy", c)
		}
	}
}

// TestAttenuateChain_NonEscalating: authority only shrinks along A→B→C; the final
// grant stays covered by the origin, and a disjoint hop cannot re-introduce.
func TestAttenuateChain_NonEscalating(t *testing.T) {
	origin := []string{"fs"}
	final := AttenuateChain(origin, []string{"fs.read"}, []string{"fs.read.public"})
	if want := []string{"fs.read.public"}; !reflect.DeepEqual(final, want) {
		t.Fatalf("chain = %v, want %v", final, want)
	}
	for _, c := range final {
		if !CoveredBy(c, origin) {
			t.Errorf("chain result %q escaped the origin grant", c)
		}
	}
	if got := AttenuateChain([]string{"fs"}, []string{"net"}); got != nil {
		t.Errorf("disjoint hop must yield empty, got %v", got)
	}
}
