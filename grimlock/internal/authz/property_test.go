package authz

import (
	"bytes"
	"math/rand"
	"testing"
)

// Property tests binding the Go transcript encoder to the injectivity lemma
// transcript_injective (L2) in ../../formal/Grimlock.v: distinct field sequences
// produce distinct encodings, so "the quote commits to exactly these fields" is
// sound. The Coq proves it about the length-prefixed encoding; these check the Go
// realizes it.

type fieldSeq struct{ labels, values []string }

func sameSeq(x, y fieldSeq) bool {
	if len(x.labels) != len(y.labels) {
		return false
	}
	for i := range x.labels {
		if x.labels[i] != y.labels[i] || x.values[i] != y.values[i] {
			return false
		}
	}
	return true
}

// Random: no two DISTINCT field sequences ever encode to the same bytes. The
// alphabet deliberately includes overlapping prefixes (a, ab, b, bc) that would
// collide if the length-prefixing were wrong.
func TestProp_TranscriptInjective(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	labels := []string{"", "a", "ab", "b", "x", "domain"}
	values := []string{"", "a", "ab", "abc", "b", "bc"}
	seen := make(map[string]fieldSeq)
	for i := 0; i < 200000; i++ {
		var s fieldSeq
		tr := New("d")
		for n := rng.Intn(4); n > 0; n-- {
			l := labels[rng.Intn(len(labels))]
			v := values[rng.Intn(len(values))]
			s.labels = append(s.labels, l)
			s.values = append(s.values, v)
			tr.Str(l, v)
		}
		key := string(tr.Bytes())
		if prev, ok := seen[key]; ok && !sameSeq(prev, s) {
			t.Fatalf("transcript collision: %+v and %+v encode identically", prev, s)
		}
		seen[key] = s
	}
}

// Targeted: the classic concatenation ambiguities that length-prefixing must
// defeat — both the field-boundary split and the label|value split.
func TestTranscript_ConcatAmbiguity(t *testing.T) {
	if bytes.Equal(
		New("d").Str("x", "ab").Str("x", "c").Bytes(),
		New("d").Str("x", "a").Str("x", "bc").Bytes(),
	) {
		t.Fatal("not injective: fields (ab,c) and (a,bc) collide — length prefix broken")
	}
	if bytes.Equal(
		New("d").Str("ab", "c").Bytes(),
		New("d").Str("a", "bc").Bytes(),
	) {
		t.Fatal("not injective: (label=ab,value=c) and (label=a,value=bc) collide")
	}
	// Domain separation: the same later fields under different domains never collide.
	if bytes.Equal(New("d1").Str("x", "v").Bytes(), New("d2").Str("x", "v").Bytes()) {
		t.Fatal("domain not bound: different domains produce colliding transcripts")
	}
}
