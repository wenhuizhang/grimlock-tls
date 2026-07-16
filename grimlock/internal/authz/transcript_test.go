package authz

import (
	"bytes"
	"testing"
)

// TestTranscriptInjective is lemma L2 (docs/model.md): distinct field sequences
// must produce distinct byte strings, including the adversarial cases where a
// naive concatenation would let one field's bytes masquerade as another's.
func TestTranscriptInjective(t *testing.T) {
	cases := []struct{ a, b *Transcript }{
		// boundary smuggling: ("ab","c") must not equal ("a","bc")
		{New("d").Str("ab", "c"), New("d").Str("a", "bc")},
		// field splitting: one field vs two that concatenate to the same bytes
		{New("d").Str("x", "12"), New("d").Str("x", "1").Str("", "2")},
		// label/value swap
		{New("d").Str("k", "v"), New("d").Str("v", "k")},
		// different domains, same later fields
		{New("d1").Str("x", "y"), New("d2").Str("x", "y")},
		// empty value vs absent field
		{New("d").Str("x", ""), New("d")},
		// integer vs its string form must not collide
		{New("d").U64("n", 49), New("d").Str("n", "1")}, // 0x31 == '1'
	}
	for i, c := range cases {
		if bytes.Equal(c.a.Bytes(), c.b.Bytes()) {
			t.Errorf("case %d: distinct transcripts collided:\n  a=%x\n  b=%x", i, c.a.Bytes(), c.b.Bytes())
		}
	}
}

// TestTranscriptDeterministic: the same field sequence always yields the same
// bytes (both peers must compute identical bindings).
func TestTranscriptDeterministic(t *testing.T) {
	mk := func() []byte {
		return New("gate").U64("epoch", 7).Str("client-key", "AAAA").Field("nonce", []byte{1, 2, 3}).Bytes()
	}
	if !bytes.Equal(mk(), mk()) {
		t.Fatal("transcript encoding is not deterministic")
	}
}
