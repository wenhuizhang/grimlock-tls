// Package authz holds the canonical binding transcript that realizes the
// Grimlock authorization model (docs/model.md). Every binding in the system —
// the attestation gate's REPORT_DATA context and each x402 payment binding — is
// constructed through one injective encoding, so that "the quote commits to X"
// is sound (lemma L2: distinct field sequences produce distinct byte strings).
package authz

import "encoding/binary"

// transcriptVersion guards the encoding; bump it on any format change so two
// versions can never produce a colliding transcript.
const transcriptVersion = 1

// Transcript is an append-only, length-prefixed (hence prefix-free, hence
// injective) sequence of domain-tagged fields. Its bytes are what EKM binds or
// what is hashed; never hand-concatenate digests anywhere else.
//
// Wire format:
//
//	version(1) ‖ field*        field = u32(len label) ‖ label ‖ u32(len value) ‖ value
//
// Length prefixes make the encoding injective: there is exactly one field
// sequence that yields any given byte string, so no two distinct bindings
// collide and no field can be smuggled into an adjacent one.
type Transcript struct {
	buf []byte
}

// New starts a transcript in a domain. The domain is the first field, so
// transcripts in different domains can never collide regardless of later fields.
func New(domain string) *Transcript {
	t := &Transcript{buf: []byte{transcriptVersion}}
	return t.Str("domain", domain)
}

// Field appends a length-prefixed labeled byte field and returns t for chaining.
func (t *Transcript) Field(label string, value []byte) *Transcript {
	t.buf = appendLP(t.buf, []byte(label))
	t.buf = appendLP(t.buf, value)
	return t
}

// Str appends a string-valued field.
func (t *Transcript) Str(label, value string) *Transcript {
	return t.Field(label, []byte(value))
}

// U64 appends a fixed-width big-endian integer field (e.g. the attestation epoch).
func (t *Transcript) U64(label string, v uint64) *Transcript {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return t.Field(label, b[:])
}

// Bytes returns the encoded transcript — the value bound by EKM.
func (t *Transcript) Bytes() []byte { return t.buf }

func appendLP(dst, b []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	dst = append(dst, l[:]...)
	return append(dst, b...)
}
