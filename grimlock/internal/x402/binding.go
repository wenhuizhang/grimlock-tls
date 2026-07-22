package x402

import (
	"crypto/sha256"
	"io"
)

// BindingHash returns a 32-byte commitment to the essential, immutable terms of
// a payment: network, scheme, recipient, value, and the one-time nonce. Grimlock
// feeds this into the attestation gate's exporter context
// (REPORT_DATA = EKM(context = BindingHash)), so the resulting TDX quote proves:
// "this measured agent, on this TLS session, authorized THIS payment."
//
// Because the EIP-3009 nonce is single-use, the hash is unique per payment; the
// EKM makes it session-bound. Together they defeat payment relay/replay: a quote
// bound to one payment+session cannot be reused for another.
func BindingHash(p *PaymentPayload) [32]byte {
	h := sha256.New()
	writeField(h, "x402")
	writeField(h, p.Network)
	writeField(h, p.Scheme)
	if p.Payload != nil && p.Payload.Authorization != nil {
		a := p.Payload.Authorization
		writeField(h, a.From)
		writeField(h, a.To)
		writeField(h, a.Value)
		writeField(h, a.Nonce)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ChallengeDigest commits to the essential terms of a 402 PaymentRequirements
// (the challenge). Binding a payment quote to this proves the payment answers
// exactly the challenge the server issued for the resource, not a different one.
func ChallengeDigest(c *PaymentRequirements) [32]byte {
	h := sha256.New()
	writeField(h, "x402-challenge")
	writeField(h, c.Scheme)
	writeField(h, c.Network)
	writeField(h, c.MaxAmountRequired)
	writeField(h, c.PayTo)
	writeField(h, c.Asset)
	writeField(h, c.Resource)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// writeField writes a length-prefixed field so concatenation is unambiguous.
func writeField(h io.Writer, s string) {
	var l [4]byte
	n := uint32(len(s))
	l[0] = byte(n >> 24)
	l[1] = byte(n >> 16)
	l[2] = byte(n >> 8)
	l[3] = byte(n)
	_, _ = h.Write(l[:])
	_, _ = io.WriteString(h, s)
}
