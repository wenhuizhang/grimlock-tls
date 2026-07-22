// Package attest provides Intel TDX remote attestation for Grimlock tunnels.
//
// It implements the RA-TLS (Remote Attestation TLS) pattern: a TDX quote is
// generated over REPORT_DATA = SHA-512(TLS public key) and embedded in the
// peer's X.509 certificate. During the TLS handshake the verifier extracts the
// quote, cryptographically verifies it against Intel roots, enforces a
// measurement policy (MRTD/RTMRs/TCB), and checks that REPORT_DATA binds the
// quote to the presented certificate key. This defeats quote-relay/MITM and
// happens entirely in-handshake, so it never touches Grimlock's kTLS data path.
package attest

import (
	"errors"
	"fmt"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
)

// ReportDataSize is the size of the TDX REPORT_DATA field (bytes).
const ReportDataSize = 64

// Quoter produces a TDX attestation quote bound to reportData. Implementations
// run inside a Trust Domain (TD) and talk to the platform quote-generation path.
type Quoter interface {
	// Quote returns a raw TDX quote whose REPORT_DATA equals reportData.
	Quote(reportData [ReportDataSize]byte) ([]byte, error)
}

// Verifier validates a raw TDX quote: signature + PCK chain to Intel roots,
// measurement policy, and the REPORT_DATA binding. On success it returns the
// measurements it observed (for logging/audit).
type Verifier interface {
	Verify(rawQuote []byte, expectedReportData [ReportDataSize]byte) (*Measurements, error)
}

// Measurements are the TD measurements extracted from a verified quote.
type Measurements struct {
	MRTD       []byte   // MR_TD: build-time measurement of the TD image (48 bytes)
	RTMRs      [][]byte // RTMR0..3: runtime-extended measurements (48 bytes each)
	TeeTcbSvn  []byte   // TEE_TCB_SVN: TDX module / TCB security version (16 bytes)
	Attachment []byte   // peer's attested attachment (capability manifest), bound by digest into the quote
}

// Policy pins what a peer TD must measure to be trusted. A nil/empty field is
// not enforced; production deployments must at least pin MRTD.
type Policy struct {
	// MRTD is the required MR_TD value (48 bytes). Nil = not pinned (logged loudly).
	MRTD []byte
	// RTMRs are required RTMR values; index i pins RTMRi. A nil entry skips that RTMR.
	RTMRs [][]byte
	// MinTeeTcbSvn is the component-wise minimum TEE_TCB_SVN (16 bytes). Nil = skip.
	MinTeeTcbSvn []byte
	// MrSeam pins the TDX module measurement MR_SEAM (48 bytes). Nil = skip.
	MrSeam []byte
	// TdAttributes pins TD_ATTRIBUTES exactly (8 bytes). Nil = skip.
	TdAttributes []byte
	// Xfam pins XFAM exactly (8 bytes). Nil = skip.
	Xfam []byte
	// AllowDebug permits a TD with the DEBUG attribute set. Must be false in prod.
	AllowDebug bool
	// GetCollateral fetches PCS collateral over the network to evaluate TCB status
	// and (optionally) revocation. False = offline verification using the quote's
	// own PCK chain to embedded Intel roots (signature + measurements only).
	GetCollateral bool
	// CheckRevocations fetches CRLs and rejects revoked PCK certs. Requires
	// GetCollateral. Ignored when GetCollateral is false.
	CheckRevocations bool
}

// tdAttrDebug is bit 0 of TD_ATTRIBUTES: the TD is debuggable when set.
const tdAttrDebug = 0x01

// TDXVerifier is the production Verifier backed by go-tdx-guest.
type TDXVerifier struct {
	policy Policy
}

// NewTDXVerifier returns a Verifier enforcing policy.
func NewTDXVerifier(policy Policy) *TDXVerifier {
	return &TDXVerifier{policy: policy}
}

// Verify implements Verifier.
func (v *TDXVerifier) Verify(rawQuote []byte, expectedReportData [ReportDataSize]byte) (*Measurements, error) {
	if len(rawQuote) == 0 {
		return nil, errors.New("empty quote")
	}

	// 1. Structural parse into a typed QuoteV4.
	parsed, err := abi.QuoteToProto(rawQuote)
	if err != nil {
		return nil, fmt.Errorf("parse quote: %w", err)
	}
	quote, ok := parsed.(*pb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("unsupported quote type %T (want TDX QuoteV4)", parsed)
	}

	// 2. Cryptographic verification: ECDSA signature chain + PCK cert chain to the
	//    Intel SGX Root CA (embedded). Optionally pull collateral for TCB/CRL.
	vopts := verify.DefaultOptions()
	vopts.GetCollateral = v.policy.GetCollateral
	vopts.CheckRevocations = v.policy.GetCollateral && v.policy.CheckRevocations
	if err := verify.TdxQuote(quote, vopts); err != nil {
		return nil, fmt.Errorf("quote cryptographic verification failed: %w", err)
	}

	// 3. Policy + channel binding. validate enforces REPORT_DATA == expected, which
	//    is what binds this quote to the presented TLS certificate key.
	valOpts := &validate.Options{
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
			ReportData:       expectedReportData[:],
			MrTd:             v.policy.MRTD,
			Rtmrs:            v.policy.RTMRs,
			MinimumTeeTcbSvn: v.policy.MinTeeTcbSvn,
			MrSeam:           v.policy.MrSeam,
			TdAttributes:     v.policy.TdAttributes,
			Xfam:             v.policy.Xfam,
		},
	}
	if err := validate.TdxQuote(quote, valOpts); err != nil {
		return nil, fmt.Errorf("policy/binding validation failed: %w", err)
	}

	body := quote.GetTdQuoteBody()

	// 4. Debug guard: a debuggable TD offers no confidentiality guarantee.
	if !v.policy.AllowDebug {
		if attrs := body.GetTdAttributes(); len(attrs) >= 1 && attrs[0]&tdAttrDebug != 0 {
			return nil, errors.New("peer TD has DEBUG attribute set; rejected by policy")
		}
	}

	return &Measurements{
		MRTD:      body.GetMrTd(),
		RTMRs:     body.GetRtmrs(),
		TeeTcbSvn: body.GetTeeTcbSvn(),
	}, nil
}
