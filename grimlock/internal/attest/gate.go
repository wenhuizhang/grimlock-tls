package attest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/grimlock-ai/grimlock/internal/authz"
)

// EKMLabel is the RFC 8446 exporter label used to bind attestation evidence to
// the TLS session (RFC 9266-style channel binding). Both peers MUST use the same
// label; it is namespaced to avoid collision with other exporter users.
const EKMLabel = "EXPORTER-grimlock-tdx-attestation"

// PaymentEKMLabel binds an x402 payment quote to the TLS session (distinct
// exporter label so payment binding can never collide with the gate's).
const PaymentEKMLabel = "EXPORTER-grimlock-x402-payment"

const (
	// maxQuoteBytes bounds a peer-supplied quote frame (TDX quotes are ~4-10 KB).
	maxQuoteBytes = 1 << 16
	// nonceSize is the per-round freshness challenge length.
	nonceSize = 32
	// barrier verdict bytes.
	ackOK  = 0x01
	ackNAK = 0x00
)

// ErrTrustFailure marks a gate/resume failure that revokes trust in the peer (bad
// measurement, capability escalation, unauthorized instance/agent, failed resume,
// or the peer rejecting us) as opposed to a transient transport error. It is
// wrapped into the returned error so callers/tests can distinguish a trust
// revocation (errors.Is(err, ErrTrustFailure)) from a transient I/O failure.
var ErrTrustFailure = errors.New("attestation trust failure")

// Exporter derives the binding value (REPORT_DATA) for a round from the TLS
// session's exported keying material, optionally salted with a per-round context
// (a fresh nonce challenge for re-attestation). The same (session, context)
// yields the same value on both peers; a different session or context does not.
type Exporter func(context []byte) ([ReportDataSize]byte, error)

// GateConfig runs mutual TDX attestation over an established secure channel,
// after the TLS handshake (and, on the client, after kTLS) and before any
// application data. Evidence is bound to the session via the Exporter, so a
// quote captured from a different session is rejected (relay/MITM defeated).
type GateConfig struct {
	Quoter   Quoter
	Verifier Verifier
	Timeout  time.Duration // 0 = no deadline

	// LocalAttachment is opaque data this side advertises in the gate (e.g. its
	// MCP capability manifest). Its digest, together with the peer's, is folded
	// into the binding context, so the quote commits to it: a peer cannot
	// advertise one attachment and be measured serving another.
	LocalAttachment []byte
	// LocalAttachmentFunc, if set, overrides LocalAttachment at call time -- used
	// when the attachment is dynamic (e.g. auto-pulled from a live MCP server).
	LocalAttachmentFunc func() []byte
	// CheckPeerAttachment, if set, appraises the peer's attachment (e.g. a
	// capability-policy check on the peer's manifest). A non-nil error fails the
	// gate via the mutual barrier, so no application data is ever forwarded.
	CheckPeerAttachment func(peerAttachment []byte) error
	// CheckPeerIdentity, if set, authorizes the peer's instance key (the model's
	// `Policy says K ⇒ TrustedPeer`): measurement authenticates the code, the
	// instance key authenticates *which* TD, and this authorizes that instance.
	// A non-nil error fails the gate. nil = accept any instance with a golden
	// measurement (closed-membership-by-measurement).
	CheckPeerIdentity func(peerKey [32]byte) error

	// LocalAgentMeasurement is this host's *agent* code measurement (distinct from
	// the Grimlock TD's own MRTD/RTMR): the identity of the application behind this
	// Grimlock. It is advertised and its digest bound into the quote, decoupling
	// "which agent" from "which Grimlock". To be hardware-rooted the operator sets
	// it equal to an RTMR the agent extends at measured launch.
	LocalAgentMeasurement []byte
	// CheckPeerAgentMeasurement, if set, appraises the peer's advertised agent
	// measurement (e.g. pin an expected value). A non-nil error fails the gate.
	CheckPeerAgentMeasurement func(peerAgentMeasurement []byte) error
}

// Run performs one attestation round over conn and returns the peer's verified
// measurements. isClient fixes the canonical nonce ordering. When fresh is true
// a nonce challenge is exchanged first (required for re-attestation on an
// existing session, where the bare EKM is constant); when false the round binds
// to the session EKM directly (sufficient for the first round of a fresh
// session). A mutual ACK barrier ensures BOTH sides appraised successfully
// before either proceeds: the function only returns nil if our verification
// passed AND the peer signalled it accepted us.
// localKey/peerKey are the SHA-256 of each endpoint's TLS SubjectPublicKeyInfo,
// proven-of-possession by the TLS 1.3 CertificateVerify and folded into the
// binding so the quote commits to *which instance* terminates this channel.
func (g *GateConfig) Run(conn net.Conn, exp Exporter, isClient, fresh bool, localKey, peerKey [32]byte) (*Measurements, error) {
	if g.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(g.Timeout))
		defer conn.SetDeadline(time.Time{})
	}

	// 1. Optional fresh nonce challenge (re-attestation on a constant session EKM).
	var myNonce, peerNonce []byte
	if fresh {
		myNonce = make([]byte, nonceSize)
		if _, err := rand.Read(myNonce); err != nil {
			return nil, fmt.Errorf("nonce: %w", err)
		}
		var err error
		if peerNonce, err = exchangeFixed(conn, myNonce, nonceSize); err != nil {
			return nil, fmt.Errorf("nonce exchange: %w", err)
		}
	}

	// 2. Exchange attachments (e.g. capability manifests).
	localAtt := g.LocalAttachment
	if g.LocalAttachmentFunc != nil {
		localAtt = g.LocalAttachmentFunc()
	}
	peerAtt, err := exchangeBlob(conn, localAtt)
	if err != nil {
		return nil, fmt.Errorf("attachment exchange: %w", err)
	}
	ld := sha256.Sum256(localAtt)
	pd := sha256.Sum256(peerAtt)

	// 2b. Exchange agent measurements: the identity of the application behind each
	//     Grimlock, distinct from the Grimlock TD's own measurement.
	peerAgent, err := exchangeBlob(conn, g.LocalAgentMeasurement)
	if err != nil {
		return nil, fmt.Errorf("agent-measurement exchange: %w", err)
	}
	lad := sha256.Sum256(g.LocalAgentMeasurement)
	pad := sha256.Sum256(peerAgent)

	// 3. Build the canonical binding transcript (identical on both peers via the
	//    client/server field ordering) and derive REPORT_DATA = EKM(transcript).
	//    The quote thus commits to: this session, the nonces, both instance keys,
	//    both attachment digests, and both agent measurements.
	cn, sn, ck, sk, cm, sm, ca, sa := myNonce, peerNonce, localKey, peerKey, ld, pd, lad, pad
	if !isClient {
		cn, sn, ck, sk, cm, sm, ca, sa = peerNonce, myNonce, peerKey, localKey, pd, ld, pad, lad
	}
	t := authz.New("grimlock-tdx-gate")
	if fresh {
		t.Field("client-nonce", cn).Field("server-nonce", sn)
	}
	t.Field("client-key", ck[:]).Field("server-key", sk[:])
	t.Field("client-manifest", cm[:]).Field("server-manifest", sm[:])
	t.Field("client-agent", ca[:]).Field("server-agent", sa[:])

	rd, err := exp(t.Bytes())
	if err != nil {
		return nil, fmt.Errorf("export keying material: %w", err)
	}

	// 4. Generate our quote bound to rd and exchange quotes.
	myQuote, err := g.Quoter.Quote(rd)
	if err != nil {
		return nil, fmt.Errorf("generate local quote: %w", err)
	}
	peerQuote, err := exchangeFrame(conn, myQuote)
	if err != nil {
		return nil, fmt.Errorf("quote exchange: %w", err)
	}

	// 5. Appraise the peer: quote, attachment (capability), instance key, agent.
	m, verr := g.Verifier.Verify(peerQuote, rd)
	var cerr, ierr, aerr error
	if g.CheckPeerAttachment != nil {
		cerr = g.CheckPeerAttachment(peerAtt)
	}
	if g.CheckPeerIdentity != nil {
		ierr = g.CheckPeerIdentity(peerKey)
	}
	if g.CheckPeerAgentMeasurement != nil {
		aerr = g.CheckPeerAgentMeasurement(peerAgent)
	}

	// 6. Mutual barrier: announce our verdict, learn the peer's. We proceed only
	//    if WE accepted the peer (quote ∧ attachment ∧ identity ∧ agent) AND the
	//    peer accepted US.
	local := byte(ackOK)
	if verr != nil || cerr != nil || ierr != nil || aerr != nil {
		local = ackNAK
	}
	peerVerdict, xerr := exchangeFixed(conn, []byte{local}, 1)
	// Trust failures (bad measurement, capability escalation, unauthorized
	// instance, or the peer rejecting us) are wrapped with ErrTrustFailure so a
	// long-lived session can hard-kill on drift; transport/IO failures stay
	// unwrapped (transient → drain).
	if verr != nil {
		return nil, fmt.Errorf("peer attestation rejected: %w: %v", ErrTrustFailure, verr)
	}
	if cerr != nil {
		return nil, fmt.Errorf("peer capability check failed: %w: %v", ErrTrustFailure, cerr)
	}
	if ierr != nil {
		return nil, fmt.Errorf("peer instance not authorized: %w: %v", ErrTrustFailure, ierr)
	}
	if aerr != nil {
		return nil, fmt.Errorf("peer agent measurement rejected: %w: %v", ErrTrustFailure, aerr)
	}
	if xerr != nil {
		return nil, fmt.Errorf("verdict exchange: %w", xerr)
	}
	if peerVerdict[0] != ackOK {
		return nil, fmt.Errorf("%w: peer rejected our attestation or capabilities", ErrTrustFailure)
	}
	// Surface the peer's attested attachment (capability manifest) so the caller
	// can enforce individual tool calls against it on the wire — bound here because
	// its digest is committed in the quote we just verified.
	m.Attachment = peerAtt
	return m, nil
}

// ResumptionLabel derives the per-peer resumption secret from a full gate's TLS
// session (RFC 9266 exporter). Both attested parties compute the same value; it
// is secret to the session endpoints, so knowing it proves continuity of the
// attested identity on a later session.
const ResumptionLabel = "EXPORTER-grimlock-resumption"

// Resume performs a cheap attestation-resumption handshake IN PLACE OF a full
// quote exchange. Both parties prove knowledge of the resumption secret rs
// (established by an earlier full gate with this peer), bound to THIS session via
// expS2, authenticating continuity of the attested identity without generating or
// verifying a quote. Fails closed (ErrTrustFailure) if the peer cannot prove rs.
//
// Freshness: rs carries the earlier gate's TTL (the re-attestation interval);
// after it expires the caller must run a full gate again, so measurement drift is
// re-checked within the same window as periodic re-attestation.
func (g *GateConfig) Resume(conn net.Conn, expS2 Exporter, isClient bool, rs []byte) error {
	if g.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(g.Timeout))
		defer conn.SetDeadline(time.Time{})
	}
	// Bind to this session (expS2 = EKM of the new session): unique per session,
	// so a captured tag cannot be replayed onto a different session, and a MITM's
	// two legs have different binds.
	bind, err := expS2([]byte("grimlock-resume"))
	if err != nil {
		return fmt.Errorf("resume binding: %w", err)
	}
	myLabel, peerLabel := "client", "server"
	if !isClient {
		myLabel, peerLabel = "server", "client"
	}
	myTag := resumeTag(rs, myLabel, bind[:])
	peerWant := resumeTag(rs, peerLabel, bind[:])
	peerTag, err := exchangeFixed(conn, myTag, len(peerWant))
	if err != nil {
		return fmt.Errorf("resume tag exchange: %w", err)
	}
	if !hmac.Equal(peerTag, peerWant) {
		return fmt.Errorf("resume authentication failed: %w", ErrTrustFailure)
	}
	return nil
}

// resumeTag is a directional HMAC (label prevents reflection) over the
// session-bound value, keyed by the resumption secret.
func resumeTag(rs []byte, label string, bind []byte) []byte {
	m := hmac.New(sha256.New, rs)
	m.Write([]byte(label))
	m.Write(bind)
	return m.Sum(nil)
}

// exchangeFixed writes out and reads exactly inLen bytes, concurrently, so it
// does not deadlock on an unbuffered transport.
func exchangeFixed(conn net.Conn, out []byte, inLen int) ([]byte, error) {
	werr := make(chan error, 1)
	go func() { _, e := conn.Write(out); werr <- e }()
	in := make([]byte, inLen)
	_, rerr := io.ReadFull(conn, in)
	if e := <-werr; e != nil {
		return nil, e
	}
	if rerr != nil {
		return nil, rerr
	}
	return in, nil
}

// exchangeFrame writes our length-prefixed quote and reads the peer's, concurrently.
func exchangeFrame(conn net.Conn, out []byte) ([]byte, error) {
	werr := make(chan error, 1)
	go func() { werr <- writeFrame(conn, out) }()
	in, rerr := readFrame(conn)
	if e := <-werr; e != nil {
		return nil, e
	}
	if rerr != nil {
		return nil, rerr
	}
	return in, nil
}

// exchangeBlob is like exchangeFrame but allows a zero-length payload (an empty
// attachment), used for the manifest/attachment exchange.
func exchangeBlob(conn net.Conn, out []byte) ([]byte, error) {
	werr := make(chan error, 1)
	go func() { werr <- writeBlob(conn, out) }()
	in, rerr := readBlob(conn)
	if e := <-werr; e != nil {
		return nil, e
	}
	if rerr != nil {
		return nil, rerr
	}
	return in, nil
}

func writeBlob(conn net.Conn, b []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	_, err := conn.Write(b)
	return err
}

func readBlob(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxQuoteBytes {
		return nil, fmt.Errorf("attachment too large (%d)", n)
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(conn net.Conn, b []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(b)
	return err
}

func readFrame(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxQuoteBytes {
		return nil, fmt.Errorf("invalid quote length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// FormatMeasurements renders measurements as copy-pasteable Grimlock policy
// flags, for capturing golden values during --attest-measure-only bootstrap.
func FormatMeasurements(m *Measurements) string {
	var b strings.Builder
	fmt.Fprintf(&b, "    --attest-mrtd=%x\n", m.MRTD)
	for i, r := range m.RTMRs {
		if i > 3 {
			break
		}
		fmt.Fprintf(&b, "    --attest-rtmr%d=%x\n", i, r)
	}
	if len(m.TeeTcbSvn) > 0 {
		fmt.Fprintf(&b, "    # TEE_TCB_SVN observed: %x (pin a floor via --attest-min-tcb-svn)\n", m.TeeTcbSvn)
	}
	return b.String()
}
