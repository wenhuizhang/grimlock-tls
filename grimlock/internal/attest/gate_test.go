package attest

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// Distinct instance keys for the two ends of a test gate (client=A, server=B).
var (
	testKeyA = [32]byte{0xA}
	testKeyB = [32]byte{0xB}
)

// fixedQuoter returns a constant quote and records the report data (binding) it
// was asked to commit to. Test stub.
type fixedQuoter struct {
	quote []byte
	seen  [ReportDataSize]byte
}

func (q *fixedQuoter) Quote(rd [ReportDataSize]byte) ([]byte, error) {
	q.seen = rd
	return q.quote, nil
}

// recordingVerifier captures what it verified and can be forced to fail.
type recordingVerifier struct {
	gotQuote []byte
	gotRD    [ReportDataSize]byte
	fail     bool
}

func (v *recordingVerifier) Verify(quote []byte, rd [ReportDataSize]byte) (*Measurements, error) {
	v.gotQuote = quote
	v.gotRD = rd
	if v.fail {
		return nil, errors.New("policy rejected")
	}
	return &Measurements{MRTD: []byte("mrtd")}, nil
}

// stubExporter models a TLS exporter: deterministic in (context) and identical
// on both ends of the same "session". (A real session derives this from secrets
// neither a relay nor a MITM can know.)
func stubExporter(ctx []byte) ([ReportDataSize]byte, error) {
	return sha512.Sum512(append([]byte("session-ekm:"), ctx...)), nil
}

func runPair(t *testing.T, a, b net.Conn, gA, gB *GateConfig, fresh bool) (mA *Measurements, rA, rB error) {
	t.Helper()
	type res struct {
		m   *Measurements
		err error
	}
	ca, cb := make(chan res, 1), make(chan res, 1)
	go func() { m, err := gA.Run(a, stubExporter, true, fresh, testKeyA, testKeyB); ca <- res{m, err} }()
	go func() { m, err := gB.Run(b, stubExporter, false, fresh, testKeyB, testKeyA); cb <- res{m, err} }()
	x, y := <-ca, <-cb
	return x.m, x.err, y.err
}

// TestGate_InstanceIdentityRejected: when the server's instance allowlist does
// not contain the client's key, the gate fails closed (the model's
// `Policy says K ⇒ TrustedPeer` premise is unsatisfied).
func TestGate_InstanceIdentityRejected(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	gA := &GateConfig{Quoter: &fixedQuoter{quote: []byte("A")}, Verifier: &recordingVerifier{}, Timeout: time.Second}
	gB := &GateConfig{
		Quoter: &fixedQuoter{quote: []byte("B")}, Verifier: &recordingVerifier{}, Timeout: time.Second,
		CheckPeerIdentity: func(k [32]byte) error {
			if k != testKeyB { // peer (A) is testKeyA, not allowed
				return fmt.Errorf("instance key %x not in allowlist", k)
			}
			return nil
		},
	}
	_, eA, eB := runPair(t, a, b, gA, gB, false)
	if eA == nil && eB == nil {
		t.Fatal("gate must fail when the peer instance key is not authorized")
	}
	if !errors.Is(eB, ErrTrustFailure) {
		t.Fatalf("rejection should be a trust failure, got %v", eB)
	}
}

// TestGate_Resume: with a shared resumption secret both ends resume (no quote);
// a mismatched secret fails closed.
func TestGate_Resume(t *testing.T) {
	run := func(rsA, rsB []byte) (error, error) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		g := &GateConfig{Timeout: time.Second}
		ca := make(chan error, 1)
		go func() { ca <- g.Resume(a, stubExporter, true, rsA) }()
		eb := g.Resume(b, stubExporter, false, rsB)
		return <-ca, eb
	}
	rs := bytes.Repeat([]byte{0x5a}, 32)
	if eA, eB := run(rs, rs); eA != nil || eB != nil {
		t.Fatalf("matching resumption secret should resume: A=%v B=%v", eA, eB)
	}
	eA, eB := run(rs, bytes.Repeat([]byte{0x01}, 32))
	if eA == nil && eB == nil {
		t.Fatal("mismatched resumption secret must fail")
	}
	if !errors.Is(eB, ErrTrustFailure) {
		t.Fatalf("resume mismatch should be a trust failure, got %v", eB)
	}
}

// TestGate_AgentMeasurement: the advertised agent measurement is bound and
// pinned — a matching value passes, a mismatch fails closed.
func TestGate_AgentMeasurement(t *testing.T) {
	run := func(advertise, pin string) (error, error) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		gA := &GateConfig{
			Quoter: &fixedQuoter{quote: []byte("A")}, Verifier: &recordingVerifier{}, Timeout: time.Second,
			LocalAgentMeasurement: []byte(advertise),
		}
		gB := &GateConfig{
			Quoter: &fixedQuoter{quote: []byte("B")}, Verifier: &recordingVerifier{}, Timeout: time.Second,
			CheckPeerAgentMeasurement: func(got []byte) error {
				if string(got) != pin {
					return fmt.Errorf("agent measurement %q != pinned %q", got, pin)
				}
				return nil
			},
		}
		_, eA, eB := runPair(t, a, b, gA, gB, false)
		return eA, eB
	}

	if eA, eB := run("agent-x", "agent-x"); eA != nil || eB != nil {
		t.Fatalf("matching agent measurement should pass: A=%v B=%v", eA, eB)
	}
	eA, eB := run("agent-x", "agent-y")
	if eA == nil && eB == nil {
		t.Fatal("gate must fail on agent-measurement mismatch")
	}
	if !errors.Is(eB, ErrTrustFailure) {
		t.Fatalf("mismatch should be a trust failure, got %v", eB)
	}
}

func TestGate_MutualSuccessAndBinding(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	qa, qb := &fixedQuoter{quote: []byte("QUOTE-A")}, &fixedQuoter{quote: []byte("QUOTE-B")}
	va, vb := &recordingVerifier{}, &recordingVerifier{}
	gA := &GateConfig{Quoter: qa, Verifier: va, Timeout: 2 * time.Second}
	gB := &GateConfig{Quoter: qb, Verifier: vb, Timeout: 2 * time.Second}

	mA, eA, eB := runPair(t, a, b, gA, gB, false)
	if eA != nil || eB != nil {
		t.Fatalf("expected mutual success, got A=%v B=%v", eA, eB)
	}
	if mA == nil || string(mA.MRTD) != "mrtd" {
		t.Fatalf("missing measurements")
	}
	// Each side verified the OTHER's quote, both bound to the SAME session value.
	if !bytes.Equal(va.gotQuote, []byte("QUOTE-B")) || !bytes.Equal(vb.gotQuote, []byte("QUOTE-A")) {
		t.Fatal("quotes not exchanged correctly")
	}
	if va.gotRD != vb.gotRD || qa.seen != va.gotRD {
		t.Fatal("binding value not shared/enforced across the session")
	}
}

// The barrier: if one side's appraisal fails, the OTHER side must NOT proceed,
// even though its own appraisal passed. This is the honest-risk fix.
func TestGate_BarrierBlocksWhenPeerRejects(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// A rejects B; B accepts A.
	gA := &GateConfig{Quoter: &fixedQuoter{quote: []byte("A")}, Verifier: &recordingVerifier{fail: true}, Timeout: time.Second}
	gB := &GateConfig{Quoter: &fixedQuoter{quote: []byte("B")}, Verifier: &recordingVerifier{}, Timeout: time.Second}

	_, eA, eB := runPair(t, a, b, gA, gB, false)
	if eA == nil {
		t.Fatal("A should fail: it rejected the peer")
	}
	if eB == nil {
		t.Fatal("B should fail at the barrier: its own appraisal passed but the peer NAK'd it")
	}
}

// Freshness: two re-attestation rounds over the same session derive different
// binding values (different nonces), so a replayed quote cannot pass round 2.
func TestGate_FreshRoundsDifferPerNonce(t *testing.T) {
	round := func() [ReportDataSize]byte {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		qa := &fixedQuoter{quote: []byte("A")}
		gA := &GateConfig{Quoter: qa, Verifier: &recordingVerifier{}, Timeout: time.Second}
		gB := &GateConfig{Quoter: &fixedQuoter{quote: []byte("B")}, Verifier: &recordingVerifier{}, Timeout: time.Second}
		_, eA, eB := runPair(t, a, b, gA, gB, true) // fresh = true
		if eA != nil || eB != nil {
			t.Fatalf("fresh round failed: A=%v B=%v", eA, eB)
		}
		return qa.seen
	}
	first, second := round(), round()
	if first == second {
		t.Fatal("two fresh rounds produced the same binding value (nonce not applied)")
	}
}

func TestGate_TimeoutWhenPeerSilent(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = b
	g := &GateConfig{Quoter: &fixedQuoter{quote: []byte("A")}, Verifier: &recordingVerifier{}, Timeout: 150 * time.Millisecond}
	if _, err := g.Run(a, stubExporter, true, false, testKeyA, testKeyB); err == nil {
		t.Fatal("expected timeout when peer is silent")
	}
}

// The capability check is folded into the gate: when the client rejects the
// peer's advertised attachment (manifest), BOTH sides fail (no forwarding).
func TestGate_AttachmentCheckBlocks(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	manifest := []byte(`[{"name":"del","capability":"fs.delete","scope":"system"}]`)
	gA := &GateConfig{ // client: rejects any non-empty peer attachment
		Quoter: &fixedQuoter{quote: []byte("A")}, Verifier: &recordingVerifier{}, Timeout: time.Second,
		CheckPeerAttachment: func(m []byte) error {
			if len(m) > 0 {
				return errors.New("privilege escalation")
			}
			return nil
		},
	}
	gB := &GateConfig{ // server: advertises the manifest
		Quoter: &fixedQuoter{quote: []byte("B")}, Verifier: &recordingVerifier{}, Timeout: time.Second,
		LocalAttachment: manifest,
	}
	_, eA, eB := runPair(t, a, b, gA, gB, false)
	if eA == nil {
		t.Fatal("client should reject the escalating manifest")
	}
	if eB == nil {
		t.Fatal("server should fail at the barrier after the client NAK")
	}
}

// The attachment is bound into the quote: a different attachment yields a
// different REPORT_DATA, so a manifest swap breaks quote verification.
func TestGate_AttachmentBindsIntoReportData(t *testing.T) {
	run := func(att []byte) [ReportDataSize]byte {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		qb := &fixedQuoter{quote: []byte("B")}
		gA := &GateConfig{Quoter: &fixedQuoter{quote: []byte("A")}, Verifier: &recordingVerifier{}, Timeout: time.Second}
		gB := &GateConfig{Quoter: qb, Verifier: &recordingVerifier{}, Timeout: time.Second, LocalAttachment: att}
		_, eA, eB := runPair(t, a, b, gA, gB, false)
		if eA != nil || eB != nil {
			t.Fatalf("gate failed: A=%v B=%v", eA, eB)
		}
		return qb.seen
	}
	if run([]byte("manifest-1")) == run([]byte("manifest-2")) {
		t.Fatal("REPORT_DATA must differ when the advertised attachment differs")
	}
}
