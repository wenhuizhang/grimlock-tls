// Transparent x402 payment enforcement on the client forward path.
//
// Grimlock parses the agent's outgoing HTTP requests; for any carrying an
// X-PAYMENT header it (1) correlates the payment to the prior 402 challenge for
// that resource, (2) enforces the spend policy OUTSIDE the (possibly hijacked)
// agent, and (3) binds an allowed payment to a TDX quote whose REPORT_DATA
// commits to: the TLS session (EKM), the exact HTTP request (method/host/path),
// the payment terms, the 402 challenge, and the policy. A denied payment is
// blocked with a 403 and never reaches the wire; a tamper-evident receipt is
// recorded. Per-connection state (pending settlements, last challenge) is held in
// paymentConn, not shared across connections.

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/grimlock-ai/grimlock/internal/attest"
	"github.com/grimlock-ai/grimlock/internal/authz"
	"github.com/grimlock-ai/grimlock/internal/x402"
)

// paymentAuthDomain separates this REPORT_DATA use from any other.
const paymentAuthDomain = "grimlock-x402-auth-v2\x00"

// x402Enforcer is shared across connections: policy, quoter, receipt log, and the
// policy digest. Per-connection state lives in paymentConn.
type x402Enforcer struct {
	enforcer     *x402.Enforcer
	quoter       attest.Quoter // optional; nil = no per-payment binding quote (off-TD)
	log          *ReceiptLog
	bind         bool
	policyDigest [32]byte
}

func newX402Enforcer(p x402.Policy, quoter attest.Quoter, rlog *ReceiptLog, bind bool) *x402Enforcer {
	return &x402Enforcer{
		enforcer:     x402.NewEnforcer(p),
		quoter:       quoter,
		log:          rlog,
		bind:         bind,
		policyDigest: x402.PolicyDigest(p),
	}
}

// factory builds a per-connection x402 enforcer for the guarded pipeline. The
// paymentConn implements requestEnforcer (per-request check), responseHandler
// (402/settlement sniff), and finisher (flush pending receipts). exporter binds
// payment quotes to this TLS session via EKM; epoch is the attestation epoch.
func (xe *x402Enforcer) factory() enforcerFactory {
	return func(cc channelContext) any {
		return &paymentConn{xe: xe, exporter: cc.exp, epoch: cc.epoch}
	}
}

// paymentConn holds per-connection enforcement state.
type paymentConn struct {
	xe       *x402Enforcer
	exporter attest.Exporter
	epoch    uint64 // attestation epoch bound into payment quotes

	mu        sync.Mutex
	pending   []*Receipt                // allowed payments awaiting settlement, FIFO
	challenge *x402.PaymentRequirements // most recent unconsumed 402 challenge
}

// enforce vets one request: non-payment requests pass through; a payment is
// correlated to the prior 402 challenge, policy-evaluated, recorded, and blocked
// or permitted. (The pipeline in guard.go forwards permitted requests.)
func (pc *paymentConn) enforce(req *http.Request, body []byte, deny io.Writer) error {
	hv := req.Header.Get(x402.HeaderPayment)
	if hv == "" {
		return nil // not a payment: passthrough
	}
	payload, perr := x402.DecodePaymentHeader(hv)
	if perr != nil {
		pc.record(req, nil, nil, x402.Decision{Allow: false, Reason: "malformed X-PAYMENT"})
		writeBlocked(deny, "malformed X-PAYMENT")
		return errors.New("malformed X-PAYMENT")
	}
	challenge := pc.takeChallenge()
	d := pc.evaluate(payload, challenge)
	rcpt := pc.record(req, payload, challenge, d)
	if !d.Allow {
		metrics.paymentsBlocked.Add(1)
		log.Printf("[X402] BLOCK %s %s to=%s value=%s: %s",
			req.Method, req.URL.Path, payload.PayTo(), valueOf(payload), d.Reason)
		writeBlocked(deny, d.Reason)
		return errors.New(d.Reason)
	}
	metrics.paymentsAllowed.Add(1)
	log.Printf("[X402] ALLOW %s %s to=%s value=%s net=%s bind=%s",
		req.Method, req.URL.Path, payload.PayTo(), valueOf(payload), payload.Network, shortBind(rcpt))
	return nil
}

// evaluate enforces both the 402-challenge correlation and the spend policy.
func (pc *paymentConn) evaluate(payload *x402.PaymentPayload, challenge *x402.PaymentRequirements) x402.Decision {
	if challenge != nil {
		if err := x402.MatchesChallenge(payload, challenge); err != nil {
			return x402.Decision{Allow: false, Reason: "payment does not match 402 challenge: " + err.Error()}
		}
	}
	return pc.xe.enforcer.Evaluate(payload)
}

// handleResponses owns the tunnel→agent direction: it parses responses, captures
// 402 challenges and settlement results, and re-emits each response to the agent.
// Parsing (rather than teeing) ensures the challenge is recorded BEFORE the agent
// can retry.
func (pc *paymentConn) handleResponses(tunnelConn, agentConn net.Conn) {
	br := bufio.NewReader(tunnelConn)
	for {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return
		}
		if resp.StatusCode == x402.StatusPaymentRequired {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
			if pr, e := x402.DecodePaymentRequired(body); e == nil && len(pr.Accepts) > 0 {
				pc.setChallenge(&pr.Accepts[0])
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
		} else if hv := resp.Header.Get(x402.HeaderPaymentResponse); hv != "" {
			if s, e := x402.DecodeSettleResponse(hv); e == nil {
				pc.finalizePending(s)
			}
		}
		if err := resp.Write(agentConn); err != nil {
			return
		}
	}
}

// record builds and stores a receipt, generating the per-payment binding quote
// on allow.
func (pc *paymentConn) record(req *http.Request, payload *x402.PaymentPayload, challenge *x402.PaymentRequirements, d x402.Decision) *Receipt {
	if payload == nil && d.Allow {
		return nil
	}
	r := &Receipt{Time: time.Now(), Method: req.Method, Allowed: d.Allow, Reason: d.Reason}
	if payload != nil {
		r.Network = payload.Network
		r.PayTo = payload.PayTo()
		r.Value = valueOf(payload)
		bh := x402.BindingHash(payload)
		r.BindingHash = fmt.Sprintf("%x", bh)
		if d.Allow && pc.xe.bind && pc.xe.quoter != nil {
			if rd, err := pc.reportData(req, payload, challenge); err != nil {
				log.Printf("[X402] binding report-data failed: %v", err)
			} else if q, qerr := pc.xe.quoter.Quote(rd); qerr != nil {
				log.Printf("[X402] binding quote failed: %v", qerr)
			} else {
				r.QuoteB64 = base64.StdEncoding.EncodeToString(q)
			}
		}
	}
	if !d.Allow {
		pc.appendReceipt(r) // terminal: no settlement expected
		return r
	}
	pc.addPending(r)
	return r
}

// reportData binds the payment quote, via the canonical transcript, to the
// session (EKM), the attestation epoch, the exact HTTP request, the payment
// terms, the 402 challenge, and the policy. The session exporter is mandatory:
// binding is only enabled in attested mode (enforced at startup), so there is no
// silent non-session-bound fallback.
func (pc *paymentConn) reportData(req *http.Request, payload *x402.PaymentPayload, challenge *x402.PaymentRequirements) ([attest.ReportDataSize]byte, error) {
	var zero [attest.ReportDataSize]byte
	if pc.exporter == nil {
		return zero, fmt.Errorf("payment binding requires a session exporter")
	}
	bh := x402.BindingHash(payload)
	t := authz.New(paymentAuthDomain).
		U64("epoch", pc.epoch).
		Str("method", req.Method).
		Str("host", req.Host).
		Str("path", req.URL.Path).
		Field("payment", bh[:])
	if challenge != nil {
		cd := x402.ChallengeDigest(challenge)
		t.Field("challenge", cd[:])
	}
	t.Field("policy", pc.xe.policyDigest[:])
	return pc.exporter(t.Bytes()) // EKM(context = transcript): session-bound, 64 bytes
}

func (pc *paymentConn) setChallenge(c *x402.PaymentRequirements) {
	pc.mu.Lock()
	pc.challenge = c
	pc.mu.Unlock()
}

func (pc *paymentConn) takeChallenge() *x402.PaymentRequirements {
	pc.mu.Lock()
	c := pc.challenge
	pc.challenge = nil
	pc.mu.Unlock()
	return c
}

func (pc *paymentConn) addPending(r *Receipt) {
	pc.mu.Lock()
	pc.pending = append(pc.pending, r)
	pc.mu.Unlock()
}

func (pc *paymentConn) finalizePending(s *x402.SettleResponse) {
	pc.mu.Lock()
	var r *Receipt
	if len(pc.pending) > 0 {
		r, pc.pending = pc.pending[0], pc.pending[1:]
	}
	pc.mu.Unlock()
	if r == nil {
		return
	}
	r.SettleTx = s.Transaction
	r.SettleOK = s.Success
	pc.appendReceipt(r)
}

// finish flushes any pending receipts (settlements that never arrived) when the
// connection closes — the finisher hook in the guarded pipeline.
func (pc *paymentConn) finish() {
	pc.mu.Lock()
	p := pc.pending
	pc.pending = nil
	pc.mu.Unlock()
	for _, r := range p {
		pc.appendReceipt(r)
	}
}

func (pc *paymentConn) appendReceipt(r *Receipt) {
	if err := pc.xe.log.Append(r); err != nil {
		log.Printf("[X402] receipt append failed: %v", err)
	}
}

func valueOf(p *x402.PaymentPayload) string {
	if a, err := p.Amount(); err == nil {
		return a.String()
	}
	return "?"
}

func shortBind(r *Receipt) string {
	if r == nil || len(r.BindingHash) < 16 {
		return "-"
	}
	q := ""
	if r.QuoteB64 != "" {
		q = "+quote"
	}
	return r.BindingHash[:16] + q
}

// writeBlocked sends a 403 back to the agent for a policy-denied payment.
func writeBlocked(w io.Writer, reason string) {
	body := fmt.Sprintf("{\"error\":\"payment blocked by Grimlock policy\",\"reason\":%q}\n", reason)
	fmt.Fprintf(w, "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}
