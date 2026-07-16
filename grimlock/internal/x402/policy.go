package x402

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"
)

// Policy is the spend policy enforced OUTSIDE the agent. Because Grimlock is on
// the agent's unbypassable (eBPF-intercepted) path and runs in its own measured
// TD, these limits hold even when the agent itself is hijacked (prompt
// injection): a genuine-but-compromised agent still cannot exceed them.
type Policy struct {
	// MaxPerPayment caps a single payment's value (smallest unit). nil = no cap.
	MaxPerPayment *big.Int
	// MaxPerEpoch caps total value within EpochDuration (velocity). nil = no cap.
	MaxPerEpoch   *big.Int
	EpochDuration time.Duration
	// AllowedPayTo, if non-empty, restricts recipients (lowercased addresses).
	AllowedPayTo map[string]bool
	// AllowedNetworks, if non-empty, restricts chains (e.g. "base", "base-sepolia").
	AllowedNetworks map[string]bool
}

// Decision is the enforcement outcome for one payment.
type Decision struct {
	Allow  bool
	Reason string
}

func allow() Decision { return Decision{Allow: true, Reason: "ok"} }
func deny(f string, a ...any) Decision {
	return Decision{Allow: false, Reason: fmt.Sprintf(f, a...)}
}

// Enforcer applies a Policy and tracks per-epoch velocity. Safe for concurrent
// use. Construct with NewEnforcer; nowFn is injectable for testing.
type Enforcer struct {
	policy Policy
	nowFn  func() time.Time

	mu         sync.Mutex
	epochStart time.Time
	spent      *big.Int
}

func NewEnforcer(p Policy) *Enforcer {
	return &Enforcer{policy: p, nowFn: time.Now, spent: new(big.Int)}
}

// Evaluate decides whether a payment is permitted and, if so, records it against
// the epoch velocity budget. A denied payment does NOT consume budget.
func (e *Enforcer) Evaluate(p *PaymentPayload) Decision {
	amount, err := p.Amount()
	if err != nil {
		return deny("unparseable amount: %v", err)
	}
	if amount.Sign() < 0 {
		return deny("negative amount")
	}

	if len(e.policy.AllowedNetworks) > 0 && !e.policy.AllowedNetworks[p.Network] {
		return deny("network %q not allowed", p.Network)
	}
	if len(e.policy.AllowedPayTo) > 0 {
		to := strings.ToLower(p.PayTo())
		if to == "" || !e.policy.AllowedPayTo[to] {
			return deny("payTo %q not in allowlist", p.PayTo())
		}
	}
	if e.policy.MaxPerPayment != nil && amount.Cmp(e.policy.MaxPerPayment) > 0 {
		return deny("amount %s exceeds per-payment cap %s", amount, e.policy.MaxPerPayment)
	}

	// Velocity: roll the epoch, then check the running total would stay within cap.
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.nowFn()
	if e.policy.EpochDuration > 0 && now.Sub(e.epochStart) >= e.policy.EpochDuration {
		e.epochStart = now
		e.spent = new(big.Int)
	}
	if e.policy.MaxPerEpoch != nil {
		projected := new(big.Int).Add(e.spent, amount)
		if projected.Cmp(e.policy.MaxPerEpoch) > 0 {
			return deny("epoch spend %s + %s exceeds cap %s", e.spent, amount, e.policy.MaxPerEpoch)
		}
		e.spent = projected
	}
	return allow()
}

// MatchesChallenge verifies a payment answers exactly the 402 challenge: same
// recipient and network, and amount within the challenge's maximum. Prevents a
// payment from being accepted against a different/larger challenge than issued.
func MatchesChallenge(payload *PaymentPayload, c *PaymentRequirements) error {
	if !strings.EqualFold(payload.PayTo(), c.PayTo) {
		return fmt.Errorf("payTo %q does not match challenge %q", payload.PayTo(), c.PayTo)
	}
	if payload.Network != c.Network {
		return fmt.Errorf("network %q does not match challenge %q", payload.Network, c.Network)
	}
	amt, err := payload.Amount()
	if err != nil {
		return err
	}
	if max, ok := new(big.Int).SetString(c.MaxAmountRequired, 10); ok && amt.Cmp(max) > 0 {
		return fmt.Errorf("amount %s exceeds challenge max %s", amt, max)
	}
	return nil
}

// PolicyDigest is a stable hash of the spend policy, bound into payment quotes so
// a receipt proves which policy authorized the payment.
func PolicyDigest(p Policy) [32]byte {
	h := sha256.New()
	writeField(h, "x402-policy")
	writeField(h, bigString(p.MaxPerPayment))
	writeField(h, bigString(p.MaxPerEpoch))
	writeField(h, p.EpochDuration.String())
	for _, k := range sortedKeys(p.AllowedPayTo) {
		writeField(h, "payto:"+k)
	}
	for _, k := range sortedKeys(p.AllowedNetworks) {
		writeField(h, "net:"+k)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func bigString(v *big.Int) string {
	if v == nil {
		return ""
	}
	return v.String()
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// LowerSet builds an allowlist set from addresses (lowercased).
func LowerSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		if it = strings.TrimSpace(it); it != "" {
			m[strings.ToLower(it)] = true
		}
	}
	return m
}
