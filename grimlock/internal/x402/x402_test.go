package x402

import (
	"math/big"
	"testing"
	"time"
)

func payment(network, to, value, nonce string) *PaymentPayload {
	return &PaymentPayload{
		X402Version: 1,
		Scheme:      "exact",
		Network:     network,
		Payload: &ExactEvmPayload{
			Signature: "0xsig",
			Authorization: &ExactEvmPayloadAuthorization{
				From: "0xPayer", To: to, Value: value,
				ValidAfter: "0", ValidBefore: "9999999999", Nonce: nonce,
			},
		},
	}
}

func TestPaymentHeaderRoundTrip(t *testing.T) {
	p := payment("base-sepolia", "0xMerchant", "10000", "0xnonce")
	hdr, err := EncodePaymentHeader(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePaymentHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if got.Network != "base-sepolia" || got.PayTo() != "0xMerchant" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	amt, err := got.Amount()
	if err != nil || amt.Cmp(big.NewInt(10000)) != 0 {
		t.Fatalf("amount = %v, %v", amt, err)
	}
}

func TestPolicy_AllowsWithinLimits(t *testing.T) {
	e := NewEnforcer(Policy{
		MaxPerPayment:   big.NewInt(50000),
		AllowedPayTo:    LowerSet([]string{"0xMerchant"}),
		AllowedNetworks: map[string]bool{"base-sepolia": true},
	})
	if d := e.Evaluate(payment("base-sepolia", "0xMERCHANT", "10000", "n1")); !d.Allow {
		t.Fatalf("expected allow, got deny: %s", d.Reason)
	}
}

func TestPolicy_DeniesOverPerPaymentCap(t *testing.T) {
	e := NewEnforcer(Policy{MaxPerPayment: big.NewInt(9999)})
	if d := e.Evaluate(payment("base", "0xM", "10000", "n1")); d.Allow {
		t.Fatal("expected deny on per-payment cap")
	}
}

func TestPolicy_DeniesDisallowedPayToAndNetwork(t *testing.T) {
	e := NewEnforcer(Policy{
		AllowedPayTo:    LowerSet([]string{"0xGood"}),
		AllowedNetworks: map[string]bool{"base": true},
	})
	if d := e.Evaluate(payment("base", "0xEvil", "1", "n1")); d.Allow {
		t.Fatal("expected deny: payTo not in allowlist")
	}
	if d := e.Evaluate(payment("solana", "0xGood", "1", "n2")); d.Allow {
		t.Fatal("expected deny: network not allowed")
	}
}

func TestPolicy_VelocityCapAndEpochReset(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	e := NewEnforcer(Policy{MaxPerEpoch: big.NewInt(15000), EpochDuration: time.Minute})
	e.nowFn = func() time.Time { return now }

	if d := e.Evaluate(payment("base", "0xM", "10000", "n1")); !d.Allow {
		t.Fatalf("first payment should pass: %s", d.Reason)
	}
	// 10000 + 10000 > 15000 cap -> deny, and budget must NOT be consumed.
	if d := e.Evaluate(payment("base", "0xM", "10000", "n2")); d.Allow {
		t.Fatal("second payment should exceed epoch cap")
	}
	// A smaller one still fits (proves the denied one didn't consume budget).
	if d := e.Evaluate(payment("base", "0xM", "5000", "n3")); !d.Allow {
		t.Fatalf("5000 should fit (10000 spent, cap 15000): %s", d.Reason)
	}
	// Roll the epoch forward -> budget resets.
	now = now.Add(2 * time.Minute)
	if d := e.Evaluate(payment("base", "0xM", "15000", "n4")); !d.Allow {
		t.Fatalf("after epoch reset 15000 should fit: %s", d.Reason)
	}
}

func TestBindingHash_DeterministicAndSensitive(t *testing.T) {
	base := payment("base", "0xM", "10000", "n1")
	if BindingHash(base) != BindingHash(payment("base", "0xM", "10000", "n1")) {
		t.Fatal("binding not deterministic")
	}
	if BindingHash(base) == BindingHash(payment("base", "0xM", "10001", "n1")) {
		t.Fatal("binding insensitive to value")
	}
	if BindingHash(base) == BindingHash(payment("base", "0xOther", "10000", "n1")) {
		t.Fatal("binding insensitive to recipient")
	}
	if BindingHash(base) == BindingHash(payment("base", "0xM", "10000", "n2")) {
		t.Fatal("binding insensitive to nonce")
	}
}
