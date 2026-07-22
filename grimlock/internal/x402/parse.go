package x402

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// DecodePaymentHeader decodes an X-PAYMENT header value (base64 of a JSON
// PaymentPayload) into a PaymentPayload.
func DecodePaymentHeader(headerValue string) (*PaymentPayload, error) {
	raw, err := base64.StdEncoding.DecodeString(headerValue)
	if err != nil {
		// Some clients use URL-safe base64; try that too.
		raw, err = base64.RawURLEncoding.DecodeString(headerValue)
		if err != nil {
			return nil, fmt.Errorf("x402: decode X-PAYMENT base64: %w", err)
		}
	}
	var p PaymentPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("x402: parse X-PAYMENT json: %w", err)
	}
	return &p, nil
}

// EncodePaymentHeader is the inverse of DecodePaymentHeader (used in tests and
// when Grimlock needs to re-emit a header).
func EncodePaymentHeader(p *PaymentPayload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// DecodePaymentRequired parses a 402 challenge body.
func DecodePaymentRequired(body []byte) (*PaymentRequiredResponse, error) {
	var r PaymentRequiredResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("x402: parse 402 body: %w", err)
	}
	return &r, nil
}

// DecodeSettleResponse parses an X-PAYMENT-RESPONSE header value (base64 of a
// JSON SettleResponse), for receipt logging.
func DecodeSettleResponse(headerValue string) (*SettleResponse, error) {
	raw, err := base64.StdEncoding.DecodeString(headerValue)
	if err != nil {
		return nil, fmt.Errorf("x402: decode X-PAYMENT-RESPONSE base64: %w", err)
	}
	var s SettleResponse
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("x402: parse X-PAYMENT-RESPONSE json: %w", err)
	}
	return &s, nil
}

// Amount returns the payment value (token smallest unit) from an "exact" payload.
func (p *PaymentPayload) Amount() (*big.Int, error) {
	if p.Payload == nil || p.Payload.Authorization == nil {
		return nil, fmt.Errorf("x402: payload missing authorization")
	}
	v, ok := new(big.Int).SetString(p.Payload.Authorization.Value, 10)
	if !ok {
		return nil, fmt.Errorf("x402: invalid authorization value %q", p.Payload.Authorization.Value)
	}
	return v, nil
}

// PayTo returns the recipient address from an "exact" payload.
func (p *PaymentPayload) PayTo() string {
	if p.Payload == nil || p.Payload.Authorization == nil {
		return ""
	}
	return p.Payload.Authorization.To
}
