// Package x402 implements the parsing, policy enforcement, and attestation
// binding that let Grimlock act as a transparent, attestation-gated enforcement
// point for x402 (HTTP 402) agent payments.
//
// Grimlock sits on the agent's HTTP path (via eBPF interception), so it observes
// the x402 exchange without any change to agent code: a "402 Payment Required"
// challenge carrying PaymentRequirements, and the agent's retried request
// carrying an X-PAYMENT header. Grimlock parses these to (a) enforce a spending
// policy OUTSIDE the (possibly hijacked) agent and (b) bind the payment to the
// agent's TDX attestation. It never signs or settles -- that remains the
// agent's and the facilitator's job.
//
// Types mirror the canonical x402 v1 schema (github.com/x402-foundation/x402),
// restricted to the fields Grimlock needs to parse. Source of truth: the x402
// specification; we deliberately avoid the EVM/crypto SDK deps since enforcement
// requires only parsing.
package x402

import "encoding/json"

// HTTP wire constants (x402 v1).
const (
	HeaderPayment         = "X-PAYMENT"          // request: base64(JSON(PaymentPayload))
	HeaderPaymentResponse = "X-PAYMENT-RESPONSE" // response: base64(JSON(SettleResponse))
	StatusPaymentRequired = 402
)

// PaymentRequirements is one accepted way to pay, carried in the 402 challenge's
// "accepts" array.
type PaymentRequirements struct {
	Scheme            string           `json:"scheme"`
	Network           string           `json:"network"`
	MaxAmountRequired string           `json:"maxAmountRequired"` // token smallest unit
	Resource          string           `json:"resource"`
	Description       string           `json:"description"`
	MimeType          string           `json:"mimeType"`
	PayTo             string           `json:"payTo"`
	MaxTimeoutSeconds int              `json:"maxTimeoutSeconds"`
	Asset             string           `json:"asset"`
	OutputSchema      *json.RawMessage `json:"outputSchema,omitempty"`
	Extra             *json.RawMessage `json:"extra,omitempty"`
}

// PaymentRequiredResponse is the body of a 402 challenge.
type PaymentRequiredResponse struct {
	X402Version int                   `json:"x402Version"`
	Error       string                `json:"error,omitempty"`
	Accepts     []PaymentRequirements `json:"accepts"`
}

// PaymentPayload is the decoded X-PAYMENT header the paying agent sends.
type PaymentPayload struct {
	X402Version int              `json:"x402Version"`
	Scheme      string           `json:"scheme"`
	Network     string           `json:"network"`
	Payload     *ExactEvmPayload `json:"payload"`
}

// ExactEvmPayload is the "exact" scheme payload (EIP-3009 gasless transfer).
type ExactEvmPayload struct {
	Signature     string                        `json:"signature"`
	Authorization *ExactEvmPayloadAuthorization `json:"authorization"`
}

// ExactEvmPayloadAuthorization is the signed transfer authorization. Value is the
// amount in the token's smallest unit; To is the recipient. These are the fields
// Grimlock's spend policy acts on.
type ExactEvmPayloadAuthorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

// VerifyResponse / SettleResponse are facilitator results (parsed from
// X-PAYMENT-RESPONSE for receipts).
type VerifyResponse struct {
	IsValid       bool    `json:"isValid"`
	InvalidReason *string `json:"invalidReason,omitempty"`
	Payer         *string `json:"payer,omitempty"`
}

type SettleResponse struct {
	Success     bool    `json:"success"`
	ErrorReason *string `json:"errorReason,omitempty"`
	Transaction string  `json:"transaction"` // on-chain tx hash
	Network     string  `json:"network"`
	Payer       *string `json:"payer,omitempty"`
}
