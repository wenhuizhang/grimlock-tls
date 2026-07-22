package attest

import (
	"fmt"

	"github.com/google/go-tdx-guest/client"
)

// ConfigfsQuoter generates TDX quotes via the kernel configfs-tsm interface
// (/sys/kernel/config/tsm/report, kernel 6.7+). It must run inside a TD.
type ConfigfsQuoter struct {
	provider client.QuoteProvider
}

// NewConfigfsQuoter opens the platform quote provider and verifies TDX quote
// generation is actually supported here. It returns an error when not running
// inside a TD (no tdx_guest TSM provider), which is the correct, fail-closed
// behaviour for an attestation-required deployment.
func NewConfigfsQuoter() (*ConfigfsQuoter, error) {
	provider, err := client.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("open TDX quote provider (are we inside a TD?): %w", err)
	}
	if err := provider.IsSupported(); err != nil {
		return nil, fmt.Errorf("configfs-tsm TDX quoting not supported: %w", err)
	}
	return &ConfigfsQuoter{provider: provider}, nil
}

// Quote implements Quoter.
func (q *ConfigfsQuoter) Quote(reportData [ReportDataSize]byte) ([]byte, error) {
	raw, err := q.provider.GetRawQuote(reportData)
	if err != nil {
		return nil, fmt.Errorf("generate TDX quote: %w", err)
	}
	return raw, nil
}
