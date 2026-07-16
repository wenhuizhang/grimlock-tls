// Package mcpmanifest lets the server-side Grimlock auto-pull its local MCP
// server's capability manifest over HTTP (the governed MCP SDK exposes it at
// /.well-known/mcp-capabilities), instead of requiring a static --mcp-manifest
// file. The pulled bytes are advertised verbatim in the attestation gate and
// bound into the quote, so the client sees the manifest the measured server
// actually serves.
package mcpmanifest

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/grimlock-ai/grimlock/internal/capability"
)

const maxManifestBytes = 1 << 20

// Puller fetches and caches an MCP capability manifest from a URL.
type Puller struct {
	url    string
	client *http.Client

	mu     sync.RWMutex
	cached []byte
}

func NewPuller(url string, timeout time.Duration) *Puller {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Puller{url: url, client: &http.Client{Timeout: timeout}}
}

// Pull fetches the manifest, validates it parses as a capability manifest, caches
// the raw bytes, and returns them. The raw bytes (not a re-serialization) are
// cached so the digest the gate binds matches what the server served.
func (p *Puller) Pull(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pull manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest endpoint %s returned HTTP %d", p.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	if _, err := capability.ParseManifest(body); err != nil {
		return nil, fmt.Errorf("invalid manifest from %s: %w", p.url, err)
	}
	p.mu.Lock()
	p.cached = body
	p.mu.Unlock()
	return body, nil
}

// Cached returns the last successfully pulled manifest bytes (nil if none yet).
// Suitable as a GateConfig.LocalAttachmentFunc.
func (p *Puller) Cached() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cached
}

// Refresh re-pulls the manifest every interval until ctx is cancelled. A failed
// refresh keeps the last good value.
func (p *Puller) Refresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := p.Pull(ctx); err != nil {
				log.Printf("[MCP] manifest refresh failed: %v", err)
			}
		}
	}
}
