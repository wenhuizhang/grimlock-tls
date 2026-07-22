// Warm pre-established tunnel pool — the sole tunnel strategy.
//
// Every tunnel is a 1:1 kTLS connection, so the data plane rides splice(2)
// (dataplane.go). Establishing one is cheap: the FIRST connection to a peer runs
// a full attestation gate and caches a resumption secret; subsequent connections
// RESUME (a cheap HMAC handshake bound to the new session, no quote) within the
// secret's TTL — see tunnel.go. The pool pre-establishes `size` tunnels so even
// the ~1-RTT setup is off the request path, and drops any warm tunnel whose
// attestation is older than maxIdle (a resumed, cheap replacement takes its
// place). This gives BOTH amortized attestation (via resumption) and a zero-copy
// data plane (via splice), so no multiplexer is needed.

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grimlock-ai/grimlock/internal/attest"
)

// establishCooldown throttles reconnects to a peer that just failed to establish,
// so a down peer cannot cause a dial storm.
const establishCooldown = 2 * time.Second

// streamHandle is what the forward path needs for one request: the data
// connection, the session EKM exporter (x402 binding), the attestation epoch
// (model @e), and a closer.
type streamHandle struct {
	conn  net.Conn
	exp   attest.Exporter
	epoch uint64
	close io.Closer
}

type warmTunnel struct {
	dataConn net.Conn
	tlsConn  *tls.Conn
	epoch    uint64 // attestation generation this tunnel was established under
	bornAt   time.Time
}

type tunnelPool struct {
	tm        *TunnelManager
	peerIP    string
	size      int
	maxIdle   time.Duration // drop a warm tunnel whose attestation is older than this (0 = never)
	warm      chan *warmTunnel
	quit      chan struct{}
	closeOnce sync.Once
	coolUntil atomic.Int64 // unix-nanos; skip establishes until then (circuit breaker)
}

// cooling reports whether the peer is in the post-failure cooldown window.
func (p *tunnelPool) cooling() bool { return timeNowNanos() < p.coolUntil.Load() }

// cool starts a cooldown after a failed establish.
func (p *tunnelPool) cool() { p.coolUntil.Store(timeNowNanos() + int64(establishCooldown)) }

func timeNowNanos() int64 { return time.Now().UnixNano() }

func newTunnelPool(tm *TunnelManager, peerIP string, size int, maxIdle time.Duration) *tunnelPool {
	if size < 1 {
		size = 1
	}
	p := &tunnelPool{
		tm:      tm,
		peerIP:  peerIP,
		size:    size,
		maxIdle: maxIdle,
		warm:    make(chan *warmTunnel, size),
		quit:    make(chan struct{}),
	}
	for i := 0; i < size; i++ {
		go p.refill()
	}
	log.Printf("[POOL] warming %d tunnels to %s (max idle %s)", size, peerIP, maxIdle)
	return p
}

// stream returns a ready spliceable tunnel with its EKM exporter and epoch.
func (p *tunnelPool) stream() (streamHandle, error) {
	dc, closer, epoch, err := p.get()
	if err != nil {
		return streamHandle{}, err
	}
	var exp attest.Exporter
	if tc, ok := closer.(*tls.Conn); ok {
		exp = makeExporter(tc, attest.PaymentEKMLabel)
	}
	return streamHandle{conn: dc, exp: exp, epoch: epoch, close: closer}, nil
}

// get returns an attested tunnel: a warm one if available (setup already paid,
// off the request path), else a freshly established one. A warm tunnel whose
// attestation is older than maxIdle is dropped — a resumed replacement is cheap.
func (p *tunnelPool) get() (net.Conn, io.Closer, uint64, error) {
	for attempts := 0; attempts <= p.size; attempts++ {
		select {
		case wt := <-p.warm:
			go p.refill() // replace the one we took
			if p.maxIdle > 0 && time.Since(wt.bornAt) > p.maxIdle {
				wt.tlsConn.Close() // stale attestation; drop and try the next
				continue
			}
			return wt.dataConn, wt.tlsConn, wt.epoch, nil
		default:
			go p.refill()
			if p.cooling() { // peer recently failed to establish — fail fast, don't dial
				return nil, nil, 0, fmt.Errorf("peer %s cooling down after establish failure", p.peerIP)
			}
			return p.establish()
		}
	}
	return p.establish()
}

// establish creates a tunnel and starts a cooldown on failure.
func (p *tunnelPool) establish() (net.Conn, io.Closer, uint64, error) {
	dc, closer, epoch, err := p.tm.CreateDedicatedTunnel(p.peerIP)
	if err != nil {
		p.cool()
	}
	return dc, closer, epoch, err
}

func (p *tunnelPool) refill() {
	select {
	case <-p.quit:
		return
	default:
	}
	if p.cooling() {
		return // skip background warming during the cooldown
	}
	dataConn, closer, epoch, err := p.establish()
	if err != nil {
		log.Printf("[POOL] tunnel establish to %s failed: %v", p.peerIP, err)
		return
	}
	tlsConn, _ := closer.(*tls.Conn)
	wt := &warmTunnel{dataConn: dataConn, tlsConn: tlsConn, epoch: epoch, bornAt: time.Now()}
	select {
	case p.warm <- wt:
	case <-p.quit:
		closer.Close()
	default:
		closer.Close() // pool already full
	}
}

func (p *tunnelPool) Close() {
	p.closeOnce.Do(func() { close(p.quit) })
	for {
		select {
		case wt := <-p.warm:
			wt.tlsConn.Close()
		default:
			return
		}
	}
}
