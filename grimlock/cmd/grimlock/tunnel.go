// Tunnel management for Grimlock
//
// Handles mTLS tunnels between Grimlock instances on different hosts.
// Updated to match verified Grimlock production implementation:
//   - tls.Conn.NetConn() instead of reflect/unsafe for TCP extraction
//   - After kTLS, data flows through raw *net.TCPConn (not *tls.Conn)
//   - Raw net.Listen for server-side kTLS (not tls.Listen)
//   - CloseWrite propagation for clean bidirectional forwarding

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/grimlock-ai/grimlock/internal/attest"
	"github.com/grimlock-ai/grimlock/internal/capability"
)

// TunnelManager manages tunnels to peer Grimlocks
type TunnelManager struct {
	tlsConfig *tls.Config
	localCert tls.Certificate
	caPool    *x509.CertPool

	listener net.Listener

	// Attestation (TDX) mode. When attestEnabled is true, peers are authenticated
	// by a post-handshake mutual TDX-quote exchange (the gate), bound to the TLS
	// session via exported keying material, run before any application data. The
	// TLS handshake itself uses a throwaway ephemeral cert. The wire is still
	// TLS 1.3 + kTLS exactly as in CA mode.
	attestEnabled bool
	gate          *attest.GateConfig
	measureOnly   bool
	localKeyHash  [32]byte // SHA-256 of our ephemeral TLS SPKI (our instance key K)
	x402          *x402Enforcer
	mcp           *mcpEnforcer  // wire-level MCP capability enforcement (optional)
	egress        *egressPolicy // per-connection channel classification (guard.go)

	// attestedManifests holds each peer's attested capability manifest (captured on
	// the full gate, reused across resumed connections), keyed by peer IP — the
	// tool→capability map the wire enforcer checks each call against.
	manifestMu        sync.Mutex
	attestedManifests map[string]capability.Manifest

	// Per-peer warm tunnel pool. channelFor lazily creates one pool per peer; every
	// tunnel is a dedicated, spliceable 1:1 kTLS connection. channelDepth is the
	// warm pool depth; reattestInterval is both the resumption-secret TTL and the
	// warm-tunnel max-idle (0 = never re-check).
	channelDepth     int
	reattestInterval time.Duration
	tunnelPort       int           // port peers listen on / clients dial (set by StartListener)
	setupSem         chan struct{} // caps concurrent inbound setups (load-shed / anti-DoS)
	peerMu           sync.Mutex
	pools            map[string]*tunnelPool
	resume           *resumeCache
}

// Timeouts bound tunnel setup so a slow or malicious peer cannot wedge daemon
// goroutines. The data-transfer phase (post-setup) is unbounded (splice/relay).
const (
	dialTimeout         = 10 * time.Second // TCP connect
	setupTimeout        = 30 * time.Second // TLS handshake + gate/resume + header
	setupAcquireTimeout = 5 * time.Second  // wait for a setup slot before shedding
	maxConcurrentSetups = 128              // cap concurrent (expensive) inbound setups
)

// channelFor returns the per-peer warm tunnel pool, creating it on first use.
func (tm *TunnelManager) channelFor(peerIP string) *tunnelPool {
	tm.peerMu.Lock()
	defer tm.peerMu.Unlock()
	if tm.pools == nil {
		tm.pools = make(map[string]*tunnelPool)
	}
	if p, ok := tm.pools[peerIP]; ok {
		return p
	}
	p := newTunnelPool(tm, peerIP, tm.channelDepth, tm.reattestInterval)
	tm.pools[peerIP] = p
	return p
}

// storeManifest records a peer's attested capability manifest (parsed) for
// wire-level enforcement. Called after a full gate; a parse failure or empty
// manifest stores nil, which the enforcer treats as fail-closed.
func (tm *TunnelManager) storeManifest(peerIP string, raw []byte) {
	m, _ := capability.ParseManifest(raw)
	tm.manifestMu.Lock()
	if tm.attestedManifests == nil {
		tm.attestedManifests = make(map[string]capability.Manifest)
	}
	tm.attestedManifests[peerIP] = m
	tm.manifestMu.Unlock()
}

// manifestFor returns the peer's attested manifest (nil if none captured yet).
func (tm *TunnelManager) manifestFor(peerIP string) capability.Manifest {
	tm.manifestMu.Lock()
	defer tm.manifestMu.Unlock()
	return tm.attestedManifests[peerIP]
}

// Connection-setup mode (attested only), sent by the client right after kTLS and
// answered by the server when resumption is proposed. Resumption skips the full
// quote exchange in favour of a cheap HMAC handshake (gate.Resume).
const (
	modeFull   = 'F' // full attestation gate (quote exchange)
	modeResume = 'R' // resume from a cached secret
)

// resumeCache holds per-peer resumption secrets from prior full gates, keyed by
// the peer's instance key, with a TTL (the re-attestation interval) after which a
// full gate is required again (re-checking measurement). Each full gate bumps a
// monotonic generation used as the attestation epoch bound into payments.
type resumeCache struct {
	mu  sync.Mutex
	ttl time.Duration
	gen uint64
	m   map[[32]byte]rsEntry
}

type rsEntry struct {
	rs     []byte
	gen    uint64
	expiry time.Time // zero = never expires (ttl <= 0)
}

func newResumeCache(ttl time.Duration) *resumeCache {
	// Seed the generation (attestation epoch) from the wall clock so epochs are
	// globally monotone across daemon restarts — a payment receipt's epoch is
	// unambiguous even after a restart, without persisting state.
	return &resumeCache{ttl: ttl, gen: uint64(time.Now().Unix()), m: make(map[[32]byte]rsEntry)}
}

// put stores a fresh secret and returns its generation (the attestation epoch).
func (c *resumeCache) put(peerKey [32]byte, rs []byte) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	var exp time.Time
	if c.ttl > 0 {
		exp = time.Now().Add(c.ttl)
	}
	c.m[peerKey] = rsEntry{rs: rs, gen: c.gen, expiry: exp}
	return c.gen
}

// get returns a live secret for the peer, or ok=false if absent/expired.
func (c *resumeCache) get(peerKey [32]byte) (rsEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[peerKey]
	if !ok {
		return rsEntry{}, false
	}
	if !e.expiry.IsZero() && time.Now().After(e.expiry) {
		delete(c.m, peerKey)
		return rsEntry{}, false
	}
	return e, true
}

// AttestConfig enables the post-handshake attestation gate: the TLS handshake
// uses an ephemeral self-signed cert, then both peers mutually attest with TDX
// quotes bound to the session (EKM) and verified against a measurement policy
// before any application data flows.
type AttestConfig struct {
	Quoter      attest.Quoter   // produces the local quote (e.g. configfs-tsm)
	Verifier    attest.Verifier // validates peer quotes against policy
	Identity    string          // CommonName for the ephemeral TLS cert
	CertTTL     time.Duration   // lifetime of the ephemeral cert
	Timeout     time.Duration   // deadline for the gate quote exchange
	MeasureOnly bool            // bootstrap: log peer measurements, don't pin them

	// MCP capability governance (optional). LocalManifest is this host's MCP tool
	// manifest, advertised + bound into the quote. LocalManifestFunc overrides it
	// when the manifest is auto-pulled from a live MCP server (dynamic). CapPolicy
	// enforces the peer's manifest; escalation fails the gate (no forwarding).
	LocalManifest     []byte
	LocalManifestFunc func() []byte
	CapPolicy         capability.Policy

	// AllowInstanceKeys, if non-empty, is the allowlist of authorized peer
	// instance keys (SHA-256 of the peer's TLS SubjectPublicKeyInfo). It realizes
	// `Policy says K ⇒ TrustedPeer`: only these instances are accepted even with a
	// golden measurement. Empty = accept any instance whose measurement is golden.
	AllowInstanceKeys [][32]byte

	// AgentMeasurement is this host's agent-code measurement, advertised + bound
	// into the quote (decouples "which agent" from "which Grimlock"). PeerAgent, if
	// non-nil, pins the required peer agent measurement (else not enforced).
	AgentMeasurement []byte
	PeerAgent        []byte
}

// TunnelConfig configures a TunnelManager. Exactly one trust mode is selected:
// when Attest is non-nil, RA-TLS/TDX is used and the CA fields are ignored;
// otherwise the shared-CA mTLS mode is used.
type TunnelConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
	Attest   *AttestConfig
}

// NewTunnelManager creates a new tunnel manager in either CA-mTLS or RA-TLS mode.
func NewTunnelManager(cfg TunnelConfig) (*TunnelManager, error) {
	tm := &TunnelManager{
		setupSem: make(chan struct{}, maxConcurrentSetups),
	}

	if cfg.Attest != nil {
		return tm.initAttested(cfg.Attest)
	}
	return tm.initCA(cfg)
}

// initCA configures shared-CA mutual TLS (the original trust model).
func (tm *TunnelManager) initCA(cfg TunnelConfig) (*TunnelManager, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}
	tm.localCert = cert

	caCert, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA: %v", err)
	}
	tm.caPool = x509.NewCertPool()
	if !tm.caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tm.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      tm.caPool,
		ClientCAs:    tm.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	return tm, nil
}

// initAttested configures the post-handshake attestation gate: the TLS
// handshake uses an ephemeral self-signed cert (trust is NOT established there),
// and peers mutually attest with TDX quotes after the handshake.
func (tm *TunnelManager) initAttested(ac *AttestConfig) (*TunnelManager, error) {
	cert, err := attest.GenerateEphemeralCert(ac.Identity, ac.CertTTL)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral certificate: %w", err)
	}
	tm.localCert = cert
	tm.attestEnabled = true
	tm.measureOnly = ac.MeasureOnly
	keyHash, err := spkiHash(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("hash local instance key: %w", err)
	}
	tm.localKeyHash = keyHash
	tm.resume = newResumeCache(0) // TTL set from --attest-reattest-interval in main
	tm.gate = &attest.GateConfig{
		Quoter:                ac.Quoter,
		Verifier:              ac.Verifier,
		Timeout:               ac.Timeout,
		LocalAttachment:       ac.LocalManifest,
		LocalAttachmentFunc:   ac.LocalManifestFunc,
		LocalAgentMeasurement: ac.AgentMeasurement,
	}
	// Pin the peer's agent measurement (agent-code identity) if configured.
	if len(ac.PeerAgent) > 0 {
		want := ac.PeerAgent
		tm.gate.CheckPeerAgentMeasurement = func(got []byte) error {
			if !bytes.Equal(got, want) {
				return fmt.Errorf("peer agent measurement %x != pinned %x", got, want)
			}
			return nil
		}
		log.Printf("[ATTEST] peer agent measurement pinned (%d bytes)", len(want))
	}
	// Instance-key allowlist (Policy says K ⇒ TrustedPeer). Empty = accept any
	// instance with a golden measurement (closed-membership-by-measurement).
	if len(ac.AllowInstanceKeys) > 0 {
		allow := make(map[[32]byte]bool, len(ac.AllowInstanceKeys))
		for _, k := range ac.AllowInstanceKeys {
			allow[k] = true
		}
		tm.gate.CheckPeerIdentity = func(k [32]byte) error {
			if !allow[k] {
				return fmt.Errorf("instance key %x not authorized", k)
			}
			return nil
		}
		log.Printf("[ATTEST] instance-key allowlist enforced (%d keys)", len(allow))
	}
	// Enforce the peer's MCP capability manifest (if a policy is configured). The
	// check is folded into the gate barrier, so escalation aborts the tunnel
	// before any agent/tool data is forwarded.
	if ac.CapPolicy.Enforced() {
		policy := ac.CapPolicy
		// Fail closed: an empty/missing peer manifest (e.g. a failed auto-pull)
		// is rejected, not passed.
		tm.gate.CheckPeerAttachment = func(peerManifest []byte) error {
			return policy.CheckManifestBytes(peerManifest)
		}
		log.Printf("[ATTEST] MCP capability policy enforced (%d caps, %d scopes)",
			len(ac.CapPolicy.AllowedCapabilities), len(ac.CapPolicy.AllowedScopes))
	}
	if len(ac.LocalManifest) > 0 {
		log.Printf("[ATTEST] advertising MCP manifest (%d bytes) bound into attestation", len(ac.LocalManifest))
	}

	// Standard TLS 1.3 handshake with an ephemeral cert. Require a client cert so
	// the handshake is mutual (the gate then attests both ends), but do NOT
	// chain-verify it -- the post-handshake gate is the real check.
	// SessionTicketsDisabled keeps the client's kTLS RX stream free of
	// post-handshake NewSessionTicket records, which would otherwise desync the
	// RecSeq=0 assumption made when kTLS is enabled.
	tm.tlsConfig = &tls.Config{
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAnyClientCert,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}

	log.Printf("[ATTEST] post-handshake gate enabled (identity=%q, cert TTL=%s, gate timeout=%s)",
		ac.Identity, ac.CertTTL, ac.Timeout)
	return tm, nil
}

// newClientConfig builds the tls.Config used when dialing a peer, matching the
// manager's trust mode. The keyLog is PER-CALL so concurrent tunnel establishes
// (warm-pool refills) don't stomp each other's kTLS traffic secrets.
func (tm *TunnelManager) newClientConfig(kl *keyLogWriter) *tls.Config {
	if tm.attestEnabled {
		return &tls.Config{
			Certificates:           []tls.Certificate{tm.localCert},
			InsecureSkipVerify:     true, // trust established by the post-handshake gate, not PKI
			MinVersion:             tls.VersionTLS13,
			MaxVersion:             tls.VersionTLS13,
			SessionTicketsDisabled: true,
			KeyLogWriter:           kl,
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tm.localCert},
		RootCAs:      tm.caPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		KeyLogWriter: kl,
	}
}

// spkiHash returns SHA-256 of a DER certificate's SubjectPublicKeyInfo — the
// endpoint's instance key K.
func spkiHash(der []byte) ([32]byte, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(c.RawSubjectPublicKeyInfo), nil
}

// makeExporter returns an attest.Exporter over a TLS session for the given RFC
// 8446 exporter label. Used to bind both the attestation gate and x402 payment
// quotes to the session via EKM.
func makeExporter(tlsConn *tls.Conn, label string) attest.Exporter {
	return func(ctx []byte) ([attest.ReportDataSize]byte, error) {
		var rd [attest.ReportDataSize]byte
		state := tlsConn.ConnectionState()
		b, err := state.ExportKeyingMaterial(label, ctx, attest.ReportDataSize)
		if err != nil {
			return rd, err
		}
		copy(rd[:], b)
		return rd, nil
	}
}

// peerKeyOf returns the peer's instance key: SHA-256 of its TLS SPKI. TLS 1.3
// CertificateVerify already proved the peer holds this key on this session, so it
// is a sound (possession-proven) instance identity even though the cert chain is
// not chain-validated (trust comes from the gate, not PKI).
func peerKeyOf(tlsConn *tls.Conn) [32]byte {
	var k [32]byte
	if certs := tlsConn.ConnectionState().PeerCertificates; len(certs) > 0 {
		k = sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	}
	return k
}

// deriveRS derives the per-peer resumption secret from a full gate's TLS session.
func deriveRS(tlsConn *tls.Conn) ([]byte, error) {
	state := tlsConn.ConnectionState()
	return state.ExportKeyingMaterial(attest.ResumptionLabel, nil, 32)
}

// runGate executes the one-time mutual attestation gate over dataConn, bound to
// the TLS session (tlsConn) via exported keying material. It must be called after
// the handshake (and after kTLS on the client) and before any application data.
// On success it caches a resumption secret for cheap future re-establishment and
// returns the attestation epoch. On failure the caller MUST NOT forward data.
func (tm *TunnelManager) runGate(tlsConn *tls.Conn, dataConn net.Conn, isClient bool, role string) (uint64, []byte, error) {
	state := tlsConn.ConnectionState()
	peerKey := peerKeyOf(tlsConn)
	exporter := func(ctx []byte) ([attest.ReportDataSize]byte, error) {
		var rd [attest.ReportDataSize]byte
		b, err := state.ExportKeyingMaterial(attest.EKMLabel, ctx, attest.ReportDataSize)
		if err != nil {
			return rd, err
		}
		copy(rd[:], b)
		return rd, nil
	}

	m, err := tm.gate.Run(dataConn, exporter, isClient, false, tm.localKeyHash, peerKey)
	if err != nil {
		return 0, nil, err
	}

	if tm.measureOnly {
		log.Printf("[ATTEST] MEASURE-ONLY (%s): peer quote verified+bound; observed measurements:\n%s"+
			"         pin these (drop --attest-measure-only, add the flags above) to enforce.",
			role, attest.FormatMeasurements(m))
	} else {
		log.Printf("[ATTEST] peer attested (%s): MRTD=%x", role, m.MRTD)
	}

	rs, rerr := deriveRS(tlsConn)
	if rerr != nil {
		return 0, nil, fmt.Errorf("derive resumption secret: %w", rerr)
	}
	metrics.fullGates.Add(1)
	return tm.resume.put(peerKey, rs), m.Attachment, nil
}

// runResume performs the cheap resumption handshake in place of a full gate,
// authenticating continuity of the attested identity via the cached secret,
// bound to this session. Fail closed.
func (tm *TunnelManager) runResume(tlsConn *tls.Conn, dataConn net.Conn, isClient bool, rs []byte, role string) error {
	expS2 := makeExporter(tlsConn, "EXPORTER-grimlock-resume-bind")
	if err := tm.gate.Resume(dataConn, expS2, isClient, rs); err != nil {
		return err
	}
	metrics.resumes.Add(1)
	log.Printf("[ATTEST] resumed (%s)", role)
	return nil
}

// StartListener starts a raw TCP listener for incoming tunnel connections.
// We use net.Listen (not tls.Listen) so we retain the *net.TCPConn needed
// to enable kTLS on the server side via setsockopt.
func (tm *TunnelManager) StartListener(port int) error {
	tm.tunnelPort = port // clients dial peers on this same port
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %v", err)
	}
	tm.listener = listener

	log.Printf("[TUNNEL] Listening on %s for peer connections", addr)

	go tm.acceptLoop()

	return nil
}

func (tm *TunnelManager) acceptLoop() {
	for {
		conn, err := tm.listener.Accept()
		if err != nil {
			log.Printf("[TUNNEL] Accept error: %v", err)
			return
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			log.Printf("[TUNNEL] Accepted non-TCP connection: %T", conn)
			conn.Close()
			continue
		}
		go tm.handleIncomingTCP(tcpConn)
	}
}

// handleIncomingTCP processes an incoming tunnel connection: TLS handshake, then
// (attested) gate/resume, then forwarding. Setup is load-shed and deadline-bound
// so an unauthenticated flood or slowloris cannot exhaust the daemon.
func (tm *TunnelManager) handleIncomingTCP(tcpConn *net.TCPConn) {
	defer tcpConn.Close()

	// Load-shed: cap concurrent (expensive) setups; drop if none free in time.
	select {
	case tm.setupSem <- struct{}{}:
	case <-time.After(setupAcquireTimeout):
		metrics.setupShed.Add(1)
		log.Printf("[TUNNEL] setup capacity reached, dropping %s", tcpConn.RemoteAddr())
		return
	}
	slotFreed := false
	freeSlot := func() {
		if !slotFreed {
			slotFreed = true
			<-tm.setupSem
		}
	}
	defer freeSlot()

	_ = tcpConn.SetDeadline(time.Now().Add(setupTimeout))
	tlsConn := tls.Server(tcpConn, tm.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[TUNNEL] Incoming handshake failed: %v", err)
		return
	}

	peerIP := tcpConn.RemoteAddr().(*net.TCPAddr).IP.String()
	if certs := tlsConn.ConnectionState().PeerCertificates; len(certs) > 0 {
		log.Printf("[TUNNEL] Incoming connection from %s (CN=%s)", peerIP, certs[0].Subject.CommonName)
	}

	// Attested mode: read the client's setup mode and either resume (cheap) or run
	// a full gate, before any application data. Fail closed. Server-side data uses
	// the user-space tls.Conn (client-side kTLS encrypts the wire).
	if tm.attestEnabled {
		if err := tm.serverAttest(tlsConn, peerIP); err != nil {
			metrics.attestFail.Add(1)
			log.Printf("[TUNNEL] Attestation failed from %s: %v", peerIP, err)
			return
		}
	}
	freeSlot() // setup done; free the slot before the long-lived data phase
	tm.handleForwardingConnection(tlsConn, peerIP)
}

// serverAttest reads the client's setup mode byte and completes either a
// resumption handshake (if the client proposes it and we hold the secret) or a
// full gate. Fail closed.
func (tm *TunnelManager) serverAttest(tlsConn *tls.Conn, peerIP string) error {
	var mode [1]byte
	if _, err := io.ReadFull(tlsConn, mode[:]); err != nil {
		return fmt.Errorf("read setup mode: %w", err)
	}
	if mode[0] == modeResume {
		if e, ok := tm.resume.get(peerKeyOf(tlsConn)); ok {
			if _, err := tlsConn.Write([]byte{modeResume}); err != nil {
				return err
			}
			return tm.runResume(tlsConn, tlsConn, false, e.rs, "server<-"+peerIP)
		}
		// No cached secret: tell the client to fall back to a full gate.
		if _, err := tlsConn.Write([]byte{modeFull}); err != nil {
			return err
		}
	}
	_, _, err := tm.runGate(tlsConn, tlsConn, false, "server<-"+peerIP)
	return err
}

// handleForwardingConnection reads the destination header and splices the tunnel
// to the local agent. Attestation (gate or resume) has already completed.
func (tm *TunnelManager) handleForwardingConnection(dataConn net.Conn, peerIP string) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(dataConn, header); err != nil {
		log.Printf("[TUNNEL] Failed to read header from %s: %v", peerIP, err)
		return
	}
	// Setup complete. Server-side freshness (threat-model §8.2): bound how long we
	// serve on ONE attestation to the re-attestation interval, so a validly
	// established tunnel held open past the TTL is closed (the client re-establishes,
	// re-attesting). 0 = re-attestation disabled ⇒ unbounded (matches the client's
	// warm-tunnel max-idle). Independent of the client dropping stale tunnels — both
	// ends bound staleness.
	if tm.reattestInterval > 0 {
		_ = dataConn.SetDeadline(time.Now().Add(tm.reattestInterval))
	} else {
		_ = dataConn.SetDeadline(time.Time{})
	}

	dstIP := net.IP(header[0:4])
	dstPort := int(binary.BigEndian.Uint16(header[4:6]))

	log.Printf("[TUNNEL] Request from %s for local %s:%d", peerIP, dstIP, dstPort)

	agentAddr := fmt.Sprintf("127.0.0.1:%d", dstPort)
	agentConn, err := net.DialTimeout("tcp", agentAddr, dialTimeout)
	if err != nil {
		log.Printf("[TUNNEL] Failed to connect to local agent %s: %v", agentAddr, err)
		return
	}
	defer agentConn.Close()
	metrics.requestsForwarded.Add(1)

	log.Printf("[TUNNEL] Connected to local agent at %s", agentAddr)

	// Data plane: dedicated tunnel ↔ local agent, both *net.TCPConn on the
	// server side → kernel splice(2) (zero-copy).
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := relay(agentConn, dataConn)
		closeWrite(agentConn)
		metrics.bytesForwarded.Add(uint64(n))
		log.Printf("[TUNNEL] Forwarded %d bytes to agent", n)
	}()

	go func() {
		defer wg.Done()
		n, _ := relay(dataConn, agentConn)
		closeWrite(dataConn)
		metrics.bytesForwarded.Add(uint64(n))
		log.Printf("[TUNNEL] Sent %d bytes back through tunnel", n)
	}()

	wg.Wait()
	log.Printf("[TUNNEL] Forwarding connection closed")
}

// closeWrite shuts down the write side to propagate EOF.
func closeWrite(c net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := c.(closeWriter); ok {
		cw.CloseWrite()
	}
}

// CreateDedicatedTunnel establishes a dedicated 1:1 kTLS connection to a peer.
// Returns the data connection (raw TCP if kTLS active, tls.Conn otherwise), the
// underlying tls.Conn for cleanup, and the attestation epoch (0 in CA mode).
// Attested mode resumes from a cached secret when available (cheap, no quote),
// else runs a full gate; either way trust is established before returning.
func (tm *TunnelManager) CreateDedicatedTunnel(peerIP string) (dataConn net.Conn, closer io.Closer, epoch uint64, err error) {
	kl := newKeyLogWriter() // per-call: concurrent establishes must not share key state

	port := tm.tunnelPort
	if port == 0 {
		port = 9443
	}
	addr := fmt.Sprintf("%s:%d", peerIP, port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tm.newClientConfig(kl))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to connect to %s: %v", addr, err)
	}
	// Bound the TLS handshake + gate/resume so a stalled peer can't wedge a warm
	// tunnel goroutine indefinitely.
	_ = conn.SetDeadline(time.Now().Add(setupTimeout))
	defer conn.SetDeadline(time.Time{})

	// Enable kTLS. dataConn is the raw TCP socket if kTLS is active (kernel
	// encrypts) — so the data plane splices — or the tls.Conn if it could not be.
	dataConn = conn
	clientSecret, serverSecret := kl.GetKeys()
	if len(clientSecret) > 0 && len(serverSecret) > 0 {
		if kerr := enableKTLS(conn, true, clientSecret, serverSecret); kerr != nil {
			log.Printf("[TUNNEL] kTLS failed for %s, using user-space TLS: %v", peerIP, kerr)
		} else if tcpConn, terr := getTCPConn(conn); terr != nil {
			log.Printf("[TUNNEL] Failed to get TCP conn: %v", terr)
		} else {
			dataConn = tcpConn
		}
	}

	if tm.attestEnabled {
		if epoch, err = tm.clientAttest(conn, dataConn, peerIP); err != nil {
			conn.Close()
			return nil, nil, 0, err
		}
	}
	return dataConn, conn, epoch, nil
}

// clientAttest proposes resumption when a live secret is cached; if the server
// accepts, it runs the cheap resume handshake, otherwise it runs a full gate.
// Returns the attestation epoch. Runs over dataConn (the kTLS socket), before any
// application data. Fail closed.
func (tm *TunnelManager) clientAttest(conn *tls.Conn, dataConn net.Conn, peerIP string) (uint64, error) {
	if e, ok := tm.resume.get(peerKeyOf(conn)); ok {
		if _, err := dataConn.Write([]byte{modeResume}); err != nil {
			return 0, err
		}
		var ack [1]byte
		if _, err := io.ReadFull(dataConn, ack[:]); err != nil {
			return 0, err
		}
		if ack[0] == modeResume {
			if err := tm.runResume(conn, dataConn, true, e.rs, "client->"+peerIP); err != nil {
				return 0, err
			}
			return e.gen, nil
		}
		// Server lacks the secret: fall through to a full gate.
	} else if _, err := dataConn.Write([]byte{modeFull}); err != nil {
		return 0, err
	}
	epoch, manifest, err := tm.runGate(conn, dataConn, true, "client->"+peerIP)
	if err != nil {
		return 0, fmt.Errorf("attestation gate failed for %s: %w", peerIP, err)
	}
	// Capture the peer's attested manifest for wire-level capability enforcement
	// (mcp.go). Resumed connections reuse it (they don't re-exchange the manifest).
	tm.storeManifest(peerIP, manifest)
	return epoch, nil
}

// Close shuts down the tunnel manager and all per-peer pools.
func (tm *TunnelManager) Close() {
	if tm.listener != nil {
		tm.listener.Close()
	}
	tm.peerMu.Lock()
	for _, p := range tm.pools {
		p.Close()
	}
	tm.peerMu.Unlock()
}
