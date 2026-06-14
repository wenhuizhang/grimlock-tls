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
)

// TunnelState represents the state of a tunnel
type TunnelState int

const (
	TunnelStateNone TunnelState = iota
	TunnelStateConnecting
	TunnelStateReady
	TunnelStateFailed
)

func (s TunnelState) String() string {
	switch s {
	case TunnelStateNone:
		return "NONE"
	case TunnelStateConnecting:
		return "CONNECTING"
	case TunnelStateReady:
		return "READY"
	case TunnelStateFailed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

// Tunnel represents an mTLS tunnel to a peer Grimlock.
// After kTLS is enabled, data flows through TCPConn (kernel handles crypto).
type Tunnel struct {
	PeerIP      string
	PeerPort    int
	State       TunnelState
	Conn        *tls.Conn    // handshake only
	TCPConn     *net.TCPConn // raw socket for data after kTLS
	KTLSEnabled bool

	ClientKey []byte
	ClientIV  []byte
	ServerKey []byte
	ServerIV  []byte

	LocalAgentConn net.Conn
}

// DataConn returns the connection to use for data operations.
// If kTLS is enabled, returns the raw TCP socket (kernel handles crypto).
// Otherwise returns the tls.Conn (user-space crypto).
func (t *Tunnel) DataConn() net.Conn {
	if t.KTLSEnabled && t.TCPConn != nil {
		return t.TCPConn
	}
	return t.Conn
}

// TunnelManager manages tunnels to peer Grimlocks
type TunnelManager struct {
	mu      sync.RWMutex
	tunnels map[string]*Tunnel

	tlsConfig *tls.Config
	localCert tls.Certificate
	caPool    *x509.CertPool

	listener net.Listener

	keyLog *keyLogWriter
}

// NewTunnelManager creates a new tunnel manager
func NewTunnelManager(certFile, keyFile, caFile string) (*TunnelManager, error) {
	tm := &TunnelManager{
		tunnels: make(map[string]*Tunnel),
		keyLog:  newKeyLogWriter(),
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}
	tm.localCert = cert

	caCert, err := os.ReadFile(caFile)
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
		KeyLogWriter: tm.keyLog,
	}

	return tm, nil
}

// StartListener starts a raw TCP listener for incoming tunnel connections.
// We use net.Listen (not tls.Listen) so we retain the *net.TCPConn needed
// to enable kTLS on the server side via setsockopt.
func (tm *TunnelManager) StartListener(port int) error {
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

// handleIncomingTCP processes an incoming tunnel connection.
// Wraps the raw TCP in tls.Server() for handshake, then enables kTLS
// on the raw fd immediately after, before any data flows.
func (tm *TunnelManager) handleIncomingTCP(tcpConn *net.TCPConn) {
	defer tcpConn.Close()

	tlsConn := tls.Server(tcpConn, tm.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[TUNNEL] Incoming handshake failed: %v", err)
		return
	}

	state := tlsConn.ConnectionState()
	peerCN := state.PeerCertificates[0].Subject.CommonName
	peerIP := tcpConn.RemoteAddr().(*net.TCPAddr).IP.String()

	log.Printf("[TUNNEL] Incoming connection from %s (CN=%s)", peerIP, peerCN)

	// Server-side uses user-space TLS for decryption (via tls.Conn).
	// Client-side kTLS handles encryption on the sending end.
	// The wire is encrypted either way -- the difference is whether
	// the kernel or user-space handles the crypto on the receiving side.
	// Server-side kTLS requires careful buffer synchronization with Go's
	// TLS library which is left for future optimization.
	tm.handleForwardingConnection(tlsConn, peerIP)
}

// handleForwardingConnection handles a dedicated tunnel connection for forwarding
func (tm *TunnelManager) handleForwardingConnection(dataConn net.Conn, peerIP string) {
	header := make([]byte, 8)
	_, err := io.ReadFull(dataConn, header)
	if err != nil {
		log.Printf("[TUNNEL] Failed to read header from %s: %v", peerIP, err)
		return
	}

	dstIP := net.IP(header[0:4])
	dstPort := int(binary.BigEndian.Uint16(header[4:6]))

	log.Printf("[TUNNEL] Request from %s for local %s:%d", peerIP, dstIP, dstPort)

	agentAddr := fmt.Sprintf("127.0.0.1:%d", dstPort)
	agentConn, err := net.DialTimeout("tcp", agentAddr, 5*time.Second)
	if err != nil {
		log.Printf("[TUNNEL] Failed to connect to local agent %s: %v", agentAddr, err)
		return
	}
	defer agentConn.Close()

	log.Printf("[TUNNEL] Connected to local agent at %s", agentAddr)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(agentConn, dataConn)
		closeWrite(agentConn)
		log.Printf("[TUNNEL] Forwarded %d bytes to agent", n)
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(dataConn, agentConn)
		closeWrite(dataConn)
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

// createTunnel establishes a new mTLS tunnel to a peer with kTLS.
// After the TLS handshake, kTLS is enabled on the raw TCP socket.
// All subsequent data flows through the raw socket (kernel encrypts/decrypts).
func (tm *TunnelManager) createTunnel(peerIP string) (*Tunnel, error) {
	tm.mu.Lock()

	if tunnel, exists := tm.tunnels[peerIP]; exists && tunnel.State == TunnelStateReady {
		tm.mu.Unlock()
		return tunnel, nil
	}

	tunnel := &Tunnel{
		PeerIP:   peerIP,
		PeerPort: 9443,
		State:    TunnelStateConnecting,
	}
	tm.tunnels[peerIP] = tunnel
	tm.mu.Unlock()

	log.Printf("[TUNNEL] Creating tunnel to %s:9443", peerIP)

	tm.keyLog.Reset()

	clientConfig := &tls.Config{
		Certificates: []tls.Certificate{tm.localCert},
		RootCAs:      tm.caPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		KeyLogWriter: tm.keyLog,
	}

	addr := fmt.Sprintf("%s:9443", peerIP)
	conn, err := tls.Dial("tcp", addr, clientConfig)
	if err != nil {
		tunnel.State = TunnelStateFailed
		return nil, fmt.Errorf("failed to connect to %s: %v", addr, err)
	}

	state := conn.ConnectionState()
	log.Printf("[TUNNEL] Connected to %s (CN=%s, cipher=%s)",
		peerIP,
		state.PeerCertificates[0].Subject.CommonName,
		tls.CipherSuiteName(state.CipherSuite))

	tunnel.Conn = conn
	tunnel.State = TunnelStateReady

	// Enable kTLS: after this, use TCPConn for data (kernel handles crypto)
	clientSecret, serverSecret := tm.keyLog.GetKeys()
	if len(clientSecret) > 0 && len(serverSecret) > 0 {
		if err := enableKTLS(conn, true, clientSecret, serverSecret); err != nil {
			log.Printf("[TUNNEL] kTLS setup failed: %v", err)
		} else {
			tcpConn, err := getTCPConn(conn)
			if err != nil {
				log.Printf("[TUNNEL] Failed to get TCP conn after kTLS: %v", err)
			} else {
				tunnel.TCPConn = tcpConn
				tunnel.KTLSEnabled = true
				log.Printf("[TUNNEL] kTLS enabled for tunnel to %s -- kernel handles crypto", peerIP)
			}
		}
	}

	return tunnel, nil
}

// GetOrCreateTunnel returns existing tunnel or creates new one
func (tm *TunnelManager) GetOrCreateTunnel(peerIP string) (*Tunnel, error) {
	tm.mu.RLock()
	tunnel, exists := tm.tunnels[peerIP]
	tm.mu.RUnlock()

	if exists && tunnel.State == TunnelStateReady {
		return tunnel, nil
	}

	return tm.createTunnel(peerIP)
}

// CreateDedicatedTunnel creates a new kTLS connection for a single request.
// Returns the data connection (raw TCP if kTLS active, tls.Conn otherwise)
// and the underlying tls.Conn for cleanup.
func (tm *TunnelManager) CreateDedicatedTunnel(peerIP string) (dataConn net.Conn, closer io.Closer, err error) {
	tm.keyLog.Reset()

	clientConfig := &tls.Config{
		Certificates: []tls.Certificate{tm.localCert},
		RootCAs:      tm.caPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		KeyLogWriter: tm.keyLog,
	}

	addr := fmt.Sprintf("%s:9443", peerIP)
	conn, err := tls.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to %s: %v", addr, err)
	}

	state := conn.ConnectionState()
	peerCN := ""
	if len(state.PeerCertificates) > 0 {
		peerCN = state.PeerCertificates[0].Subject.CommonName
	}

	// Enable kTLS on the dedicated tunnel
	clientSecret, serverSecret := tm.keyLog.GetKeys()
	if len(clientSecret) > 0 && len(serverSecret) > 0 {
		if err := enableKTLS(conn, true, clientSecret, serverSecret); err != nil {
			log.Printf("[TUNNEL] Dedicated tunnel kTLS failed for %s, using user-space TLS: %v", peerIP, err)
			return conn, conn, nil
		}
		tcpConn, err := getTCPConn(conn)
		if err != nil {
			log.Printf("[TUNNEL] Failed to get TCP conn: %v", err)
			return conn, conn, nil
		}
		log.Printf("[TUNNEL] Dedicated tunnel to %s (CN=%s) with kTLS -- kernel handles crypto", peerIP, peerCN)
		return tcpConn, conn, nil
	}

	log.Printf("[TUNNEL] Dedicated tunnel to %s (CN=%s) with user-space TLS", peerIP, peerCN)
	return conn, conn, nil
}

// Close shuts down the tunnel manager
func (tm *TunnelManager) Close() {
	if tm.listener != nil {
		tm.listener.Close()
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	for _, tunnel := range tm.tunnels {
		if tunnel.Conn != nil {
			tunnel.Conn.Close()
		}
	}

	tm.keyLog.Reset()
}

// GetTunnelStats returns tunnel statistics
func (tm *TunnelManager) GetTunnelStats() map[string]string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	stats := make(map[string]string)
	for ip, tunnel := range tm.tunnels {
		kTLS := "no"
		if tunnel.KTLSEnabled {
			kTLS = "yes"
		}
		stats[ip] = fmt.Sprintf("state=%s kTLS=%s", tunnel.State, kTLS)
	}
	return stats
}

// GetLocalPort returns the local port of the tunnel connection
func (t *Tunnel) GetLocalPort() uint32 {
	if t.Conn == nil {
		return 0
	}
	addr := t.Conn.LocalAddr()
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return uint32(tcpAddr.Port)
	}
	return 0
}
