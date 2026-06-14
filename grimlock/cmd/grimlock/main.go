// Grimlock Control Plane
//
// This program loads eBPF programs for transparent AI agent security:
// 1. cgroup/connect4: Intercepts agent connections, redirects to local Grimlock
// 2. Grimlock forwards through kTLS tunnel to peer Grimlock
// 3. Peer Grimlock forwards to destination agent

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	// Local port for redirected agent connections
	LocalListenPort = 15001

	// Header format: 4 bytes IP + 2 bytes port + 2 bytes reserved
	HeaderSize = 8
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" bpf ../../src/bpf/grimlock.bpf.c -- -I../../src/bpf

// Event types from eBPF
const (
	EventConnect = 1
	EventAccept  = 2
	EventClose   = 3
)

// Event structure matching the eBPF definition
type Event struct {
	TimestampNs uint64
	Pid         uint32
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	EventType   uint8
	Padding     [3]uint8
}

// Config structure matching eBPF
type Config struct {
	Enabled uint32
	LocalIP uint32
}

// Global managers
var tunnelMgr *TunnelManager
var redirectMgr *RedirectManager

func main() {
	// Parse flags
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "Path to cgroup v2 mount")
	peerIPs := flag.String("peers", "", "Comma-separated list of agent peer IPs")
	certFile := flag.String("cert", "certs/agent-a.crt", "Path to certificate file")
	keyFile := flag.String("key", "certs/agent-a.pem", "Path to key file")
	caFile := flag.String("ca", "certs/ca.crt", "Path to CA certificate")
	tunnelPort := flag.Int("tunnel-port", 9443, "Port for Grimlock-to-Grimlock tunnels")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("==============================================")
	log.Println("  Grimlock - AI Agent Security Layer")
	log.Println("==============================================")
	log.Println()

	// Remove memory lock limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load pre-compiled eBPF programs
	log.Println("[1/4] Loading eBPF programs...")
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier error:\n%+v", ve)
		}
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()
	log.Println("   eBPF programs loaded successfully")

	// Attach sockops to cgroup
	log.Printf("[2/10] Attaching sock_ops to cgroup: %s", *cgroupPath)
	sockopsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.GrimlockSockops,
	})
	if err != nil {
		log.Fatalf("Failed to attach sock_ops: %v", err)
	}
	defer sockopsLink.Close()
	log.Println("   sock_ops attached successfully")

	// Attach cgroup/connect4 for connection interception
	log.Printf("[3/10] Attaching connect4 to cgroup: %s", *cgroupPath)
	connect4Link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.GrimlockConnect4,
	})
	if err != nil {
		log.Fatalf("Failed to attach connect4: %v", err)
	}
	defer connect4Link.Close()
	log.Println("   connect4 attached successfully")

	// Configure agent peers
	log.Println("[4/10] Configuring agent peers...")
	if *peerIPs != "" {
		peers := parsePeerIPs(*peerIPs)
		for _, ip := range peers {
			ipInt := ipToUint32(ip)
			val := uint8(1)
			if err := objs.AgentPeers.Put(ipInt, val); err != nil {
				log.Printf("   Warning: Failed to add peer %s: %v", ip, err)
			} else {
				log.Printf("   Added peer: %s", ip)
				// Set first peer as default for forwarding
				if configuredPeerIP == "" {
					configuredPeerIP = ip.String()
				}
			}
		}
		log.Printf("   Default peer for forwarding: %s", configuredPeerIP)
	} else {
		log.Println("   No peers configured (use --peers flag)")
	}

	// Enable tracking
	log.Println("[5/10] Enabling connection tracking...")
	cfg := Config{Enabled: 1, LocalIP: 0}
	if err := objs.ConfigMap.Put(uint32(0), cfg); err != nil {
		log.Fatalf("Failed to enable tracking: %v", err)
	}
	log.Println("   Connection tracking enabled")

	// Initialize tunnel manager
	log.Println("[6/10] Initializing tunnel manager...")
	tunnelMgr, err = NewTunnelManager(*certFile, *keyFile, *caFile)
	if err != nil {
		log.Fatalf("Failed to initialize tunnel manager: %v", err)
	}
	defer tunnelMgr.Close()
	log.Println("   Tunnel manager initialized")

	// Start tunnel listener (for incoming encrypted connections from peers)
	log.Printf("[7/10] Starting tunnel listener on port %d...", *tunnelPort)
	if err := tunnelMgr.StartListener(*tunnelPort); err != nil {
		log.Fatalf("Failed to start tunnel listener: %v", err)
	}
	log.Println("   Tunnel listener started")

	// Start local listener (for redirected agent connections)
	log.Printf("[8/10] Starting local listener on port %d...", LocalListenPort)
	localListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", LocalListenPort))
	if err != nil {
		log.Fatalf("Failed to start local listener: %v", err)
	}
	defer localListener.Close()
	log.Println("   Local listener started")

	// Start accepting redirected connections
	go acceptLocalConnections(localListener)

	log.Println()
	log.Println("==============================================")
	log.Println("  Grimlock is running - Press Ctrl+C to stop")
	log.Println("==============================================")
	log.Println()
	log.Printf("  Tunnel port:  %d", *tunnelPort)
	log.Printf("  Local port:   %d", LocalListenPort)
	log.Printf("  Certificate:  %s", *certFile)
	log.Println()

	log.Println("[9/10] Starting event processor...")
	log.Println("       (Tunnels created on-demand when agents communicate)")

	// Set up ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to create ring buffer reader: %v", err)
	}
	defer rd.Close()

	// Handle signals for graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Event processing goroutine
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Error reading ring buffer: %v", err)
				continue
			}

			var event Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			handleEvent(&event)
		}
	}()

	// Wait for signal
	<-sig
	log.Println()
	log.Println("Shutting down Grimlock...")
}

func handleEvent(e *Event) {
	dstIP := uint32ToIP(e.DstIP)

	var eventName string
	switch e.EventType {
	case EventConnect:
		eventName = "CONNECT"
	case EventAccept:
		eventName = "ACCEPT"
	case EventClose:
		eventName = "CLOSE"
	default:
		eventName = "UNKNOWN"
	}

	timestamp := time.Unix(0, int64(e.TimestampNs)).Format("15:04:05.000")
	log.Printf("[EVENT] %s %s to %s:%d", eventName, timestamp, dstIP, e.DstPort)
}

// =============================================================================
// Local Connection Handling (for redirected agent connections)
// =============================================================================

// Connection state for tracking
type LocalConn struct {
	AgentConn   net.Conn // Connection from agent (redirected)
	OrigDstIP   string   // Original destination IP
	OrigDstPort int      // Original destination port
}

var (
	localConnMu sync.Mutex
	localConns  = make(map[string]*LocalConn)
)

// acceptLocalConnections handles connections redirected by cgroup/connect4
func acceptLocalConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[LOCAL] Accept error: %v", err)
			return
		}
		go handleLocalConnection(conn)
	}
}

// Configured peer for POC (set by --peers flag)
var configuredPeerIP string

// handleLocalConnection processes a single redirected connection
func handleLocalConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[LOCAL] Redirected connection from %s", remoteAddr)

	if configuredPeerIP == "" {
		log.Printf("[LOCAL] No peer configured, cannot forward")
		return
	}

	if tunnelMgr == nil {
		log.Printf("[LOCAL] Tunnel manager not initialized")
		return
	}

	// Create a dedicated kTLS tunnel connection for this request.
	// dataConn is the raw TCP socket if kTLS is active (kernel encrypts),
	// or the tls.Conn if kTLS failed (user-space encrypts).
	dataConn, closer, err := tunnelMgr.CreateDedicatedTunnel(configuredPeerIP)
	if err != nil {
		log.Printf("[LOCAL] Failed to create dedicated tunnel to %s: %v", configuredPeerIP, err)
		return
	}
	defer closer.Close()

	log.Printf("[LOCAL] Created dedicated tunnel to %s", configuredPeerIP)

	// Send destination header through tunnel (peer IP + port 8080)
	destHeader := make([]byte, HeaderSize)
	peerIP := net.ParseIP(configuredPeerIP).To4()
	if peerIP != nil {
		copy(destHeader[0:4], peerIP)
	}
	binary.BigEndian.PutUint16(destHeader[4:6], 8080)

	_, err = dataConn.Write(destHeader)
	if err != nil {
		log.Printf("[LOCAL] Failed to send destination header: %v", err)
		return
	}

	// Bidirectional forward: agent <-> kTLS tunnel
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(dataConn, conn)
		closeWrite(dataConn)
		log.Printf("[LOCAL] Sent %d bytes through tunnel", n)
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, dataConn)
		closeWrite(conn)
		log.Printf("[LOCAL] Received %d bytes from tunnel", n)
	}()

	wg.Wait()
	log.Printf("[LOCAL] Connection closed")
}

func parsePeerIPs(s string) []net.IP {
	var ips []net.IP
	for _, part := range splitAndTrim(s, ",") {
		ip := net.ParseIP(part)
		if ip != nil {
			ips = append(ips, ip.To4())
		}
	}
	return ips
}

func splitAndTrim(s, sep string) []string {
	var result []string
	for _, part := range bytes.Split([]byte(s), []byte(sep)) {
		trimmed := bytes.TrimSpace(part)
		if len(trimmed) > 0 {
			result = append(result, string(trimmed))
		}
	}
	return result
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	// eBPF sees IPs in network byte order, which on little-endian x86
	// means the raw uint32 value is effectively "reversed"
	// Use LittleEndian to match how the kernel stores it
	return binary.LittleEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	// Match the LittleEndian used in ipToUint32
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}
