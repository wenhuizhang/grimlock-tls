// Grimlock Control Plane
//
// This program loads eBPF programs for transparent AI agent security:
// 1. cgroup/connect4: Intercepts agent connections, redirects to local Grimlock
// 2. Grimlock forwards through kTLS tunnel to peer Grimlock
// 3. Peer Grimlock forwards to destination agent

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/grimlock-ai/grimlock/internal/attest"
	"github.com/grimlock-ai/grimlock/internal/capability"
	"github.com/grimlock-ai/grimlock/internal/mcpmanifest"
	"github.com/grimlock-ai/grimlock/internal/x402"
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

func main() {
	// Parse flags
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "Path to cgroup v2 mount")
	peerIPs := flag.String("peers", "", "Comma-separated list of agent peer IPs")
	certFile := flag.String("cert", "certs/agent-a.crt", "Path to certificate file")
	keyFile := flag.String("key", "certs/agent-a.pem", "Path to key file")
	caFile := flag.String("ca", "certs/ca.crt", "Path to CA certificate")
	tunnelPort := flag.Int("tunnel-port", 9443, "Port for Grimlock-to-Grimlock tunnels")
	agentPorts := flag.String("agent-ports", "8080", "Comma-separated destination ports to intercept to peers (multi-port support)")
	metricsAddr := flag.String("metrics-addr", "", "Serve expvar metrics at /debug/vars on this address (e.g. 127.0.0.1:9090; empty = disabled)")
	seccompEnable := flag.Bool("seccomp", false, "Install a seccomp deny-list blocking dangerous syscalls (ptrace, module load, mount, namespace ops) — defense in depth")

	// TDX remote attestation (RA-TLS). When enabled, peers are authenticated by
	// their embedded TDX quote + measurement policy instead of a shared CA.
	attestEnable := flag.Bool("attest", false, "Enable TDX remote attestation (RA-TLS) instead of CA mTLS")
	attestIdentity := flag.String("attest-identity", "grimlock-td", "CommonName for this TD's RA-TLS certificate")
	attestMRTD := flag.String("attest-mrtd", "", "Required peer MRTD as hex (48 bytes); empty = NOT pinned (insecure)")
	attestRTMR0 := flag.String("attest-rtmr0", "", "Required peer RTMR0 as hex (48 bytes); empty = skip")
	attestRTMR1 := flag.String("attest-rtmr1", "", "Required peer RTMR1 as hex (48 bytes); empty = skip")
	attestRTMR2 := flag.String("attest-rtmr2", "", "Required peer RTMR2 as hex (48 bytes); empty = skip")
	attestRTMR3 := flag.String("attest-rtmr3", "", "Required peer RTMR3 as hex (48 bytes); empty = skip")
	attestMinTCB := flag.String("attest-min-tcb-svn", "", "Minimum peer TEE_TCB_SVN as hex (16 bytes); empty = skip")
	attestAllowDebug := flag.Bool("attest-allow-debug", false, "Accept debuggable peer TDs (INSECURE)")
	attestMeasureOnly := flag.Bool("attest-measure-only", false, "Bootstrap: verify+bind peer quotes but log measurements instead of enforcing a policy")
	attestCollateral := flag.Bool("attest-get-collateral", false, "Fetch PCS collateral over the network for TCB-status evaluation")
	attestRevocation := flag.Bool("attest-check-revocations", false, "Check PCK certificate revocation (requires --attest-get-collateral)")
	attestCertTTL := flag.Duration("attest-cert-ttl", 24*time.Hour, "Lifetime of the ephemeral TLS certificate")
	attestTimeout := flag.Duration("attest-timeout", 10*time.Second, "Deadline for the post-handshake attestation quote exchange")
	attestChannelDepth := flag.Int("attest-channel-depth", 2, "Warm attested tunnels to keep per peer (>=1)")
	attestReattest := flag.Duration("attest-reattest-interval", 0, "Live re-attestation interval for a mux session, or warm-tunnel idle TTL for a dedicated pool (0 = never)")
	attestAllowKeys := flag.String("attest-allow-instance-key", "", "Comma-separated allowlist of authorized peer instance keys (hex SHA-256 of TLS SPKI); empty = accept any instance with a golden measurement")
	attestAgentMeas := flag.String("attest-agent-measurement", "", "This host's agent-code measurement (hex), advertised + bound into the quote (decouples agent identity from Grimlock's TD measurement)")
	attestPeerAgent := flag.String("attest-peer-agent-measurement", "", "Required peer agent measurement (hex); empty = not enforced")

	// MCP capability governance (bound into the attestation gate).
	mcpManifest := flag.String("mcp-manifest", "", "Path to this host's MCP capability manifest JSON (advertised + bound into the quote)")
	mcpManifestURL := flag.String("mcp-manifest-url", "", "Auto-pull this host's manifest from a live MCP server (e.g. http://127.0.0.1:8080/.well-known/mcp-capabilities); overrides --mcp-manifest")
	mcpManifestRefresh := flag.Duration("mcp-manifest-refresh", 30*time.Second, "Background refresh interval for --mcp-manifest-url (0 = once)")
	mcpPolicyCaps := flag.String("mcp-policy-capabilities", "", "Comma-separated capabilities this client allows from a peer (empty = not enforced)")
	mcpPolicyScopes := flag.String("mcp-policy-scopes", "", "Comma-separated scopes this client allows from a peer (empty = not enforced)")
	mcpEnforce := flag.Bool("mcp-enforce", false, "Enforce MCP capabilities on the wire: block tool calls outside the grant / not in the attested manifest, out-of-agent")
	guardSpecs := multiFlag{}
	flag.Var(&guardSpecs, "guard", "Guard a dest port with enforcers, e.g. --guard 8080:mcp,x402 (repeatable). Enforcers must be enabled via their --*-enforce flag; scopes them to this port instead of all agent ports.")
	fastSpecs := multiFlag{}
	flag.Var(&fastSpecs, "fast", "Mark a dest port as bulk/fast — never enforced, splice fast-path (repeatable).")
	egressDefault := flag.String("egress-default", "fast", "Class for an intercepted port with no rule: fast|deny (deny makes Grimlock an egress chokepoint for A2A ports).")

	// x402 payment enforcement (transparent HTTP-aware spend policy).
	x402Enforce := flag.Bool("x402-enforce", false, "Enforce x402 payment policy on agent HTTP requests")
	x402MaxPayment := flag.String("x402-max-payment", "", "Max value per payment, token smallest unit (empty = no cap)")
	x402MaxEpoch := flag.String("x402-max-epoch", "", "Max total value per epoch (empty = no cap)")
	x402Epoch := flag.Duration("x402-epoch", time.Hour, "Velocity epoch window for --x402-max-epoch")
	x402AllowPayTo := flag.String("x402-allow-payto", "", "Comma-separated allowed recipient addresses (empty = any)")
	x402AllowNetworks := flag.String("x402-allow-networks", "", "Comma-separated allowed networks, e.g. base,base-sepolia (empty = any)")
	x402Bind := flag.Bool("x402-bind", true, "Bind each allowed payment to a TDX attestation quote")
	x402ReceiptLog := flag.String("x402-receipt-log", "", "Path for the append-only payment receipt log (empty = stderr)")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("==============================================")
	log.Println("  Grimlock - AI Agent Security Layer")
	log.Println("==============================================")
	log.Println()

	// Defense in depth: no_new_privs + non-dumpable (+ optional seccomp deny-list).
	hardenProcess(*seccompEnable)

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

	// Original-destination resolver (multi-peer routing) backed by the BPF map.
	origDest = newOrigDestResolver(objs.PortDest)

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

	// Configure intercepted agent ports (connect4 redirects these to peers).
	for _, p := range parseAgentPorts(*agentPorts) {
		if err := objs.AgentPorts.Put(uint32(p), uint8(1)); err != nil {
			log.Printf("   Warning: Failed to add agent port %d: %v", p, err)
		} else {
			log.Printf("   Intercepting agent port: %d", p)
		}
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
	tunnelCfg := TunnelConfig{CertFile: *certFile, KeyFile: *keyFile, CAFile: *caFile}
	if *attestEnable {
		ac, aerr := buildAttestConfig(attestParams{
			identity:      *attestIdentity,
			mrtd:          *attestMRTD,
			rtmrs:         [4]string{*attestRTMR0, *attestRTMR1, *attestRTMR2, *attestRTMR3},
			minTCB:        *attestMinTCB,
			allowDebug:    *attestAllowDebug,
			getCollateral: *attestCollateral,
			checkRevoke:   *attestRevocation,
			certTTL:       *attestCertTTL,
			timeout:       *attestTimeout,
			measureOnly:   *attestMeasureOnly,
			mcpManifest:   *mcpManifest,
			mcpCaps:       *mcpPolicyCaps,
			mcpScopes:     *mcpPolicyScopes,
			allowKeys:     *attestAllowKeys,
			agentMeas:     *attestAgentMeas,
			peerAgent:     *attestPeerAgent,
		})
		if aerr != nil {
			log.Fatalf("Failed to configure attestation: %v", aerr)
		}
		// --mcp-enforce moves capability enforcement to the wire (per-call,
		// runtime). The gate still binds the manifest digest (integrity) but does
		// NOT statically reject the peer — we accept it and block individual
		// out-of-grant / unattested calls in the data path instead.
		if *mcpEnforce {
			ac.CapPolicy = capability.Policy{}
		}
		// Auto-pull the local MCP server's manifest (overrides --mcp-manifest).
		if *mcpManifestURL != "" {
			puller := mcpmanifest.NewPuller(*mcpManifestURL, 5*time.Second)
			if _, perr := puller.Pull(context.Background()); perr != nil {
				log.Printf("   WARNING: initial MCP manifest pull failed (will keep retrying): %v", perr)
			} else {
				log.Printf("   Auto-pulled MCP manifest from %s (%d bytes)", *mcpManifestURL, len(puller.Cached()))
			}
			ac.LocalManifest = nil
			ac.LocalManifestFunc = puller.Cached
			go puller.Refresh(context.Background(), *mcpManifestRefresh)
		}
		tunnelCfg.Attest = ac
		log.Println("   Mode: TDX remote attestation (RA-TLS)")
	} else {
		log.Println("   Mode: shared-CA mutual TLS")
	}
	tunnelMgr, err = NewTunnelManager(tunnelCfg)
	if err != nil {
		log.Fatalf("Failed to initialize tunnel manager: %v", err)
	}
	defer tunnelMgr.Close()
	log.Println("   Tunnel manager initialized")

	// Per-peer channel: a warm pool (depth) of attested tunnels that multiplex
	// (yamux) when the peer agrees, else stay single-use. Negotiated per tunnel;
	// created lazily by channelFor. tunnelMgr.Close() shuts them all down.
	tunnelMgr.reattestInterval = *attestReattest
	tunnelMgr.channelDepth = *attestChannelDepth
	if tunnelMgr.channelDepth < 1 {
		tunnelMgr.channelDepth = 1
	}
	if *attestEnable {
		tunnelMgr.resume.ttl = *attestReattest // resumption-secret TTL = re-attest interval
		log.Printf("   Tunnels: dedicated splice + attestation resumption, warm pool depth=%d, resume TTL=%s",
			tunnelMgr.channelDepth, *attestReattest)
	}

	// x402 payment enforcement (transparent spend policy on the forward path).
	if *x402Enforce {
		pol := x402.Policy{
			EpochDuration:   *x402Epoch,
			AllowedPayTo:    x402.LowerSet(splitAndTrim(*x402AllowPayTo, ",")),
			AllowedNetworks: stringSet(splitAndTrim(*x402AllowNetworks, ",")),
		}
		var perr error
		if pol.MaxPerPayment, perr = parseAmount(*x402MaxPayment); perr != nil {
			log.Fatalf("Invalid --x402-max-payment: %v", perr)
		}
		if pol.MaxPerEpoch, perr = parseAmount(*x402MaxEpoch); perr != nil {
			log.Fatalf("Invalid --x402-max-epoch: %v", perr)
		}

		// Receipt log destination. A file recovers the hash-chain head on restart.
		var rlog *ReceiptLog
		if *x402ReceiptLog != "" {
			rl, ferr := OpenReceiptLogFile(*x402ReceiptLog)
			if ferr != nil {
				log.Fatalf("Failed to open --x402-receipt-log: %v", ferr)
			}
			rlog = rl
		} else {
			rlog = NewReceiptLog(os.Stderr)
		}

		// Per-payment binding quoter. Binding requires both the session EKM (so it
		// must run in attested mode) and a TDX quoter (so it must run in a TD).
		// Fail loud at startup rather than silently degrade to an unbound payment.
		var quoter attest.Quoter
		if *x402Bind {
			if !*attestEnable {
				log.Fatalf("--x402-bind requires --attest (payment binding needs the attestation session EKM); pass --x402-bind=false to enforce policy without binding")
			}
			q, qerr := attest.NewConfigfsQuoter()
			if qerr != nil {
				log.Fatalf("--x402-bind requires running in a TD: %v", qerr)
			}
			quoter = q
		}

		tunnelMgr.x402 = newX402Enforcer(pol, quoter, rlog, *x402Bind)
		log.Printf("   x402 enforcement: max/payment=%s max/epoch=%s epoch=%s payTo=%d nets=%d bind=%v",
			orAny(*x402MaxPayment), orAny(*x402MaxEpoch), *x402Epoch,
			len(pol.AllowedPayTo), len(pol.AllowedNetworks), quoter != nil)
	}

	// Wire-level MCP capability enforcement (out-of-agent, against the attested
	// manifest). Uses the same capability grant the gate checks statically.
	if *mcpEnforce {
		capPol := capability.NewPolicy(splitAndTrim(*mcpPolicyCaps, ","), splitAndTrim(*mcpPolicyScopes, ","))
		if !capPol.Enforced() {
			log.Fatalf("--mcp-enforce requires --mcp-policy-capabilities and/or --mcp-policy-scopes (nothing to enforce otherwise)")
		}
		tunnelMgr.mcp = newMCPEnforcer(capPol)
		log.Printf("   MCP capability enforcement ON (wire-level): caps=%d scopes=%d",
			len(capPol.AllowedCapabilities), len(capPol.AllowedScopes))
	}

	// Channel classification: map each dest port to fast (splice) / guarded (enforce)
	// / deny (docs/channel-classes.md). Backward compatible — a global --*-enforce
	// with no --guard scopes that enforcer to all agent ports (today's behavior).
	tunnelMgr.egress = buildEgressPolicy(parseAgentPorts(*agentPorts), tunnelMgr.x402, tunnelMgr.mcp,
		guardSpecs, fastSpecs, *egressDefault)

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

	// Optional metrics endpoint (expvar at /debug/vars).
	if *metricsAddr != "" {
		go func() {
			log.Printf("[METRICS] serving expvar on http://%s/debug/vars", *metricsAddr)
			if err := http.ListenAndServe(*metricsAddr, nil); err != nil {
				log.Printf("[METRICS] server error: %v", err)
			}
		}()
	}

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

// configuredPeerIP is the fallback peer when original-destination recovery is
// unavailable (single-peer mode). origDest recovers the real peer per connection.
var configuredPeerIP string
var origDest *origDestResolver

// handleLocalConnection processes a single redirected connection
func handleLocalConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[LOCAL] Redirected connection from %s", remoteAddr)

	if tunnelMgr == nil {
		log.Printf("[LOCAL] Tunnel manager not initialized")
		return
	}

	// Recover the original destination (which peer:port the agent dialed) so we
	// route to the correct peer. Falls back to the configured peer if recovery
	// is unavailable (e.g. single-peer mode without the BPF map).
	peerIP, destPort := configuredPeerIP, 8080
	if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		if ip, port, found := origDest.Resolve(ra.Port); found {
			peerIP, destPort = ip, port
		}
	}
	if peerIP == "" {
		log.Printf("[LOCAL] Could not determine destination peer; dropping")
		return
	}

	// Classify the channel from the recovered destination (docs/channel-classes.md):
	// fast (splice), guarded (enforcer pipeline), or deny. Deny is refused before we
	// pay for a tunnel.
	factories, class := tunnelMgr.egress.classify(destPort)
	if class == classDeny {
		metrics.egressDenied.Add(1)
		log.Printf("[LOCAL] Egress to %s:%d denied by policy", peerIP, destPort)
		return
	}

	// Acquire a data connection. In attested mode the per-peer warm pool hands back
	// a dedicated tunnel plus the session's EKM exporter + attestation epoch (for
	// x402 binding); CA mode uses a plain tunnel (no exporter, no epoch).
	var h streamHandle
	var err error
	if tunnelMgr.attestEnabled {
		h, err = tunnelMgr.channelFor(peerIP).stream()
	} else {
		var dc net.Conn
		var closer io.Closer
		dc, closer, _, err = tunnelMgr.CreateDedicatedTunnel(peerIP)
		h = streamHandle{conn: dc, close: closer}
	}
	if err != nil {
		log.Printf("[LOCAL] Failed to obtain tunnel to %s: %v", peerIP, err)
		return
	}
	dataConn := h.conn
	defer h.close.Close()
	log.Printf("[LOCAL] Tunnel to %s:%d ready", peerIP, destPort)

	// Destination header: the original peer IP + port (the receiver dials
	// 127.0.0.1:port). Attestation (gate or resume) already completed during
	// tunnel setup, so the request follows directly — no control tags.
	destHeader := make([]byte, HeaderSize)
	if ip4 := net.ParseIP(peerIP).To4(); ip4 != nil {
		copy(destHeader[0:4], ip4)
	}
	binary.BigEndian.PutUint16(destHeader[4:6], uint16(destPort))
	if _, err = dataConn.Write(destHeader); err != nil {
		log.Printf("[LOCAL] Failed to send destination header: %v", err)
		return
	}

	// Guarded channel: run the enforcer pipeline in userspace (no splice). Each
	// enforcer (x402, MCP, …) vets every request; it forwards only if all permit it —
	// the model's `⊢ Forward` with conjoined premises.
	if class == classGuarded {
		cc := channelContext{
			exp: h.exp, epoch: h.epoch, manifest: tunnelMgr.manifestFor(peerIP),
			peerIP: peerIP, destPort: destPort,
		}
		reqs, rh := buildPipeline(factories, cc)
		guardedProxy(conn, dataConn, reqs, rh)
		log.Printf("[LOCAL] Connection closed (guarded: %d enforcer(s))", len(reqs))
		return
	}

	// Fast channel: authorization is done; move bytes with the daemon off the path.
	// A dedicated kTLS tunnel (both ends *net.TCPConn) rides the splice(2) fast
	// path — zero userspace copy.
	if spliceable(dataConn, conn) {
		log.Printf("[LOCAL] Data plane: kernel splice (zero-copy)")
	}
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := relay(dataConn, conn)
		closeWrite(dataConn)
		log.Printf("[LOCAL] Sent %d bytes through tunnel", n)
	}()

	go func() {
		defer wg.Done()
		n, _ := relay(conn, dataConn)
		closeWrite(conn)
		log.Printf("[LOCAL] Received %d bytes from tunnel", n)
	}()

	wg.Wait()
	log.Printf("[LOCAL] Connection closed")
}

// attestParams holds the raw attestation flag values.
type attestParams struct {
	identity      string
	mrtd          string
	rtmrs         [4]string
	minTCB        string
	allowDebug    bool
	getCollateral bool
	checkRevoke   bool
	certTTL       time.Duration
	timeout       time.Duration
	measureOnly   bool
	mcpManifest   string
	mcpCaps       string
	mcpScopes     string
	allowKeys     string
	agentMeas     string
	peerAgent     string
}

// buildAttestConfig parses attestation flags into an AttestConfig, opening the
// TDX quote provider (fails closed if not inside a TD).
func buildAttestConfig(p attestParams) (*AttestConfig, error) {
	mrtd, err := parseHexLen("attest-mrtd", p.mrtd, 48)
	if err != nil {
		return nil, err
	}

	rtmrs := make([][]byte, 4)
	anyRTMR := false
	for i, h := range p.rtmrs {
		v, err := parseHexLen(fmt.Sprintf("attest-rtmr%d", i), h, 48)
		if err != nil {
			return nil, err
		}
		rtmrs[i] = v
		anyRTMR = anyRTMR || v != nil
	}
	if !anyRTMR {
		rtmrs = nil // nothing to enforce
	}

	minTCB, err := parseHexLen("attest-min-tcb-svn", p.minTCB, 16)
	if err != nil {
		return nil, err
	}

	if p.checkRevoke && !p.getCollateral {
		return nil, fmt.Errorf("--attest-check-revocations requires --attest-get-collateral")
	}

	policy := attest.Policy{
		MRTD:             mrtd,
		RTMRs:            rtmrs,
		MinTeeTcbSvn:     minTCB,
		AllowDebug:       p.allowDebug,
		GetCollateral:    p.getCollateral,
		CheckRevocations: p.checkRevoke,
	}

	// Measure-only bootstrap: still verify quote signature + REPORT_DATA binding,
	// but enforce no measurement policy so the peer's golden values can be logged.
	if p.measureOnly {
		if mrtd != nil || anyRTMR || minTCB != nil {
			log.Println("   WARNING: --attest-measure-only ignores --attest-mrtd/--attest-rtmr*/--attest-min-tcb-svn")
		}
		policy.MRTD, policy.RTMRs, policy.MinTeeTcbSvn = nil, nil, nil
		policy.AllowDebug = true // bootstrap TDs may be debuggable
		log.Println("   ATTEST MODE: measure-only (NO measurement policy enforced -- bootstrap use only)")
	} else {
		if mrtd == nil {
			log.Println("   WARNING: --attest-mrtd not set; peer MRTD will NOT be pinned (quote signature still verified)")
		}
		if p.allowDebug {
			log.Println("   WARNING: --attest-allow-debug set; debuggable peer TDs will be accepted (INSECURE)")
		}
	}

	quoter, err := attest.NewConfigfsQuoter()
	if err != nil {
		return nil, fmt.Errorf("TDX quoting unavailable: %w", err)
	}

	// MCP capability governance bound into the gate.
	var localManifest []byte
	if p.mcpManifest != "" {
		localManifest, err = os.ReadFile(p.mcpManifest)
		if err != nil {
			return nil, fmt.Errorf("read --mcp-manifest: %w", err)
		}
	}
	capPolicy := capability.NewPolicy(splitAndTrim(p.mcpCaps, ","), splitAndTrim(p.mcpScopes, ","))

	// Instance-key allowlist (Policy says K ⇒ TrustedPeer): hex SHA-256 of TLS SPKI.
	var allowKeys [][32]byte
	for _, h := range splitAndTrim(p.allowKeys, ",") {
		k, kerr := parseHexLen("attest-allow-instance-key", h, 32)
		if kerr != nil {
			return nil, kerr
		}
		var arr [32]byte
		copy(arr[:], k)
		allowKeys = append(allowKeys, arr)
	}

	// Agent-code measurement (advertise ours, optionally pin the peer's).
	var agentMeas, peerAgent []byte
	if p.agentMeas != "" {
		if agentMeas, err = hex.DecodeString(p.agentMeas); err != nil {
			return nil, fmt.Errorf("--attest-agent-measurement: invalid hex: %w", err)
		}
	}
	if p.peerAgent != "" {
		if peerAgent, err = hex.DecodeString(p.peerAgent); err != nil {
			return nil, fmt.Errorf("--attest-peer-agent-measurement: invalid hex: %w", err)
		}
	}

	return &AttestConfig{
		Quoter:            quoter,
		Verifier:          attest.NewTDXVerifier(policy),
		Identity:          p.identity,
		CertTTL:           p.certTTL,
		Timeout:           p.timeout,
		MeasureOnly:       p.measureOnly,
		LocalManifest:     localManifest,
		CapPolicy:         capPolicy,
		AllowInstanceKeys: allowKeys,
		AgentMeasurement:  agentMeas,
		PeerAgent:         peerAgent,
	}, nil
}

// parseHexLen decodes a hex string and asserts an exact byte length. An empty
// string yields (nil, nil) meaning "not set / not enforced".
func parseHexLen(name, h string, want int) ([]byte, error) {
	if h == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("--%s: invalid hex: %w", name, err)
	}
	if len(b) != want {
		return nil, fmt.Errorf("--%s: expected %d bytes, got %d", name, want, len(b))
	}
	return b, nil
}

// parseAmount parses a decimal smallest-unit amount; "" yields nil (no cap).
func parseAmount(s string) (*big.Int, error) {
	if s == "" {
		return nil, nil
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 {
		return nil, fmt.Errorf("not a non-negative integer: %q", s)
	}
	return v, nil
}

// stringSet builds a set from items (no case folding; networks are exact).
func stringSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
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

// parseAgentPorts parses a comma-separated port list, ignoring invalid entries.
// Always returns at least the legacy agent port so interception never silently
// degrades to a no-op when given a malformed flag.
func parseAgentPorts(s string) []int {
	var ports []int
	seen := make(map[int]bool)
	for _, part := range splitAndTrim(s, ",") {
		p, err := strconv.Atoi(part)
		if err != nil || p <= 0 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		ports = append(ports, p)
	}
	if len(ports) == 0 {
		ports = []int{8080}
	}
	return ports
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
