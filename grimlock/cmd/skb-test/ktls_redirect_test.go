//go:build ignore

// kTLS + sk_skb redirect test
//
// This tests whether sk_skb redirect works with kTLS sockets
// and whether sk_skb sees decrypted or encrypted data.
//
// Run with: sudo go run ktls_redirect_test.go

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	tlsPortA = 19443 // TLS server with kTLS
	tcpPortB = 19444 // Plain TCP redirect target
)

func main() {
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "Cgroup path")
	certDir := flag.String("certs", "../../certs", "Certificate directory")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("============================================")
	log.Println("  kTLS + sk_skb Redirect Test")
	log.Println("============================================")
	log.Println()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load eBPF (reuse the same programs)
	log.Println("[1/7] Loading eBPF programs...")
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier error:\n%+v", ve)
		}
		log.Fatalf("Failed to load eBPF: %v", err)
	}
	defer objs.Close()
	log.Println("   ✓ Programs loaded")

	// Attach sock_ops
	log.Printf("[2/7] Attaching sock_ops to %s...", *cgroupPath)
	sockOpsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.SockOpsHandler,
	})
	if err != nil {
		log.Fatalf("Failed to attach sock_ops: %v", err)
	}
	defer sockOpsLink.Close()
	log.Println("   ✓ sock_ops attached")

	// Attach sk_skb
	log.Println("[3/7] Attaching sk_skb to sockmap...")
	if err := attachSkSkb(objs.SockMap.FD(), objs.StreamParser.FD(), ebpf.AttachSkSKBStreamParser); err != nil {
		log.Fatalf("Failed to attach parser: %v", err)
	}
	if err := attachSkSkb(objs.SockMap.FD(), objs.StreamVerdict.FD(), ebpf.AttachSkSKBStreamVerdict); err != nil {
		log.Fatalf("Failed to attach verdict: %v", err)
	}
	log.Println("   ✓ sk_skb attached")

	// Load certificates
	log.Println("[4/7] Loading certificates...")
	cert, err := tls.LoadX509KeyPair(
		*certDir+"/agent-a.crt",
		*certDir+"/agent-a.pem",
	)
	if err != nil {
		log.Fatalf("Failed to load cert: %v", err)
	}
	caCert, err := os.ReadFile(*certDir + "/ca.crt")
	if err != nil {
		log.Fatalf("Failed to load CA: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)
	log.Println("   ✓ Certificates loaded")

	// Create TLS server
	log.Println("[5/7] Creating TLS server with kTLS...")
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	tlsListener, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPortA), tlsConfig)
	if err != nil {
		log.Fatalf("Failed to create TLS listener: %v", err)
	}
	defer tlsListener.Close()
	log.Printf("   TLS server listening on :%d", tlsPortA)

	// Create plain TCP server (redirect target)
	tcpListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPortB))
	if err != nil {
		log.Fatalf("Failed to create TCP listener: %v", err)
	}
	defer tcpListener.Close()
	log.Printf("   TCP server listening on :%d", tcpPortB)

	// Accept channels
	tlsConnCh := make(chan *tls.Conn, 1)
	tcpConnCh := make(chan net.Conn, 1)

	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			log.Printf("TLS accept error: %v", err)
			return
		}
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("TLS handshake error: %v", err)
			return
		}
		log.Printf("   TLS connection accepted, cipher: %s",
			tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite))
		tlsConnCh <- tlsConn
	}()

	go func() {
		conn, err := tcpListener.Accept()
		if err != nil {
			return
		}
		tcpConnCh <- conn
	}()

	time.Sleep(100 * time.Millisecond)

	// Connect TCP client to port B (so it's in sockmap)
	log.Println("[6/7] Establishing connections...")
	tcpClient, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPortB))
	if err != nil {
		log.Fatalf("Failed to connect to TCP: %v", err)
	}
	defer tcpClient.Close()

	var tcpServerConn net.Conn
	select {
	case tcpServerConn = <-tcpConnCh:
		log.Printf("   TCP server accepted on port %d", tcpServerConn.LocalAddr().(*net.TCPAddr).Port)
	case <-time.After(2 * time.Second):
		log.Fatal("Timeout waiting for TCP accept")
	}
	defer tcpServerConn.Close()

	// Connect TLS client
	clientConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true, // For localhost testing
		MinVersion:         tls.VersionTLS13,
	}
	tlsClient, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPortA), clientConfig)
	if err != nil {
		log.Fatalf("Failed TLS dial: %v", err)
	}
	defer tlsClient.Close()

	var tlsServerConn *tls.Conn
	select {
	case tlsServerConn = <-tlsConnCh:
		log.Printf("   TLS server accepted on port %d", getLocalPort(tlsServerConn))
	case <-time.After(2 * time.Second):
		log.Fatal("Timeout waiting for TLS accept")
	}
	defer tlsServerConn.Close()

	// Try to enable kTLS on server connection
	log.Println("[7/7] Testing kTLS + sk_skb redirect...")
	
	// Get the underlying TCP connection
	tcpConn, err := getTCPConn(tlsServerConn)
	if err != nil {
		log.Printf("   Note: Could not get TCP conn for kTLS: %v", err)
		log.Println("   Testing WITHOUT kTLS (TLS handled in user-space)")
	} else {
		// Try to enable kTLS
		if err := enableKTLS(tcpConn); err != nil {
			log.Printf("   Note: kTLS not enabled: %v", err)
		} else {
			log.Println("   ✓ kTLS enabled on TLS connection")
		}
	}

	// Get local ports for redirect config
	tlsPort := uint32(getLocalPort(tlsServerConn))
	tcpPort := uint32(tcpServerConn.LocalAddr().(*net.TCPAddr).Port)

	log.Printf("   Configuring redirect: TLS port %d -> TCP port %d", tlsPort, tcpPort)
	if err := objs.RedirectMap.Put(tlsPort, tcpPort); err != nil {
		log.Fatalf("Failed to set redirect: %v", err)
	}

	printStats(&objs, "Before send")

	// Send data through TLS
	testData := "KTLS_REDIRECT_TEST_SECRET_DATA"
	log.Printf("   TLS client sending: %q", testData)
	if _, err := tlsClient.Write([]byte(testData)); err != nil {
		log.Fatalf("TLS write failed: %v", err)
	}

	// Try to read on TLS server (should timeout if redirected)
	tlsServerConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	n, err := tlsServerConn.Read(buf)
	if err != nil {
		log.Printf("   TLS server: read timeout/error (data may have been redirected)")
	} else {
		log.Printf("   TLS server received: %q", buf[:n])
		log.Println("   Note: Data arrived at TLS server - redirect may not work with TLS")
	}

	// Try to read on TCP server (redirect target)
	tcpServerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = tcpServerConn.Read(buf)
	if err != nil {
		log.Printf("   TCP server: read error: %v", err)
		log.Println("   ✗ Redirect did not work - TCP server got nothing")
	} else {
		received := string(buf[:n])
		log.Printf("   TCP server received: %q", received)
		
		if received == testData {
			log.Println()
			log.Println("   ╔════════════════════════════════════════════════╗")
			log.Println("   ║  ✓ kTLS + sk_skb REDIRECT WORKS!              ║")
			log.Println("   ║  sk_skb sees DECRYPTED data from kTLS!        ║")
			log.Println("   ╚════════════════════════════════════════════════╝")
		} else {
			log.Printf("   Data mismatch - received something unexpected")
		}
	}

	printStats(&objs, "Final")
	log.Println("Done.")
}

func getLocalPort(conn net.Conn) int {
	switch c := conn.(type) {
	case *tls.Conn:
		return c.LocalAddr().(*net.TCPAddr).Port
	case *net.TCPConn:
		return c.LocalAddr().(*net.TCPAddr).Port
	default:
		return conn.LocalAddr().(*net.TCPAddr).Port
	}
}

func getTCPConn(tlsConn *tls.Conn) (*net.TCPConn, error) {
	connVal := reflect.ValueOf(tlsConn).Elem()
	netConnField := connVal.FieldByName("conn")
	if !netConnField.IsValid() {
		return nil, fmt.Errorf("cannot find conn field")
	}
	netConnPtr := unsafe.Pointer(netConnField.UnsafeAddr())
	netConn := *(*net.Conn)(netConnPtr)
	tcpConn, ok := netConn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("not a TCP conn")
	}
	return tcpConn, nil
}

func enableKTLS(tcpConn *net.TCPConn) error {
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}
	
	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		// Try to set TCP_ULP to "tls"
		err := syscall.SetsockoptString(int(fd), syscall.SOL_TCP, 31, "tls")
		if err != nil {
			sockErr = fmt.Errorf("TCP_ULP failed: %v", err)
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}

func attachSkSkb(mapFD, progFD int, attachType ebpf.AttachType) error {
	const SYS_BPF = 321
	const BPF_PROG_ATTACH = 8
	
	attr := struct {
		targetFD    uint32
		attachBpfFD uint32
		attachType  uint32
		attachFlags uint32
	}{
		targetFD:    uint32(mapFD),
		attachBpfFD: uint32(progFD),
		attachType:  uint32(attachType),
		attachFlags: 0,
	}
	
	_, _, errno := syscall.Syscall(
		SYS_BPF,
		BPF_PROG_ATTACH,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return fmt.Errorf("BPF_PROG_ATTACH: %v", errno)
	}
	return nil
}

func printStats(objs *bpfObjects, label string) {
	var stats [8]uint64
	for i := 0; i < 7; i++ {
		var val uint64
		objs.Stats.Lookup(uint32(i), &val)
		stats[i] = val
	}
	log.Printf("   [%s] sockops=%d parser=%d verdict=%d redir_ok=%d redir_fail=%d pass=%d",
		label, stats[0], stats[2], stats[3], stats[4], stats[5], stats[6])
}
