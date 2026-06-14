// sk_skb redirect test
//
// This tests whether we can redirect incoming data between sockets
// using eBPF sk_skb programs. This is crucial for our Grimlock design.
//
// Test scenario:
//   1. Socket A (server on :18081) accepts connection from Client
//   2. Socket B (server on :18082) - redirect target
//   3. Configure redirect: data arriving on A -> goes to B
//   4. Client sends "HELLO" to A
//   5. B receives "HELLO" (not A!)
//
// Run with: sudo go run .

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I../../src/bpf" bpf redirect.bpf.c

const (
	portA = 18081
	portB = 18082
)

func main() {
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "Cgroup path for sock_ops")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("============================================")
	log.Println("  sk_skb Redirect Test")
	log.Println("============================================")
	log.Println()

	// Remove memlock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load eBPF programs
	log.Println("[1/6] Loading eBPF programs...")
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

	// Attach sock_ops to cgroup
	log.Printf("[2/6] Attaching sock_ops to %s...", *cgroupPath)
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

	// Attach sk_skb programs to sockmap using prog attach (not link)
	log.Println("[3/6] Attaching sk_skb to sockmap...")
	
	// Use the lower-level prog attach for sk_skb
	// This is more compatible than link-based attach
	err = attachSkSkb(objs.SockMap.FD(), objs.StreamParser.FD(), ebpf.AttachSkSKBStreamParser)
	if err != nil {
		log.Fatalf("Failed to attach stream_parser: %v", err)
	}
	log.Println("   ✓ stream_parser attached")

	err = attachSkSkb(objs.SockMap.FD(), objs.StreamVerdict.FD(), ebpf.AttachSkSKBStreamVerdict)
	if err != nil {
		log.Fatalf("Failed to attach stream_verdict: %v", err)
	}
	log.Println("   ✓ stream_verdict attached")

	// Create test sockets
	log.Println("[4/6] Creating test sockets...")

	// Server A on portA
	listenerA, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", portA))
	if err != nil {
		log.Fatalf("Failed to listen on A: %v", err)
	}
	defer listenerA.Close()
	log.Printf("   Server A listening on :%d", portA)

	// Server B on portB
	listenerB, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", portB))
	if err != nil {
		log.Fatalf("Failed to listen on B: %v", err)
	}
	defer listenerB.Close()
	log.Printf("   Server B listening on :%d", portB)

	// Accept channels
	connACh := make(chan net.Conn, 1)
	connBCh := make(chan net.Conn, 1)
	errCh := make(chan error, 2)

	// Accept on A
	go func() {
		conn, err := listenerA.Accept()
		if err != nil {
			errCh <- fmt.Errorf("accept A: %w", err)
			return
		}
		connACh <- conn
	}()

	// Accept on B
	go func() {
		conn, err := listenerB.Accept()
		if err != nil {
			errCh <- fmt.Errorf("accept B: %w", err)
			return
		}
		connBCh <- conn
	}()

	// Wait a moment for listeners to be ready
	time.Sleep(100 * time.Millisecond)

	// TEST 1: Baseline (no redirect)
	log.Println()
	log.Println("[5/6] Test 1: Baseline (no redirect)...")

	clientA, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", portA))
	if err != nil {
		log.Fatalf("Failed to connect to A: %v", err)
	}

	var connA net.Conn
	select {
	case connA = <-connACh:
		log.Printf("   Server A accepted, local port: %d", getLocalPort(connA))
	case err := <-errCh:
		log.Fatalf("Accept error: %v", err)
	case <-time.After(2 * time.Second):
		log.Fatal("Timeout waiting for accept A")
	}

	// Print stats before test
	printStats(&objs, "Before baseline test")

	// Send test data
	testData := []byte("BASELINE_TEST_12345")
	if _, err := clientA.Write(testData); err != nil {
		log.Fatalf("Write failed: %v", err)
	}
	log.Printf("   Client sent: %q", testData)

	// Read on A
	buf := make([]byte, 1024)
	connA.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := connA.Read(buf)
	if err != nil {
		log.Printf("   Server A read error: %v", err)
	} else {
		log.Printf("   Server A received: %q", buf[:n])
		if string(buf[:n]) == string(testData) {
			log.Println("   ✓ Baseline test PASSED")
		}
	}

	printStats(&objs, "After baseline test")

	// Close baseline connections
	clientA.Close()
	connA.Close()

	// Re-create listeners for redirect test
	listenerA.Close()
	listenerB.Close()
	time.Sleep(100 * time.Millisecond)

	listenerA, _ = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", portA))
	defer listenerA.Close()
	listenerB, _ = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", portB))
	defer listenerB.Close()

	// Accept goroutines for redirect test
	go func() {
		conn, err := listenerA.Accept()
		if err != nil {
			return
		}
		connACh <- conn
	}()
	go func() {
		conn, err := listenerB.Accept()
		if err != nil {
			return
		}
		connBCh <- conn
	}()

	time.Sleep(100 * time.Millisecond)

	// TEST 2: With redirect
	log.Println()
	log.Println("[6/6] Test 2: With redirect (A -> B)...")

	// First, establish connection to B (so B's socket is in sockmap)
	clientB, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", portB))
	if err != nil {
		log.Fatalf("Failed to connect to B: %v", err)
	}
	defer clientB.Close()

	var connB net.Conn
	select {
	case connB = <-connBCh:
		log.Printf("   Server B accepted, local port: %d", getLocalPort(connB))
	case <-time.After(2 * time.Second):
		log.Fatal("Timeout waiting for accept B")
	}
	defer connB.Close()

	// Now connect to A
	clientA2, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", portA))
	if err != nil {
		log.Fatalf("Failed to connect to A: %v", err)
	}
	defer clientA2.Close()

	var connA2 net.Conn
	select {
	case connA2 = <-connACh:
		log.Printf("   Server A accepted, local port: %d", getLocalPort(connA2))
	case <-time.After(2 * time.Second):
		log.Fatal("Timeout waiting for accept A")
	}
	defer connA2.Close()

	// Get the actual local ports of the accepted sockets
	portASock := uint32(getLocalPort(connA2))
	portBSock := uint32(getLocalPort(connB))
	
	log.Printf("   Configuring redirect: port %d -> port %d", portASock, portBSock)

	// Configure redirect: A -> B
	if err := objs.RedirectMap.Put(portASock, portBSock); err != nil {
		log.Fatalf("Failed to set redirect: %v", err)
	}
	log.Println("   ✓ Redirect configured in eBPF map")

	printStats(&objs, "After redirect config")

	// Send data to A
	testData2 := []byte("REDIRECT_TEST_DATA_67890")
	if _, err := clientA2.Write(testData2); err != nil {
		log.Fatalf("Write to A failed: %v", err)
	}
	log.Printf("   Client sent to A: %q", testData2)

	// Try to read on A (should timeout - data was redirected)
	connA2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err = connA2.Read(buf)
	if err != nil {
		log.Printf("   Server A: read timeout (expected - data redirected)")
	} else {
		log.Printf("   Server A received: %q (redirect may have failed!)", buf[:n])
	}

	// Try to read on B (should receive the data!)
	connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = connB.Read(buf)
	if err != nil {
		log.Printf("   Server B read error: %v", err)
		log.Println("   ✗ Redirect test FAILED - B did not receive data")
	} else {
		log.Printf("   Server B received: %q", buf[:n])
		if string(buf[:n]) == string(testData2) {
			log.Println()
			log.Println("   ╔══════════════════════════════════════════╗")
			log.Println("   ║  ✓✓✓ REDIRECT TEST PASSED! ✓✓✓           ║")
			log.Println("   ║  Data sent to A arrived at B!            ║")
			log.Println("   ╚══════════════════════════════════════════╝")
		}
	}

	printStats(&objs, "Final stats")

	log.Println()
	log.Println("Press Ctrl+C to exit...")
	
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	
	select {
	case <-sig:
	case <-time.After(5 * time.Second):
	}
	
	log.Println("Done.")
}

func getLocalPort(conn net.Conn) int {
	addr := conn.LocalAddr().(*net.TCPAddr)
	return addr.Port
}

// attachSkSkb attaches sk_skb program to sockmap via BPF_PROG_ATTACH syscall
func attachSkSkb(mapFD, progFD int, attachType ebpf.AttachType) error {
	// BPF syscall number on x86_64 Linux
	const SYS_BPF = 321
	const BPF_PROG_ATTACH = 8
	
	// struct bpf_attr for BPF_PROG_ATTACH:
	// __u32 target_fd;
	// __u32 attach_bpf_fd;
	// __u32 attach_type;
	// __u32 attach_flags;
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
		if err := objs.Stats.Lookup(uint32(i), &val); err == nil {
			stats[i] = val
		}
	}
	log.Printf("   [%s] sockops_est=%d close=%d parser=%d verdict=%d redir_ok=%d redir_fail=%d pass=%d",
		label, stats[0], stats[1], stats[2], stats[3], stats[4], stats[5], stats[6])
}
