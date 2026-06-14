//go:build ignore

// Test program for sk_skb redirect
//
// This loads the sk_skb eBPF program and tests whether data can be
// redirected between two sockets.
//
// Test scenario:
// 1. Create server socket A on port 18081
// 2. Create server socket B on port 18082
// 3. Client connects to A, sends "HELLO"
// 4. sk_skb redirects the data to B
// 5. B receives "HELLO" (not A!)
//
// Usage: go run redirect_test.go

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" bpf redirect_test.bpf.c

const (
	portA = 18081
	portB = 18082
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("==============================================")
	log.Println("  sk_skb Redirect Test")
	log.Println("==============================================")

	// Remove rlimit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load eBPF objects
	log.Println("[1] Loading eBPF programs...")
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier error:\n%+v", ve)
		}
		log.Fatalf("Failed to load: %v", err)
	}
	defer objs.Close()
	log.Println("   ✓ eBPF programs loaded")

	// Attach sock_ops to cgroup
	log.Println("[2] Attaching sock_ops to cgroup...")
	cgroupPath := "/sys/fs/cgroup"
	sockOpsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.SockOpsHandler,
	})
	if err != nil {
		log.Fatalf("Failed to attach sock_ops: %v", err)
	}
	defer sockOpsLink.Close()
	log.Println("   ✓ sock_ops attached to", cgroupPath)

	// Attach sk_skb programs to sockmap
	log.Println("[3] Attaching sk_skb to sockmap...")

	// Attach stream_parser
	parserLink, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  objs.SockMap.FD(),
		Program: objs.SkSkbParser,
		Attach:  ebpf.AttachSkSKBStreamParser,
	})
	if err != nil {
		log.Fatalf("Failed to attach parser: %v", err)
	}
	defer parserLink.Close()
	log.Println("   ✓ stream_parser attached")

	// Attach stream_verdict
	verdictLink, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  objs.SockMap.FD(),
		Program: objs.SkSkbVerdict,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	})
	if err != nil {
		log.Fatalf("Failed to attach verdict: %v", err)
	}
	defer verdictLink.Close()
	log.Println("   ✓ stream_verdict attached")

	// Create server sockets
	log.Println("[4] Creating server sockets...")

	listenerA, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", portA))
	if err != nil {
		log.Fatalf("Failed to listen A: %v", err)
	}
	defer listenerA.Close()
	log.Printf("   Server A listening on :%d", portA)

	listenerB, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", portB))
	if err != nil {
		log.Fatalf("Failed to listen B: %v", err)
	}
	defer listenerB.Close()
	log.Printf("   Server B listening on :%d", portB)

	// Accept connections in background
	connACh := make(chan net.Conn, 1)
	connBCh := make(chan net.Conn, 1)

	go func() {
		conn, _ := listenerA.Accept()
		if conn != nil {
			log.Printf("   Server A accepted from %s", conn.RemoteAddr())
			connACh <- conn
		}
	}()

	go func() {
		conn, _ := listenerB.Accept()
		if conn != nil {
			log.Printf("   Server B accepted from %s", conn.RemoteAddr())
			connBCh <- conn
		}
	}()

	// Wait for sockets to be in sockmap
	time.Sleep(100 * time.Millisecond)

	// Test 1: Without redirect (baseline)
	log.Println("")
	log.Println("[5] Test 1: Baseline (no redirect)...")

	client1, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", portA))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	// Wait for accept
	var connA net.Conn
	select {
	case connA = <-connACh:
	case <-time.After(2 * time.Second):
		log.Fatal("Timeout waiting for accept")
	}

	// Get the accepted socket's local port (should be portA)
	serverPort := connA.LocalAddr().(*net.TCPAddr).Port
	log.Printf("   Server A accepted on port %d", serverPort)

	// Send test data
	testData := []byte("BASELINE_TEST")
	client1.Write(testData)
	log.Printf("   Client sent: %q", testData)

	// Read on server A
	buf := make([]byte, 1024)
	connA.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := connA.Read(buf)
	if err != nil {
		log.Printf("   Server A read error: %v", err)
	} else {
		log.Printf("   Server A received: %q", buf[:n])
		if bytes.Equal(buf[:n], testData) {
			log.Println("   ✓ Baseline test passed")
		}
	}

	client1.Close()
	connA.Close()

	// Print stats
	printStats(&objs)

	// Test 2: With redirect
	log.Println("")
	log.Println("[6] Test 2: With redirect (A → B)...")

	// Need new listeners since we closed the connections
	listenerA.Close()
	listenerB.Close()

	listenerA, _ = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", portA))
	defer listenerA.Close()
	listenerB, _ = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", portB))
	defer listenerB.Close()

	// Accept in background
	go func() {
		conn, _ := listenerA.Accept()
		if conn != nil {
			connACh <- conn
		}
	}()

	go func() {
		conn, _ := listenerB.Accept()
		if conn != nil {
			connBCh <- conn
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// First connect to B to get it in sockmap
	clientB, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", portB))
	if err != nil {
		log.Fatalf("Failed to connect to B: %v", err)
	}

	var connB net.Conn
	select {
	case connB = <-connBCh:
		log.Printf("   Server B accepted, local port %d", connB.LocalAddr().(*net.TCPAddr).Port)
	case <-time.After(2 * time.Second):
		log.Fatal("Timeout waiting for B accept")
	}

	// Now connect to A
	clientA, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", portA))
	if err != nil {
		log.Fatalf("Failed to connect to A: %v", err)
	}

	select {
	case connA = <-connACh:
		log.Printf("   Server A accepted, local port %d", connA.LocalAddr().(*net.TCPAddr).Port)
	case <-time.After(2 * time.Second):
		log.Fatal("Timeout waiting for A accept")
	}

	// Configure redirect: port A -> port B
	srcPort := uint32(connA.LocalAddr().(*net.TCPAddr).Port)
	dstPort := uint32(connB.LocalAddr().(*net.TCPAddr).Port)

	log.Printf("   Configuring redirect: %d → %d", srcPort, dstPort)

	// Update redirect_config map
	if err := objs.RedirectConfig.Put(srcPort, dstPort); err != nil {
		log.Fatalf("Failed to configure redirect: %v", err)
	}
	log.Println("   ✓ Redirect configured")

	// Send data to A
	testData2 := []byte("REDIRECT_TEST_DATA")
	clientA.Write(testData2)
	log.Printf("   Client sent to A: %q", testData2)

	// Try to read on A (should timeout or get nothing)
	connA.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err = connA.Read(buf)
	if err != nil {
		log.Printf("   Server A: %v (expected - data was redirected)", err)
	} else {
		log.Printf("   Server A received: %q (redirect may have failed!)", buf[:n])
	}

	// Try to read on B (should get the data!)
	connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = connB.Read(buf)
	if err != nil {
		log.Printf("   Server B read error: %v", err)
	} else {
		log.Printf("   Server B received: %q", buf[:n])
		if bytes.Equal(buf[:n], testData2) {
			log.Println("")
			log.Println("   ✓✓✓ REDIRECT TEST PASSED! ✓✓✓")
			log.Println("   Data sent to A arrived at B!")
		}
	}

	// Print final stats
	printStats(&objs)

	clientA.Close()
	clientB.Close()
	connA.Close()
	connB.Close()

	log.Println("")
	log.Println("Press Ctrl+C to exit (or wait for trace_pipe output)...")

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sig:
	case <-time.After(5 * time.Second):
	}

	log.Println("Done.")
}

func printStats(objs *bpfObjects) {
	var stats [8]uint64
	for i := 0; i < 6; i++ {
		var val uint64
		objs.Stats.Lookup(uint32(i), &val)
		stats[i] = val
	}
	log.Printf("   Stats: parser=%d verdict=%d redirect=%d pass=%d sockops=%d",
		stats[0], stats[1], stats[2], stats[3], stats[5])
}
