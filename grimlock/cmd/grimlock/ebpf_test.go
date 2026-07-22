package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// TestEBPF_LoadAndAttach loads the compiled connect4 + sock_ops programs into the
// running kernel (exercising the verifier) and attaches them to a fresh cgroup.
// Root-gated; run via: go test -c && sudo ./grimlock.test -test.run TestEBPF.
func TestEBPF_LoadAndAttach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load/attach eBPF (run the compiled test under sudo)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier REJECTED the programs:\n%+v", ve)
		}
		t.Fatalf("load failed: %v", err)
	}
	defer objs.Close()
	t.Log("eBPF verifier ACCEPTED connect4 + sock_ops; maps created")

	cg := "/sys/fs/cgroup/grimlock-ebpf-test"
	if err := os.Mkdir(cg, 0o755); err != nil && !os.IsExist(err) {
		t.Fatalf("create test cgroup: %v", err)
	}
	defer os.Remove(cg)

	sockops, err := link.AttachCgroup(link.CgroupOptions{
		Path: cg, Attach: ebpf.AttachCGroupSockOps, Program: objs.GrimlockSockops,
	})
	if err != nil {
		t.Fatalf("attach sock_ops: %v", err)
	}
	defer sockops.Close()

	connect4, err := link.AttachCgroup(link.CgroupOptions{
		Path: cg, Attach: ebpf.AttachCGroupInet4Connect, Program: objs.GrimlockConnect4,
	})
	if err != nil {
		t.Fatalf("attach connect4: %v", err)
	}
	defer connect4.Close()
	t.Log("connect4 + sock_ops ATTACHED to cgroup — verifier + attach OK on this kernel")
}

// TestEBPF_Connect4Redirects proves the redirect behaves: a process in the cgroup
// dialing an unreachable IP on an intercepted port lands on the local proxy
// (127.0.0.1:15001) instead — i.e. connect4 rewrote the destination. Root-gated.
func TestEBPF_Connect4Redirects(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load/attach eBPF")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("load: %v", err)
	}
	defer objs.Close()

	// connect4 redirects only when: config.enabled, the dst port is an intercepted
	// agent port, AND the dst IP is a known agent peer. Populate all three exactly
	// as the daemon does.
	if err := objs.ConfigMap.Put(uint32(0), Config{Enabled: 1, LocalIP: 0}); err != nil {
		t.Fatalf("populate config: %v", err)
	}
	const port uint16 = 8080
	if err := objs.AgentPorts.Put(uint32(port), uint8(1)); err != nil {
		t.Fatalf("populate agent_ports: %v", err)
	}
	const peer = "192.0.2.1" // TEST-NET-1, unreachable — only the redirect makes it connect
	if err := objs.AgentPeers.Put(ipToUint32(net.ParseIP(peer).To4()), uint8(1)); err != nil {
		t.Fatalf("populate agent_peers: %v", err)
	}

	// The local proxy connect4 redirects to: 127.0.0.1:15001.
	proxy, err := net.Listen("tcp", "127.0.0.1:15001")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:15001 (in use?): %v", err)
	}
	defer proxy.Close()
	landed := make(chan struct{}, 1)
	go func() {
		c, err := proxy.Accept()
		if err == nil {
			landed <- struct{}{}
			c.Close()
		}
	}()

	cg := "/sys/fs/cgroup/grimlock-redirect-test"
	if err := os.Mkdir(cg, 0o755); err != nil && !os.IsExist(err) {
		t.Fatalf("create cgroup: %v", err)
	}
	// Move THIS process into the cgroup so connect4 applies to its dials.
	if err := os.WriteFile(cg+"/cgroup.procs", []byte(fmt.Sprintf("%d", os.Getpid())), 0o644); err != nil {
		t.Fatalf("join cgroup: %v", err)
	}
	defer func() {
		// Move back to the root cgroup, then remove the test cgroup.
		_ = os.WriteFile("/sys/fs/cgroup/cgroup.procs", []byte(fmt.Sprintf("%d", os.Getpid())), 0o644)
		_ = os.Remove(cg)
	}()

	sockops, err := link.AttachCgroup(link.CgroupOptions{Path: cg, Attach: ebpf.AttachCGroupSockOps, Program: objs.GrimlockSockops})
	if err != nil {
		t.Fatalf("attach sock_ops: %v", err)
	}
	defer sockops.Close()
	connect4, err := link.AttachCgroup(link.CgroupOptions{Path: cg, Attach: ebpf.AttachCGroupInet4Connect, Program: objs.GrimlockConnect4})
	if err != nil {
		t.Fatalf("attach connect4: %v", err)
	}
	defer connect4.Close()

	// Dial an unreachable TEST-NET-1 address on the intercepted port. Without the
	// redirect this times out; with it, the connection lands on the local proxy.
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.Dial("tcp", net.JoinHostPort(peer, fmt.Sprintf("%d", port)))
	if err != nil {
		t.Fatalf("dial (redirect should have made this succeed): %v", err)
	}
	defer c.Close()

	select {
	case <-landed:
		t.Log("connect4 REDIRECT confirmed: dial to 192.0.2.1:8080 landed on 127.0.0.1:15001")
	case <-time.After(3 * time.Second):
		t.Fatal("connection did not land on the local proxy — redirect did not fire")
	}
}

// BenchmarkConnect4_Overhead measures the per-connect() cost the eBPF interception
// hook adds, by comparing dial latency with and without connect4 attached to the
// process's cgroup (config enabled; the hook runs its guards then allows).
// Root-gated. Quantifies the "unbypassable interception is cheap" claim.
func BenchmarkConnect4_Overhead(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("needs root to attach eBPF")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	addr := ln.Addr().String()
	dialLoop := func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				b.Fatal(err)
			}
			c.Close()
		}
	}

	b.Run("baseline_no_ebpf", dialLoop)

	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatal(err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		b.Fatal(err)
	}
	defer objs.Close()
	if err := objs.ConfigMap.Put(uint32(0), Config{Enabled: 1, LocalIP: 0}); err != nil {
		b.Fatal(err)
	}
	cg := "/sys/fs/cgroup/grimlock-bench"
	if err := os.Mkdir(cg, 0o755); err != nil && !os.IsExist(err) {
		b.Fatal(err)
	}
	if err := os.WriteFile(cg+"/cgroup.procs", []byte(fmt.Sprintf("%d", os.Getpid())), 0o644); err != nil {
		b.Fatal(err)
	}
	defer func() {
		_ = os.WriteFile("/sys/fs/cgroup/cgroup.procs", []byte(fmt.Sprintf("%d", os.Getpid())), 0o644)
		_ = os.Remove(cg)
	}()
	l, err := link.AttachCgroup(link.CgroupOptions{Path: cg, Attach: ebpf.AttachCGroupInet4Connect, Program: objs.GrimlockConnect4})
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()

	b.Run("connect4_attached", dialLoop)
}
