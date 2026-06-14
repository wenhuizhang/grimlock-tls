// Redirect Manager - sk_skb attachment and redirect configuration
//
// This file handles:
// 1. Attaching sk_skb programs to sockmap
// 2. Configuring redirect rules between sockets
// 3. Statistics monitoring

package main

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
)

// RedirectManager handles sk_skb and sk_msg attachment and redirect configuration
type RedirectManager struct {
	sockMap     *ebpf.Map
	redirectMap *ebpf.Map
	statsMap    *ebpf.Map
	parser      *ebpf.Program
	verdict     *ebpf.Program
	msgRedirect *ebpf.Program
	attached    bool
}

// Statistics indices (must match eBPF)
const (
	StatSockopsEstablished = 0
	StatSockopsClose       = 1
	StatParserCalls        = 2
	StatVerdictCalls       = 3
	StatRedirectOK         = 4
	StatRedirectFail       = 5
	StatPass               = 6
	StatSockmapAdd         = 7
)

// NewRedirectManager creates a new redirect manager
func NewRedirectManager(objs *bpfObjects) (*RedirectManager, error) {
	return &RedirectManager{
		sockMap:     objs.SockMap,
		redirectMap: objs.RedirectMap,
		statsMap:    objs.Stats,
		parser:      objs.GrimlockStreamParser,
		verdict:     objs.GrimlockStreamVerdict,
		msgRedirect: objs.GrimlockMsgRedirect,
		attached:    false,
	}, nil
}

// AttachSkSkb attaches sk_skb and sk_msg programs to the sockmap
func (rm *RedirectManager) AttachSkSkb() error {
	if rm.attached {
		return nil
	}

	// Attach stream_parser (for incoming data framing)
	if err := attachSkSkbToSockmap(rm.sockMap.FD(), rm.parser.FD(), ebpf.AttachSkSKBStreamParser); err != nil {
		return fmt.Errorf("attach stream_parser: %w", err)
	}
	log.Println("   ✓ stream_parser attached to sockmap")

	// Attach stream_verdict (for incoming data redirect)
	if err := attachSkSkbToSockmap(rm.sockMap.FD(), rm.verdict.FD(), ebpf.AttachSkSKBStreamVerdict); err != nil {
		return fmt.Errorf("attach stream_verdict: %w", err)
	}
	log.Println("   ✓ stream_verdict attached to sockmap")

	// Attach sk_msg (for outgoing data redirect)
	if rm.msgRedirect != nil {
		if err := attachSkSkbToSockmap(rm.sockMap.FD(), rm.msgRedirect.FD(), ebpf.AttachSkMsgVerdict); err != nil {
			return fmt.Errorf("attach sk_msg: %w", err)
		}
		log.Println("   ✓ sk_msg attached to sockmap")
	}

	rm.attached = true
	return nil
}

// ConfigureRedirect sets up a redirect from sourcePort to targetPort
// Data arriving at sourcePort socket will be redirected to targetPort socket
func (rm *RedirectManager) ConfigureRedirect(sourcePort, targetPort uint32) error {
	if err := rm.redirectMap.Put(sourcePort, targetPort); err != nil {
		return fmt.Errorf("put redirect: %w", err)
	}
	log.Printf("[REDIRECT] Configured: port %d -> port %d", sourcePort, targetPort)
	return nil
}

// RemoveRedirect removes a redirect rule
func (rm *RedirectManager) RemoveRedirect(sourcePort uint32) error {
	if err := rm.redirectMap.Delete(sourcePort); err != nil {
		return fmt.Errorf("delete redirect: %w", err)
	}
	log.Printf("[REDIRECT] Removed: port %d", sourcePort)
	return nil
}

// GetStats returns current statistics
func (rm *RedirectManager) GetStats() map[string]uint64 {
	stats := make(map[string]uint64)
	names := []string{
		"sockops_established",
		"sockops_close",
		"parser_calls",
		"verdict_calls",
		"redirect_ok",
		"redirect_fail",
		"pass",
		"sockmap_add",
	}

	for i, name := range names {
		var val uint64
		if err := rm.statsMap.Lookup(uint32(i), &val); err == nil {
			stats[name] = val
		}
	}
	return stats
}

// LogStats logs current statistics
func (rm *RedirectManager) LogStats() {
	stats := rm.GetStats()
	log.Printf("[STATS] est=%d close=%d parser=%d verdict=%d redir_ok=%d redir_fail=%d pass=%d sockmap=%d",
		stats["sockops_established"],
		stats["sockops_close"],
		stats["parser_calls"],
		stats["verdict_calls"],
		stats["redirect_ok"],
		stats["redirect_fail"],
		stats["pass"],
		stats["sockmap_add"],
	)
}

// attachSkSkbToSockmap attaches sk_skb program to sockmap via BPF_PROG_ATTACH syscall
// This is necessary because link.AttachRawLink doesn't work for sk_skb
// Lesson learned: High-level APIs often lag kernel capabilities
func attachSkSkbToSockmap(mapFD, progFD int, attachType ebpf.AttachType) error {
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
