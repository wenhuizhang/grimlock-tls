package main

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestParseAgentPorts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"8080", []int{8080}},
		{"8080,9090, 7000", []int{8080, 9090, 7000}},
		{"8080,8080,9090", []int{8080, 9090}}, // dedup
		{"", []int{8080}},                     // empty -> default
		{"bad,0,70000,-1", []int{8080}},       // all invalid -> default
		{"443,bad,8443", []int{443, 8443}},    // skip invalid, keep valid
	}
	for _, c := range cases {
		if got := parseAgentPorts(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseAgentPorts(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestChannelFor_PerPeerLazyAndCached: one warm pool per peer, created lazily and
// reused. Loopback peers with no listener make the pool's warm dials fail fast
// (connection refused); keyLog is set so those background establishes don't panic.
func TestChannelFor_PerPeerLazyAndCached(t *testing.T) {
	tm := &TunnelManager{channelDepth: 1}
	defer tm.Close()
	a1 := tm.channelFor("127.0.0.1")
	a2 := tm.channelFor("127.0.0.1")
	b := tm.channelFor("127.0.0.2")
	if a1 == nil || a1 != a2 {
		t.Fatal("same peer should reuse one pool")
	}
	if b == nil || b == a1 {
		t.Fatal("different peers should get different pools")
	}
	if a1.peerIP != "127.0.0.1" || b.peerIP != "127.0.0.2" {
		t.Fatalf("wrong peer binding: %q %q", a1.peerIP, b.peerIP)
	}
}

// TestResumeCache exercises the resumption-secret store: put returns a monotone
// generation, get returns live entries and evicts expired ones.
func TestResumeCache(t *testing.T) {
	var k1, k2 [32]byte
	k1[0], k2[0] = 1, 2
	rs := bytes.Repeat([]byte{0xab}, 32)

	c := newResumeCache(0) // never expires
	g1 := c.put(k1, rs)
	g2 := c.put(k2, rs)
	if g2 <= g1 {
		t.Fatalf("generation must be monotone: %d then %d", g1, g2)
	}
	if e, ok := c.get(k1); !ok || e.gen != g1 || !bytes.Equal(e.rs, rs) {
		t.Fatalf("get(k1) = %+v ok=%v, want gen %d", e, ok, g1)
	}
	if _, ok := c.get([32]byte{9}); ok {
		t.Fatal("absent key must miss")
	}

	// Expiry: a past TTL evicts on read.
	exp := newResumeCache(time.Nanosecond)
	exp.put(k1, rs)
	time.Sleep(time.Millisecond)
	if _, ok := exp.get(k1); ok {
		t.Fatal("expired entry must be evicted")
	}
}

func TestOrigDestResolver_NilSafe(t *testing.T) {
	var r *origDestResolver
	if _, _, ok := r.Resolve(1234); ok {
		t.Fatal("nil resolver must report not-found")
	}
	if _, _, ok := newOrigDestResolver(nil).Resolve(1234); ok {
		t.Fatal("nil map must report not-found")
	}
}
