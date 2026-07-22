// Original-destination recovery for multi-peer routing.
//
// eBPF connect4 rewrites the agent's connect() to 127.0.0.1:15001, losing which
// peer it dialed. The BPF cookie->port bridge records the original (peer, port)
// keyed by the agent's ephemeral source port in the port_dest map. The local
// listener's accepted connection has that source port as its RemoteAddr, so we
// look it up here to route the request to the correct peer.

package main

import (
	"time"

	"github.com/cilium/ebpf"
)

type origDestResolver struct {
	m *ebpf.Map
}

func newOrigDestResolver(m *ebpf.Map) *origDestResolver { return &origDestResolver{m: m} }

// Resolve returns the original (peerIP, port) for the agent's ephemeral source
// port. It retries briefly to cover the race between sock_ops populating the map
// and the listener accepting the connection.
//
// The lookup is consume-on-read: the routing token is a LINEAR resource (model
// §R-forward), taken exactly once. The entry is keyed by the agent's ephemeral
// source port, which is owned by the live loopback connection we are handling,
// so it cannot be reused (ABA) before we consume it; Lookup+Delete is therefore
// equivalent to an atomic take here and is portable across kernels.
func (r *origDestResolver) Resolve(srcPort int) (peerIP string, port int, ok bool) {
	if r == nil || r.m == nil {
		return "", 0, false
	}
	key := uint32(srcPort)
	var v bpfOrigDest
	for i := 0; i < 10; i++ {
		if err := r.m.Lookup(key, &v); err == nil {
			_ = r.m.Delete(key) // consume the single-use routing token
			return uint32ToIP(v.Ip).String(), int(v.Port), true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return "", 0, false
}
