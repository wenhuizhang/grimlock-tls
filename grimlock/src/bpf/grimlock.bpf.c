// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
//
// Grimlock eBPF Program - Transparent Security for AI Agent Communication
//
// This program:
// 1. Intercepts TCP connections to known agent peers (cgroup/connect4)
// 2. Redirects agent connections to local Grimlock listener
// 3. Tracks connections for observability (sock_ops)
//
// Architecture (NEW - verified working):
//   Agent A connect(B:8080) → eBPF redirect → Grimlock local:15001
//   Grimlock reads → Write to kTLS tunnel → Wire (encrypted)
//   Wire → Grimlock kTLS reads → Write to Agent B:8080

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Constants not in vmlinux.h
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef BPF_TCP_CLOSE
#define BPF_TCP_CLOSE 7
#endif

// Port we're interested in (A2A agents listen on 8080)
#define AGENT_PORT 8080

// Grimlock local listener port (for redirected connections)
#define GRIMLOCK_LOCAL_PORT 15001

// Grimlock tunnel port
#define TUNNEL_PORT 9443

// CRITICAL: Ports to NEVER touch (prevents lockout!)
#define SSH_PORT 22

// Localhost IP (127.0.0.1 in network byte order for little-endian)
#define LOCALHOST_IP 0x0100007f  // 127.0.0.1

// Event types sent to user-space
#define EVENT_CONNECT 1
#define EVENT_ACCEPT  2
#define EVENT_CLOSE   3

// Event structure sent to user-space via ring buffer
struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  event_type;
    __u8  padding[3];
};

// Ring buffer for events to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Map of known agent peer IPs (populated by user-space)
// Key: IPv4 address, Value: 1 if known agent
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} agent_peers SEC(".maps");

// Set of agent destination ports to intercept (populated by user-space).
// Lets connect4 redirect more than the single legacy AGENT_PORT so one agent
// host can expose several services. Always holds at least AGENT_PORT.
// Key: destination port (host byte order, widened to __u32), Value: 1.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} agent_ports SEC(".maps");

// Configuration from user-space
struct config {
    __u32 enabled;
    __u32 local_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

// =============================================================================
// Multi-peer: original-destination recovery
// =============================================================================
// connect4 rewrites the destination to 127.0.0.1:15001, losing which peer the
// agent dialed. To recover it per-connection for multi-peer routing we bridge:
//   connect4 (knows orig dest, not yet the source port): cookie -> orig_dest
//   sock_ops ESTABLISHED (knows cookie AND the bound source port): re-key to
//                                                  src_port -> orig_dest
//   user-space (sees the accepted conn's remote/source port): looks up port_dest

// The peer the agent originally dialed.
struct orig_dest {
    __u32 ip;    // network byte order (as in ctx->user_ip4)
    __u16 port;  // host byte order
    __u16 _pad;
};

// connect4 -> sock_ops bridge, keyed by socket cookie (LRU self-evicts strays).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct orig_dest);
} cookie_dest SEC(".maps");

// User-space lookup table, keyed by the agent's ephemeral source port.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct orig_dest);
} port_dest SEC(".maps");

// Helper: Check if IP is a known agent peer
static __always_inline bool is_agent_peer(__u32 ip) {
    __u8 *val = bpf_map_lookup_elem(&agent_peers, &ip);
    return val != NULL && *val == 1;
}

// Helper: Check if a destination port is an intercepted agent port.
static __always_inline bool is_agent_port(__u16 port) {
    __u32 key = port;
    __u8 *val = bpf_map_lookup_elem(&agent_ports, &key);
    return val != NULL && *val == 1;
}

// Helper: Get config
static __always_inline struct config *get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

// Helper: Send event to user-space
static __always_inline void send_event(__u8 type, __u32 src_ip, __u32 dst_ip,
                                       __u16 src_port, __u16 dst_port) {
    struct event *evt;
    
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return;
    
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = 0;  // PID not available in sockops context
    evt->src_ip = src_ip;
    evt->dst_ip = dst_ip;
    evt->src_port = src_port;
    evt->dst_port = dst_port;
    evt->event_type = type;
    
    bpf_ringbuf_submit(evt, 0);
}

// sock_ops program - emits connection lifecycle events to user-space for
// observability of A2A peer connections (CONNECT/ACCEPT/CLOSE).
SEC("sockops")
int grimlock_sockops(struct bpf_sock_ops *skops) {
    struct config *cfg;
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;

    // Only handle IPv4 TCP
    if (skops->family != AF_INET)
        return 0;

    // Get configuration
    cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 0;

    // Extract connection info
    src_ip = skops->local_ip4;
    dst_ip = skops->remote_ip4;
    // local_port is already in host byte order
    src_port = skops->local_port;
    // remote_port has port in upper 16 bits, in network byte order
    dst_port = bpf_ntohs(skops->remote_port >> 16);

    // CRITICAL: Never touch SSH traffic - prevents lockout!
    if (src_port == SSH_PORT || dst_port == SSH_PORT)
        return 0;

    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        // Multi-peer: bridge the original destination recorded by connect4 from
        // the socket cookie to the now-bound ephemeral source port, where
        // user-space looks it up on the accepted local connection. (By this point
        // the destination is the rewritten 127.0.0.1:15001, so we key on cookie.)
        {
            __u64 cookie = bpf_get_socket_cookie(skops);
            struct orig_dest *od = bpf_map_lookup_elem(&cookie_dest, &cookie);
            if (od) {
                __u32 sport = skops->local_port;
                bpf_map_update_elem(&port_dest, &sport, od, BPF_ANY);
                bpf_map_delete_elem(&cookie_dest, &cookie);
                bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
            }
        }
        break;

    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        // Incoming connection from a known agent peer.
        if (is_agent_port(src_port) && is_agent_peer(src_ip)) {
            send_event(EVENT_ACCEPT, dst_ip, src_ip, dst_port, src_port);
            bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
        }
        break;

    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE) {
            __u32 sport = skops->local_port;
            bpf_map_delete_elem(&port_dest, &sport); // free the orig-dest entry
            if ((is_agent_port(dst_port) && is_agent_peer(dst_ip)) ||
                (is_agent_port(src_port) && is_agent_peer(src_ip))) {
                send_event(EVENT_CLOSE, src_ip, dst_ip, src_port, dst_port);
            }
        }
        break;
    }

    return 0;
}

// =============================================================================
// cgroup/connect4 - Intercept and redirect outgoing connections
// =============================================================================

// cgroup/connect4: Intercept connect() calls and redirect to Grimlock
SEC("cgroup/connect4")
int grimlock_connect4(struct bpf_sock_addr *ctx) {
    struct config *cfg;
    __u32 dst_ip;
    __u16 dst_port;

    // Only handle IPv4 TCP
    if (ctx->family != AF_INET)
        return 1;  // Allow
    
    // Get configuration
    cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 1;  // Allow
    
    // Get destination
    dst_ip = ctx->user_ip4;
    dst_port = bpf_ntohs(ctx->user_port);
    
    // CRITICAL: Never redirect SSH, tunnel, or local traffic
    if (dst_port == SSH_PORT || dst_port == TUNNEL_PORT || dst_port == GRIMLOCK_LOCAL_PORT)
        return 1;  // Allow
    
    // Don't redirect localhost connections
    if (dst_ip == LOCALHOST_IP)
        return 1;  // Allow
    
    // Only redirect connections to known agent peers on an intercepted port
    if (!is_agent_port(dst_port) || !is_agent_peer(dst_ip))
        return 1;  // Allow
    
    // This is an A2A connection to a known peer. Record the original destination
    // keyed by the socket cookie so sock_ops can re-key it by source port for
    // multi-peer routing in user-space.
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct orig_dest d = { .ip = dst_ip, .port = dst_port, ._pad = 0 };
    bpf_map_update_elem(&cookie_dest, &cookie, &d, BPF_ANY);

    send_event(EVENT_CONNECT, 0, dst_ip, 0, dst_port);

    // Redirect to local Grimlock listener
    ctx->user_ip4 = LOCALHOST_IP;           // 127.0.0.1
    ctx->user_port = bpf_htons(GRIMLOCK_LOCAL_PORT);  // 15001

    return 1;  // Allow (with modified destination)
}
