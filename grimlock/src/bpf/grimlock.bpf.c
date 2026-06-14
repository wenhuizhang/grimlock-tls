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

// Statistics indices
#define STAT_SOCKOPS_ESTABLISHED 0
#define STAT_SOCKOPS_CLOSE       1
#define STAT_PARSER_CALLS        2
#define STAT_VERDICT_CALLS       3
#define STAT_REDIRECT_OK         4
#define STAT_REDIRECT_FAIL       5
#define STAT_PASS                6
#define STAT_SOCKMAP_ADD         7

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
// Phase 4: Data Redirect Maps
// =============================================================================

// Sockmap: stores sockets by local port for sk_skb redirect
// Key: local port, Value: socket
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} sock_map SEC(".maps");

// Redirect configuration: source port -> target port
// When data arrives on source port socket, redirect to target port socket
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // source local port
    __type(value, __u32); // target local port (key in sock_map)
} redirect_map SEC(".maps");

// Statistics for debugging
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Helper: increment stat counter
static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// Helper: Check if IP is a known agent peer
static __always_inline bool is_agent_peer(__u32 ip) {
    __u8 *val = bpf_map_lookup_elem(&agent_peers, &ip);
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

// sock_ops program - intercepts socket operations
// This adds sockets to sockmap for sk_skb redirect
SEC("sockops")
int grimlock_sockops(struct bpf_sock_ops *skops) {
    struct config *cfg;
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;
    __u32 local_port;
    int ret;
    
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
        inc_stat(STAT_SOCKOPS_ESTABLISHED);
        
        // Add socket to sockmap for potential redirect
        local_port = skops->local_port;
        ret = bpf_sock_hash_update(skops, &sock_map, &local_port, BPF_ANY);
        if (ret == 0) {
            inc_stat(STAT_SOCKMAP_ADD);
        }
        
        // Outgoing connection established
        // Check if destination is a known agent peer AND port is 8080
        if (dst_port == AGENT_PORT && is_agent_peer(dst_ip)) {
            send_event(EVENT_CONNECT, src_ip, dst_ip, src_port, dst_port);
            // Enable state change callbacks for cleanup
            bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
        }
        break;
        
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        inc_stat(STAT_SOCKOPS_ESTABLISHED);
        
        // Add socket to sockmap for potential redirect
        local_port = skops->local_port;
        ret = bpf_sock_hash_update(skops, &sock_map, &local_port, BPF_ANY);
        if (ret == 0) {
            inc_stat(STAT_SOCKMAP_ADD);
        }
        
        // Incoming connection established
        // Check if source is a known agent peer AND our port is 8080
        if (src_port == AGENT_PORT && is_agent_peer(src_ip)) {
            send_event(EVENT_ACCEPT, dst_ip, src_ip, dst_port, src_port);
            bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
        }
        break;
        
    case BPF_SOCK_OPS_STATE_CB:
        // Socket state change - track closes
        if (skops->args[1] == BPF_TCP_CLOSE) {
            inc_stat(STAT_SOCKOPS_CLOSE);
            
            // Clean up sockmap entry
            local_port = skops->local_port;
            bpf_map_delete_elem(&sock_map, &local_port);
            bpf_map_delete_elem(&redirect_map, &local_port);
            
            // Only send close event if it was a tracked connection
            if ((dst_port == AGENT_PORT && is_agent_peer(dst_ip)) ||
                (src_port == AGENT_PORT && is_agent_peer(src_ip))) {
                send_event(EVENT_CLOSE, src_ip, dst_ip, src_port, dst_port);
            }
        }
        break;
    }
    
    return 0;
}

// =============================================================================
// sk_skb programs for data redirect
// =============================================================================

// Stream parser: determine message boundary
// For our use case, treat entire buffer as one message
SEC("sk_skb/stream_parser")
int grimlock_stream_parser(struct __sk_buff *skb) {
    inc_stat(STAT_PARSER_CALLS);
    return skb->len;
}

// Stream verdict: decide where to redirect data
SEC("sk_skb/stream_verdict")
int grimlock_stream_verdict(struct __sk_buff *skb) {
    __u32 src_port = skb->local_port;
    __u32 remote_port = skb->remote_port >> 16;  // Upper 16 bits
    __u32 *target_port;
    long ret;
    
    inc_stat(STAT_VERDICT_CALLS);
    
    // CRITICAL: Never redirect SSH traffic
    if (src_port == SSH_PORT || remote_port == SSH_PORT) {
        inc_stat(STAT_PASS);
        return SK_PASS;
    }
    
    // Check if this port has a redirect configured
    target_port = bpf_map_lookup_elem(&redirect_map, &src_port);
    if (!target_port) {
        inc_stat(STAT_PASS);
        return SK_PASS;
    }
    
    // Redirect to target socket
    ret = bpf_sk_redirect_hash(skb, &sock_map, target_port, BPF_F_INGRESS);
    if (ret == SK_PASS) {
        inc_stat(STAT_REDIRECT_OK);
    } else {
        inc_stat(STAT_REDIRECT_FAIL);
    }
    
    return ret;
}

// =============================================================================
// sk_msg program for sender-side redirect (outgoing data)
// =============================================================================

#define STAT_MSG_CALLS      8
#define STAT_MSG_REDIRECT   9

// Message redirect: intercept sendmsg/write and redirect to tunnel
// NOTE: This is kept for reference but we now use cgroup/connect4 + user-space forwarding
SEC("sk_msg")
int grimlock_msg_redirect(struct sk_msg_md *msg) {
    __u32 local_port = msg->local_port;
    __u32 remote_port = msg->remote_port >> 16;
    __u32 *target_port;
    long ret;
    
    inc_stat(STAT_MSG_CALLS);
    
    // CRITICAL: Never redirect SSH traffic
    if (local_port == SSH_PORT || remote_port == SSH_PORT) {
        return SK_PASS;
    }
    
    // Check if this socket has a redirect configured
    target_port = bpf_map_lookup_elem(&redirect_map, &local_port);
    if (!target_port) {
        return SK_PASS;
    }
    
    // Redirect outgoing message to target socket (tunnel)
    ret = bpf_msg_redirect_hash(msg, &sock_map, target_port, 0);
    if (ret == SK_PASS) {
        inc_stat(STAT_MSG_REDIRECT);
    }
    
    return ret;
}

// =============================================================================
// cgroup/connect4 - Intercept and redirect outgoing connections
// =============================================================================

#define STAT_CONNECT4_CALLS    10
#define STAT_CONNECT4_REDIRECT 11

// Store original destination for later retrieval by user-space
// Key: (local_ip, local_port) after redirect, Value: original (dst_ip, dst_port)
struct orig_dest {
    __u32 ip;
    __u16 port;
    __u16 padding;
};

struct orig_dest_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct orig_dest_key);
    __type(value, struct orig_dest);
} orig_dest_map SEC(".maps");

// cgroup/connect4: Intercept connect() calls and redirect to Grimlock
SEC("cgroup/connect4")
int grimlock_connect4(struct bpf_sock_addr *ctx) {
    struct config *cfg;
    __u32 dst_ip;
    __u16 dst_port;
    
    inc_stat(STAT_CONNECT4_CALLS);
    
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
    
    // Only redirect connections to known agent peers on agent port
    if (dst_port != AGENT_PORT || !is_agent_peer(dst_ip))
        return 1;  // Allow
    
    // This is an A2A connection to a known peer!
    // Store original destination before redirecting
    struct orig_dest_key key = {
        .src_ip = 0,  // Will be filled after connect, using dst_port as temp key
        .src_port = 0,
        .padding = 0,
    };
    // Use a simple key based on original destination for now
    // User-space will need to match this up
    key.src_ip = dst_ip;
    key.src_port = dst_port;
    
    struct orig_dest dest = {
        .ip = dst_ip,
        .port = dst_port,
        .padding = 0,
    };
    bpf_map_update_elem(&orig_dest_map, &key, &dest, BPF_ANY);
    
    // Send event to user-space
    send_event(EVENT_CONNECT, 0, dst_ip, 0, dst_port);
    
    // Redirect to local Grimlock listener
    ctx->user_ip4 = LOCALHOST_IP;           // 127.0.0.1
    ctx->user_port = bpf_htons(GRIMLOCK_LOCAL_PORT);  // 15001
    
    inc_stat(STAT_CONNECT4_REDIRECT);
    
    return 1;  // Allow (with modified destination)
}
