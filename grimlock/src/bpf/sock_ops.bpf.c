// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/*
 * Grimlock - Socket Operations eBPF Program
 * 
 * This program intercepts socket lifecycle events to:
 * 1. Track new connections to/from known agents
 * 2. Add sockets to sockmap for later redirection
 * 3. Notify user-space control plane of events
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "maps.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Helper to check if destination is a known agent */
static __always_inline bool is_known_agent(__u32 ip) {
    struct agent_identity *agent = bpf_map_lookup_elem(&agent_map, &ip);
    return agent != NULL && agent->verified;
}

/* Helper to get config */
static __always_inline struct grimlock_config *get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

/* Send event to user-space ring buffer */
static __always_inline void send_event(__u8 type, __u32 src_ip, __u32 dst_ip,
                                       __u16 src_port, __u16 dst_port) {
    struct event *evt;
    
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return;
    
    evt->timestamp = bpf_ktime_get_ns();
    evt->type = type;
    evt->src_ip = src_ip;
    evt->dst_ip = dst_ip;
    evt->src_port = src_port;
    evt->dst_port = dst_port;
    
    bpf_ringbuf_submit(evt, 0);
}

/*
 * sock_ops program - hooks into socket operations
 * 
 * Key callbacks:
 * - BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: Outgoing connection established
 * - BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: Incoming connection established
 * - BPF_SOCK_OPS_STATE_CB: Socket state changes
 */
SEC("sockops")
int grimlock_sock_ops(struct bpf_sock_ops *skops) {
    struct grimlock_config *cfg;
    struct conn_key key = {};
    struct conn_state state = {};
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;
    int ret;
    
    /* Get config and check if enabled */
    cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 0;
    
    /* Only handle IPv4 TCP for now */
    if (skops->family != AF_INET)
        return 0;
    
    /* Extract connection details */
    src_ip = skops->local_ip4;
    dst_ip = skops->remote_ip4;
    src_port = skops->local_port;
    dst_port = bpf_ntohl(skops->remote_port) >> 16;
    
    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        /*
         * Outgoing connection established
         * Check if destination is a known Grimlock agent
         */
        if (!is_known_agent(dst_ip)) {
            /* Not a known agent - check if we should discover it */
            send_event(EVENT_AGENT_DISCOVERED, src_ip, dst_ip, 
                      src_port, dst_port);
            return 0;
        }
        
        /* Known agent - set up for potential redirect */
        key.src_ip = src_ip;
        key.dst_ip = dst_ip;
        key.src_port = src_port;
        key.dst_port = dst_port;
        key.protocol = IPPROTO_TCP;
        
        /* Add to sockmap for SK_MSG redirection */
        ret = bpf_sock_hash_update(skops, &sock_hash, &key, BPF_ANY);
        if (ret) {
            send_event(EVENT_ERROR, src_ip, dst_ip, src_port, dst_port);
            return 0;
        }
        
        /* Initialize connection state */
        state.state = CONN_STATE_NEW;
        state.use_ktls = 0;  /* Will be set by user-space after handshake */
        bpf_map_update_elem(&conn_map, &key, &state, BPF_ANY);
        
        /* Notify user-space - handshake may be needed */
        send_event(EVENT_NEW_CONNECTION, src_ip, dst_ip, src_port, dst_port);
        
        /* Enable socket callbacks for state tracking */
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
        break;
        
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        /*
         * Incoming connection established
         * Check if source is a known Grimlock agent
         */
        if (!is_known_agent(src_ip)) {
            send_event(EVENT_AGENT_DISCOVERED, dst_ip, src_ip,
                      dst_port, src_port);
            return 0;
        }
        
        /* Known agent connecting to us */
        key.src_ip = dst_ip;  /* Swap - we're the "source" now */
        key.dst_ip = src_ip;
        key.src_port = dst_port;
        key.dst_port = src_port;
        key.protocol = IPPROTO_TCP;
        
        /* Add to sockmap */
        ret = bpf_sock_hash_update(skops, &sock_hash, &key, BPF_ANY);
        if (ret)
            return 0;
        
        state.state = CONN_STATE_NEW;
        bpf_map_update_elem(&conn_map, &key, &state, BPF_ANY);
        
        send_event(EVENT_NEW_CONNECTION, dst_ip, src_ip, dst_port, src_port);
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
        break;
        
    case BPF_SOCK_OPS_STATE_CB:
        /*
         * Socket state change - track for cleanup
         */
        if (skops->args[1] == BPF_TCP_CLOSE ||
            skops->args[1] == BPF_TCP_CLOSE_WAIT) {
            /* Connection closing - clean up maps */
            key.src_ip = src_ip;
            key.dst_ip = dst_ip;
            key.src_port = src_port;
            key.dst_port = dst_port;
            key.protocol = IPPROTO_TCP;
            
            bpf_map_delete_elem(&sock_hash, &key);
            bpf_map_delete_elem(&conn_map, &key);
        }
        break;
    }
    
    return 0;
}

/*
 * Optional: cgroup/connect4 program to intercept connect() calls
 * This allows us to potentially redirect connections before they're established
 */
SEC("cgroup/connect4")
int grimlock_connect4(struct bpf_sock_addr *ctx) {
    struct grimlock_config *cfg;
    __u32 dst_ip;
    
    cfg = get_config();
    if (!cfg || !cfg->enabled)
        return 1;  /* Allow connection */
    
    dst_ip = ctx->user_ip4;
    
    /* Check if connecting to a known agent */
    if (is_known_agent(dst_ip)) {
        /*
         * TODO: We could redirect the connection here to go through
         * our kTLS proxy socket instead. For POC, we just track it.
         */
        send_event(EVENT_HANDSHAKE_NEEDED, ctx->user_ip4, dst_ip, 
                  ctx->user_port, 0);
    }
    
    return 1;  /* Allow connection to proceed */
}
