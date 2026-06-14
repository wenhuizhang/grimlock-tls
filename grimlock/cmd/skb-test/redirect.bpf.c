// SPDX-License-Identifier: GPL-2.0
// sk_skb redirect test - verifies kernel-to-kernel socket data redirect
//
// This program demonstrates:
// 1. sk_skb/stream_parser for message boundary detection
// 2. sk_skb/stream_verdict for redirect decision
// 3. sock_ops for adding sockets to sockmap
// 4. Bidirectional redirect between socket pairs

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Sockmap to store sockets by their local port
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 256);
    __type(key, __u32);    // local port
    __type(value, __u64);  // socket
} sock_map SEC(".maps");

// Redirect configuration: source_port -> target_port
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);    // source local port
    __type(value, __u32);  // target local port (key in sock_map)
} redirect_map SEC(".maps");

// Statistics for debugging
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_SOCKOPS_ESTABLISHED 0
#define STAT_SOCKOPS_CLOSE       1
#define STAT_PARSER_CALLS        2
#define STAT_VERDICT_CALLS       3
#define STAT_REDIRECT_OK         4
#define STAT_REDIRECT_FAIL       5
#define STAT_PASS                6

static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// Stream parser: return the length of data to process
// For our test, we pass through entire buffer as one message
SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb) {
    inc_stat(STAT_PARSER_CALLS);
    return skb->len;
}

// Stream verdict: decide where to send the data
SEC("sk_skb/stream_verdict")
int stream_verdict(struct __sk_buff *skb) {
    __u32 src_port = skb->local_port;
    __u32 *target_port;
    long ret;
    
    inc_stat(STAT_VERDICT_CALLS);
    
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

// Sock ops: track socket lifecycle and add to sockmap
SEC("sockops")
int sock_ops_handler(struct bpf_sock_ops *skops) {
    __u32 local_port;
    int ret;
    
    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        inc_stat(STAT_SOCKOPS_ESTABLISHED);
        
        // Use local port as key
        local_port = skops->local_port;
        
        // Add to sockmap
        ret = bpf_sock_hash_update(skops, &sock_map, &local_port, BPF_ANY);
        if (ret == 0) {
            bpf_printk("sockops: added port %d to sockmap", local_port);
        }
        break;
        
    case BPF_SOCK_OPS_STATE_CB:
        // Clean up on close
        if (skops->args[1] == BPF_TCP_CLOSE) {
            inc_stat(STAT_SOCKOPS_CLOSE);
            local_port = skops->local_port;
            bpf_map_delete_elem(&sock_map, &local_port);
            bpf_map_delete_elem(&redirect_map, &local_port);
        }
        break;
    }
    
    return 1;
}
