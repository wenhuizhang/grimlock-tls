// SPDX-License-Identifier: GPL-2.0
// Test: sk_skb/stream_verdict redirect between sockets
//
// This test verifies that we can redirect incoming data from one socket
// to another socket using sk_skb. This is the foundation for our
// tunnel → agent redirect approach.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Sockmap to hold our sockets
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} sockmap SEC(".maps");

// Redirect map: source socket cookie → target socket key
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);    // source socket cookie
    __type(value, __u32);  // target socket key in sockmap
} redirect_map SEC(".maps");

// Stats for debugging
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_PARSER_CALLS  0
#define STAT_VERDICT_CALLS 1
#define STAT_REDIRECTS     2
#define STAT_PASSES        3

static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&stats, &idx);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

// Stream parser: just return the full length (no message parsing needed)
SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb) {
    inc_stat(STAT_PARSER_CALLS);
    return skb->len;
}

// Stream verdict: decide whether to redirect
SEC("sk_skb/stream_verdict")
int stream_verdict(struct __sk_buff *skb) {
    inc_stat(STAT_VERDICT_CALLS);
    
    // Get the socket cookie for this connection
    __u64 cookie = bpf_get_socket_cookie(skb);
    
    // Look up if we should redirect this socket's incoming data
    __u32 *target_key = bpf_map_lookup_elem(&redirect_map, &cookie);
    if (!target_key) {
        // No redirect configured, pass through normally
        inc_stat(STAT_PASSES);
        return SK_PASS;
    }
    
    // Redirect to the target socket
    inc_stat(STAT_REDIRECTS);
    
    // Use bpf_sk_redirect_hash to redirect to another socket in sockmap
    return bpf_sk_redirect_hash(skb, &sockmap, target_key, BPF_F_INGRESS);
}

// Sock ops: add sockets to sockmap when connections are established
SEC("sockops")
int sockops_handler(struct bpf_sock_ops *skops) {
    __u32 key;
    int ret;
    
    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        // Use local port as the key (simple for testing)
        key = skops->local_port;
        
        // Add socket to sockmap
        ret = bpf_sock_hash_update(skops, &sockmap, &key, BPF_ANY);
        if (ret) {
            bpf_printk("sockops: failed to add socket port=%d err=%d", key, ret);
        } else {
            bpf_printk("sockops: added socket port=%d cookie=%llu", 
                       key, bpf_get_socket_cookie(skops));
        }
        break;
    }
    
    return 1;
}
