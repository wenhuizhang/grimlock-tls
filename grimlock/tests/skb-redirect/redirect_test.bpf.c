// SPDX-License-Identifier: GPL-2.0
// Minimal sk_skb redirect test program
//
// This tests whether we can redirect incoming data between sockets

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Sockmap - stores sockets by key
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} sock_map SEC(".maps");

// Redirect config: source port -> target port
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);   // source local port
    __type(value, __u32); // target local port (key in sock_map)
} redirect_config SEC(".maps");

// Stats
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_PARSER    0
#define STAT_VERDICT   1
#define STAT_REDIRECT  2
#define STAT_PASS      3
#define STAT_DROP      4
#define STAT_SOCKOPS   5

static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// Stream parser - returns message length
// For testing, we just pass through entire buffer
SEC("sk_skb/stream_parser")
int sk_skb_parser(struct __sk_buff *skb) {
    inc_stat(STAT_PARSER);
    bpf_printk("parser: len=%d", skb->len);
    return skb->len;
}

// Stream verdict - decides where data goes
SEC("sk_skb/stream_verdict")
int sk_skb_verdict(struct __sk_buff *skb) {
    inc_stat(STAT_VERDICT);
    
    __u32 local_port = skb->local_port;
    bpf_printk("verdict: local_port=%d len=%d", local_port, skb->len);
    
    // Look up if we should redirect this port's traffic
    __u32 *target_port = bpf_map_lookup_elem(&redirect_config, &local_port);
    if (!target_port) {
        inc_stat(STAT_PASS);
        bpf_printk("verdict: no redirect for port %d, PASS", local_port);
        return SK_PASS;
    }
    
    bpf_printk("verdict: redirecting port %d -> %d", local_port, *target_port);
    inc_stat(STAT_REDIRECT);
    
    // Redirect to the target socket
    return bpf_sk_redirect_hash(skb, &sock_map, target_port, BPF_F_INGRESS);
}

// Sock ops - adds sockets to sockmap when connections establish
SEC("sockops")
int sock_ops_handler(struct bpf_sock_ops *skops) {
    __u32 local_port;
    int ret;
    
    // Only handle established connections
    if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
        skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        return 1;
    }
    
    inc_stat(STAT_SOCKOPS);
    
    // Use local port as key
    local_port = skops->local_port;
    
    bpf_printk("sockops: adding socket port=%d", local_port);
    
    // Add to sockmap
    ret = bpf_sock_hash_update(skops, &sock_map, &local_port, BPF_ANY);
    if (ret) {
        bpf_printk("sockops: failed to add, err=%d", ret);
    } else {
        bpf_printk("sockops: added socket port=%d", local_port);
    }
    
    return 1;
}
