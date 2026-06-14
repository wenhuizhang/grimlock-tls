// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/*
 * Grimlock - SK_MSG eBPF Program
 * 
 * This program redirects socket messages through kTLS sockets
 * for transparent encryption/decryption.
 * 
 * Flow:
 * 1. Application sends data to a "normal" socket
 * 2. SK_MSG intercepts the send
 * 3. If connection should use kTLS, redirect to kTLS socket
 * 4. kTLS socket encrypts and sends to destination
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/*
 * sk_msg program - intercepts socket messages
 * 
 * Returns:
 * - SK_PASS: Pass to original destination
 * - SK_DROP: Drop the message
 * - bpf_msg_redirect_hash(): Redirect to another socket
 */
SEC("sk_msg")
int grimlock_sk_msg(struct sk_msg_md *msg) {
    struct grimlock_config *cfg;
    struct conn_key key = {};
    struct conn_state *state;
    __u32 zero = 0;
    int ret;
    
    /* Get config */
    cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg || !cfg->enabled)
        return SK_PASS;
    
    /* Build connection key from message metadata */
    key.src_ip = msg->local_ip4;
    key.dst_ip = msg->remote_ip4;
    key.src_port = msg->local_port;
    key.dst_port = bpf_ntohl(msg->remote_port) >> 16;
    key.protocol = IPPROTO_TCP;
    
    /* Look up connection state */
    state = bpf_map_lookup_elem(&conn_map, &key);
    if (!state)
        return SK_PASS;  /* Unknown connection - pass through */
    
    /* Check if this connection should use kTLS redirect */
    if (state->state != CONN_STATE_REDIRECT || !state->use_ktls)
        return SK_PASS;
    
    /*
     * Redirect to kTLS socket
     * 
     * The kTLS socket was set up by user-space after completing
     * the TLS handshake and calling setsockopt(SOL_TLS).
     * 
     * Traffic flow becomes:
     * App -> (plain) -> SK_MSG -> kTLS socket -> (encrypted) -> Network
     */
    ret = bpf_msg_redirect_hash(msg, &sock_hash, &key, BPF_F_INGRESS);
    if (ret != SK_PASS) {
        /* Redirect failed - fall back to pass-through */
        return SK_PASS;
    }
    
    /* Update statistics */
    __sync_fetch_and_add(&state->bytes_sent, msg->size);
    
    return SK_PASS;
}

/*
 * Alternative: Direct socket-to-socket redirect using sockmap
 * This version uses the simpler sockmap lookup by IP
 */
SEC("sk_msg")
int grimlock_sk_msg_simple(struct sk_msg_md *msg) {
    struct conn_state *state;
    struct conn_key key = {};
    __u32 dst_ip;
    int ret;
    
    /* Get destination IP */
    dst_ip = msg->remote_ip4;
    
    /* Check if there's a kTLS socket for this destination */
    /* Note: bpf_msg_redirect_map requires sockmap, not sockhash */
    ret = bpf_msg_redirect_map(msg, &ktls_sock_map, &dst_ip, BPF_F_INGRESS);
    
    return ret;
}

/*
 * SK_SKB program for stream parsing (optional)
 * 
 * This can be used for more sophisticated protocol parsing
 * before deciding on redirection.
 */
SEC("sk_skb/stream_parser")
int grimlock_stream_parser(struct __sk_buff *skb) {
    /* 
     * Parse the stream to find message boundaries
     * For TLS, we'd look at the TLS record header (5 bytes)
     * to determine message length
     */
    return skb->len;  /* Return full length for now */
}

SEC("sk_skb/stream_verdict")
int grimlock_stream_verdict(struct __sk_buff *skb) {
    struct conn_key key = {};
    struct conn_state *state;
    
    /* Build key from skb */
    key.src_ip = skb->local_ip4;
    key.dst_ip = skb->remote_ip4;
    key.src_port = skb->local_port;
    key.dst_port = bpf_ntohl(skb->remote_port) >> 16;
    key.protocol = IPPROTO_TCP;
    
    state = bpf_map_lookup_elem(&conn_map, &key);
    if (!state || state->state != CONN_STATE_REDIRECT)
        return SK_PASS;
    
    /* Redirect using sockhash */
    return bpf_sk_redirect_hash(skb, &sock_hash, &key, BPF_F_INGRESS);
}
