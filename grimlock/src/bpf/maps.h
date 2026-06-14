/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * Grimlock - Shared eBPF map definitions
 * 
 * These maps are shared between eBPF programs and user-space
 * for coordination and data exchange.
 */

#ifndef __GRIMLOCK_MAPS_H
#define __GRIMLOCK_MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Maximum number of agents we track */
#define MAX_AGENTS 1024

/* Maximum number of connections in sockmap */
#define MAX_CONNECTIONS 65535

/* Agent identity structure */
struct agent_identity {
    __u32 ip_addr;              /* IPv4 address (network byte order) */
    __u16 port;                 /* Port (network byte order) */
    __u8  verified;             /* 1 if identity verified via mTLS */
    __u8  padding;
    __u64 last_seen;            /* Timestamp of last activity */
    char  name[64];             /* Agent name from certificate CN */
};

/* Connection tracking key */
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;             /* IPPROTO_TCP = 6 */
    __u8  padding[3];
};

/* Connection state */
struct conn_state {
    __u8  state;                /* Connection state enum */
    __u8  use_ktls;             /* 1 if using kTLS for this connection */
    __u16 padding;
    __u32 ktls_socket_cookie;   /* Cookie of the kTLS socket to redirect to */
    __u64 bytes_sent;
    __u64 bytes_recv;
};

/* Connection states */
enum conn_state_enum {
    CONN_STATE_NEW = 0,
    CONN_STATE_HANDSHAKE,       /* TLS handshake in progress */
    CONN_STATE_ESTABLISHED,     /* mTLS established */
    CONN_STATE_REDIRECT,        /* Traffic being redirected via kTLS */
    CONN_STATE_CLOSED,
};

/*
 * Sockmap for socket redirection
 * Used by SK_MSG programs to redirect traffic to kTLS sockets
 */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct conn_key);
    __type(value, __u64);       /* Socket cookie */
} sock_hash SEC(".maps");

/*
 * Agent identity map
 * Maps IP address to verified agent identity
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_AGENTS);
    __type(key, __u32);         /* IPv4 address */
    __type(value, struct agent_identity);
} agent_map SEC(".maps");

/*
 * Connection tracking map
 * Tracks state of each connection for redirect decisions
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct conn_key);
    __type(value, struct conn_state);
} conn_map SEC(".maps");

/*
 * kTLS socket map
 * User-space populates this with established kTLS sockets
 * Key: destination agent IP
 * Value: socket FD (actually socket cookie in eBPF)
 */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, MAX_AGENTS);
    __type(key, __u32);         /* Destination IP */
    __type(value, __u64);       /* Socket cookie */
} ktls_sock_map SEC(".maps");

/*
 * Config map for user-space to control behavior
 */
struct grimlock_config {
    __u32 enabled;              /* Master enable/disable */
    __u32 local_ip;             /* This agent's IP */
    __u16 control_port;         /* Port for control plane */
    __u8  log_level;            /* 0=off, 1=error, 2=info, 3=debug */
    __u8  padding;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct grimlock_config);
} config_map SEC(".maps");

/*
 * Ring buffer for events to user-space
 * Used to notify control plane of new connections, etc.
 */
struct event {
    __u64 timestamp;
    __u8  type;
    __u8  padding[3];
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    char  data[64];
};

enum event_type {
    EVENT_NEW_CONNECTION = 1,
    EVENT_AGENT_DISCOVERED,
    EVENT_HANDSHAKE_NEEDED,
    EVENT_REDIRECT_ACTIVE,
    EVENT_ERROR,
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256KB ring buffer */
} events SEC(".maps");

#endif /* __GRIMLOCK_MAPS_H */
