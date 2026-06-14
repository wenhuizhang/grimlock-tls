#!/usr/bin/env python3
"""Attach sk_skb programs to sockmap using BPF syscall"""
import os
import ctypes
import struct
import sys

# BPF syscall number on x86_64
__NR_bpf = 321

# BPF commands
BPF_PROG_ATTACH = 8

# Attach types
BPF_SK_SKB_STREAM_PARSER = 25
BPF_SK_SKB_STREAM_VERDICT = 26

libc = ctypes.CDLL(None, use_errno=True)

def bpf_prog_attach(prog_fd, target_fd, attach_type):
    """Attach BPF program using raw syscall"""
    # struct for BPF_PROG_ATTACH:
    # __u32 target_fd, attach_bpf_fd, attach_type, attach_flags
    # __u32 replace_bpf_fd (for BPF_F_REPLACE)
    attr = struct.pack("IIIII", target_fd, prog_fd, attach_type, 0, 0)
    # Pad to at least 64 bytes
    attr = attr + b"\x00" * (64 - len(attr))
    
    attr_buf = ctypes.create_string_buffer(attr)
    ret = libc.syscall(__NR_bpf, BPF_PROG_ATTACH, 
                       ctypes.byref(attr_buf), len(attr))
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return ret

def main():
    print("Attaching sk_skb programs to sockmap...")
    
    # Open pinned objects (BPF fs supports regular open())
    try:
        map_fd = os.open("/sys/fs/bpf/skb_test/sock_map", os.O_RDWR)
        print(f"  Sockmap FD: {map_fd}")
    except Exception as e:
        print(f"  Failed to open sockmap: {e}")
        return 1
    
    try:
        parser_fd = os.open("/sys/fs/bpf/skb_test/sk_skb_parser", os.O_RDWR)
        print(f"  Parser FD: {parser_fd}")
    except Exception as e:
        print(f"  Failed to open parser: {e}")
        os.close(map_fd)
        return 1
    
    try:
        verdict_fd = os.open("/sys/fs/bpf/skb_test/sk_skb_verdict", os.O_RDWR)
        print(f"  Verdict FD: {verdict_fd}")
    except Exception as e:
        print(f"  Failed to open verdict: {e}")
        os.close(map_fd)
        os.close(parser_fd)
        return 1
    
    # Attach stream_parser
    print("  Attaching stream_parser...")
    try:
        bpf_prog_attach(parser_fd, map_fd, BPF_SK_SKB_STREAM_PARSER)
        print("  ✓ stream_parser attached")
    except Exception as e:
        print(f"  ✗ stream_parser attach failed: {e}")
    
    # Attach stream_verdict
    print("  Attaching stream_verdict...")
    try:
        bpf_prog_attach(verdict_fd, map_fd, BPF_SK_SKB_STREAM_VERDICT)
        print("  ✓ stream_verdict attached")
    except Exception as e:
        print(f"  ✗ stream_verdict attach failed: {e}")
    
    os.close(map_fd)
    os.close(parser_fd)
    os.close(verdict_fd)
    
    print("  Done. Attachments persist in kernel.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
