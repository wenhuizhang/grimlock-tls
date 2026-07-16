package main

import (
	"io"
	"net"
	"testing"
)

// TestSpliceable: only real TCP conn pairs qualify for the zero-copy fast path.
func TestSpliceable(t *testing.T) {
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	if spliceable(p1, p2) {
		t.Fatal("net.Pipe conns must not be reported spliceable")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c }()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2 := <-accepted
	defer c2.Close()
	if !spliceable(c1, c2) {
		t.Fatal("TCP conn pair must be reported spliceable")
	}
}

// TestRelayCopies: relay faithfully moves bytes (fast path or fallback).
func TestRelayCopies(t *testing.T) {
	srcR, srcW := net.Pipe()
	dstR, dstW := net.Pipe()
	go func() { io.WriteString(srcW, "hello-data-plane"); srcW.Close() }()
	go func() { relay(dstW, srcR); dstW.Close() }()
	out, err := io.ReadAll(dstR)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello-data-plane" {
		t.Fatalf("relay moved %q, want hello-data-plane", out)
	}
}
