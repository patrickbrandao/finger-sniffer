//go:build linux

package web

import (
	"context"
	"net"
	"syscall"
	"testing"
)

// TestListenerTFO: o listener TCP do web sai com TCP_FASTOPEN ligado e fila de 256 (ADR 0029), e o socket
// aceito sai com SO_KEEPALIVE desligado (o keepalive do servidor mudaria os pacotes analisados).
func TestListenerTFO(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	lc := h.srv.listenConfig()
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	rc, err := ln.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var qlen int
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		qlen, gerr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpFastOpen)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil || qlen != tfoQueue {
		t.Fatalf("TCP_FASTOPEN = %d (%v), want %d", qlen, gerr, tfoQueue)
	}

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	ac, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ac.Close() }()
	arc, err := ac.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ka int
	if err := arc.Control(func(fd uintptr) {
		ka, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil || ka != 0 {
		t.Fatalf("SO_KEEPALIVE = %d (%v), want 0", ka, gerr)
	}
}
