//go:build linux

package web

import (
	"context"
	"net"
	"syscall"
	"testing"
)

// TestListenerTFO: o listener TCP do web sai com TCP_FASTOPEN ligado e fila de 256 (ADR 0029).
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
}
