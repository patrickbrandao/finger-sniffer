//go:build linux

package raw

import (
	"context"
	"net"
	"syscall"
	"testing"
)

// TestListenerTFO: os listeners do raw saem com TCP_FASTOPEN ligado, fila de 256 (ADR 0029), e o keepalive
// do servidor continua desligado.
func TestListenerTFO(t *testing.T) {
	srv := New(Config{}, nil, quietLog(), nil)
	lc := srv.listenConfig()
	if lc.KeepAlive >= 0 {
		t.Fatalf("KeepAlive = %v, want < 0", lc.KeepAlive)
	}
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
