//go:build linux

package web

import (
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

// serverConnOf acha o *net.TCPConn do servidor cujo par é a porta local port do cliente.
func serverConnOf(h *harness, port int) *net.TCPConn {
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	for c := range h.srv.conns {
		if a, ok := c.RemoteAddr().(*net.TCPAddr); ok && a.Port == port {
			tc, _ := c.(*net.TCPConn)
			return tc
		}
	}
	return nil
}

// sockBufs lê SO_RCVBUF e SO_SNDBUF por getsockopt.
func sockBufs(t *testing.T, tc *net.TCPConn) (rcv, snd int) {
	t.Helper()
	rc, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var e1, e2 error
	if err := rc.Control(func(fd uintptr) {
		rcv, e1 = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		snd, e2 = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	}); err != nil || e1 != nil || e2 != nil {
		t.Fatal(err, e1, e2)
	}
	return rcv, snd
}

// TestWSSocketBuffers (task 215, ADR 0036): a conexão HTTP/1 que vira WebSocket (claro e TLS) tem SO_RCVBUF e
// SO_SNDBUF de 64 KiB no socket do servidor (o kernel dobra: entre 64 e 128 KiB lidos). Só Linux: o macOS não
// reduz o SO_RCVBUF já autoajustado.
func TestWSSocketBuffers(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	for _, tc := range []struct{ name, addr, url string }{
		{"clear", h.addr80, "ws://" + testSNI + "/p/" + testProbe + "/ws"},
		{"tls", h.addr443, "wss://" + testSNI + "/p/" + testProbe + "/ws"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var port int
			wsDial(t, tc.addr, tc.url, nil, &port)
			var sc *net.TCPConn
			waitFor(t, 2*time.Second, func() bool { sc = serverConnOf(h, port); return sc != nil },
				func() string { return fmt.Sprint("no server conn for port ", port) })
			rcv, snd := sockBufs(t, sc)
			if rcv < wsSocketBuf || rcv > 2*wsSocketBuf || snd < wsSocketBuf || snd > 2*wsSocketBuf {
				t.Fatalf("SO_RCVBUF %d SO_SNDBUF %d", rcv, snd)
			}
		})
	}
}
