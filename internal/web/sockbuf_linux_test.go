//go:build linux

package web

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
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

// checkTCPBufs confere o teto de tcpSocketBuf (ADR 0037): o kernel dobra o pedido, então entre 16 e 32 KiB.
func checkTCPBufs(t *testing.T, h *harness, port int) {
	t.Helper()
	var sc *net.TCPConn
	waitFor(t, 2*time.Second, func() bool { sc = serverConnOf(h, port); return sc != nil },
		func() string { return fmt.Sprint("no server conn for port ", port) })
	rcv, snd := sockBufs(t, sc)
	if rcv < tcpSocketBuf || rcv > 2*tcpSocketBuf || snd < tcpSocketBuf || snd > 2*tcpSocketBuf {
		t.Fatalf("SO_RCVBUF %d SO_SNDBUF %d", rcv, snd)
	}
}

// TestTCPSocketBuffers (task 215, ADR 0037): toda conexão TCP aceita pelo Serve (claro e TLS) tem SO_RCVBUF e
// SO_SNDBUF de 16 KiB no socket do servidor, fixados no accept. Só Linux: o macOS não reduz o SO_RCVBUF já
// autoajustado.
func TestTCPSocketBuffers(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	t.Run("clear", func(t *testing.T) {
		c := dial(t, h.addr80)
		checkTCPBufs(t, h, srcPort(c))
	})
	t.Run("tls", func(t *testing.T) {
		c := dialTLS(t, h.addr443, testSNI)
		checkTCPBufs(t, h, srcPort(c))
	})
}

// TestWSSocketBuffers (task 215, ADR 0037): a conexão HTTP/1 que vira WebSocket (claro e TLS) mantém o teto do
// accept (16 KiB pedidos, até 32 KiB lidos).
func TestWSSocketBuffers(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	for _, tc := range []struct{ name, addr, url string }{
		{"clear", h.addr80, "ws://" + testSNI + "/p/" + testProbe + "/ws"},
		{"tls", h.addr443, "wss://" + testSNI + "/p/" + testProbe + "/ws"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var port int
			wsDial(t, tc.addr, tc.url, nil, &port)
			checkTCPBufs(t, h, port)
		})
	}
}

// udpBufs lê SO_RCVBUF e SO_SNDBUF de um socket UDP por getsockopt.
func udpBufs(t *testing.T, c *net.UDPConn) (rcv, snd int) {
	t.Helper()
	rc, err := c.SyscallConn()
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

// sysctlInt lê um inteiro de /proc/sys.
func sysctlInt(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestUDPSocketBuffers (task 215, ADR 0037): o pedido de ~7 MiB do quic-go vira no máximo 1 MiB (2 MiB lidos,
// ou 2 × rmem_max/wmem_max se o sysctl for menor); um pedido menor que 1 MiB passa sem mudança.
func TestUDPSocketBuffers(t *testing.T) {
	rmax := sysctlInt(t, "/proc/sys/net/core/rmem_max")
	wmax := sysctlInt(t, "/proc/sys/net/core/wmem_max")
	for _, tc := range []struct {
		name     string
		req      int
		rcv, snd int
	}{
		{"capped", 7 << 20, 2 * min(h3UDPSocketBuf, rmax), 2 * min(h3UDPSocketBuf, wmax)},
		{"small", 64 << 10, 2 * min(64<<10, rmax), 2 * min(64<<10, wmax)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			u := &udpConn{c: pc}
			if err := u.SetReadBuffer(tc.req); err != nil {
				t.Fatal(err)
			}
			if err := u.SetWriteBuffer(tc.req); err != nil {
				t.Fatal(err)
			}
			rcv, snd := udpBufs(t, pc)
			if rcv != tc.rcv || snd != tc.snd || rcv > 2<<20 || snd > 2<<20 {
				t.Fatalf("SO_RCVBUF %d (want %d) SO_SNDBUF %d (want %d)", rcv, tc.rcv, snd, tc.snd)
			}
		})
	}
}
