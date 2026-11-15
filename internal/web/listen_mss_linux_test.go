//go:build linux

package web

import (
	"net"
	"syscall"
)

// testMSS é o MSS da eth0 da vps602 (MTU 1500). No loopback (MTU 65536) o MSS seria ~65 KB, maior que o
// SO_RCVBUF de 16 KiB do accept (ADR 0037): a janela não comporta um segmento e 1 MiB leva ~6 s (persist
// timer), o que não acontece no caminho real. O harness fixa o MSS no listener (herdado pelo accept, limita
// os dois sentidos) para os testes verem a vazão da eth0.
const testMSS = 1448

// testListenConfig devolve a configuração dos listeners do harness.
func testListenConfig() net.ListenConfig {
	return net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, testMSS)
		}); err != nil {
			return err
		}
		return serr
	}}
}
