//go:build linux

package raw

import "syscall"

// tcpFastOpen é a opção TCP_FASTOPEN do Linux (include/uapi/linux/tcp.h); o pacote syscall não a exporta.
const tcpFastOpen = 0x17

// enableTFO liga TCP_FASTOPEN no socket do listener, com fila de qlen pedidos pendentes (ADR 0029). Com o
// tcp_fastopen=3 da vps602, o SYN-ACK passa a trazer o cookie TFO quando o cliente pede.
func enableTFO(c syscall.RawConn, qlen int) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpFastOpen, qlen)
	}); err != nil {
		return err
	}
	return serr
}
