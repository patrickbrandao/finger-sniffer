//go:build linux || darwin

package web

import (
	"net"
	"syscall"
	"unsafe"
)

// rxPending informa se a fila de recepção do socket TCP de c já tem bytes que a aplicação ainda não leu
// (ioctl FIONREAD, que no Linux é o SIOCINQ). Serve ao pipelined do HTTP/1 (spec 009 RF-05): bytes na fila
// no fim da resposta anterior são uma requisição que chegou antes de a resposta terminar. Em TLS os bytes
// são registros cifrados, então um close_notify ou KeyUpdate do cliente também conta. Sem socket TCP
// (testes em memória) ou com erro, devolve false.
func rxPending(c net.Conn) bool {
	tc := tcpConnOf(c)
	if tc == nil {
		return false
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return false
	}
	var n int32
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, fionread, uintptr(unsafe.Pointer(&n))) //nolint:gosec // ponteiro para int32 local, válido durante a chamada
	}); err != nil || errno != 0 {
		return false
	}
	return n > 0
}
