package raw

import (
	"syscall"
	"time"
	"unsafe"
)

// No Linux a fila de envio diz exatamente quando os bytes foram confirmados; sem ACK nem RST em 2 s, a
// mensagem não chegou.
const (
	halfCloseWait    = 2 * time.Second
	timeoutDelivered = false
)

// probeAck consulta SIOCOUTQ (bytes na fila de envio ainda sem ACK, enviados ou não). O RST esvazia a fila e
// marca o SO_ERROR; por isso o SO_ERROR é lido depois da fila: um RST que chegue entre as duas leituras ainda
// é visto.
func probeAck(fd int) ackState {
	var outq int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCOUTQ,
		uintptr(unsafe.Pointer(&outq))) //nolint:gosec // ioctl(SIOCOUTQ) sem wrapper na stdlib
	if errno != 0 || sockError(fd) {
		return ackReset
	}
	if outq > 0 {
		return ackPending
	}
	return ackDone
}
