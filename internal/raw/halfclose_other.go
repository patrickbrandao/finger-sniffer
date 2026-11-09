//go:build !linux

package raw

import "time"

// Fora do Linux (só desenvolvimento) não há TCP_INFO portável: o RST aparece no SO_ERROR e, sem ele em
// 300 ms, a mensagem conta como entregue.
const (
	halfCloseWait    = 300 * time.Millisecond
	timeoutDelivered = true
)

func probeAck(fd int) ackState {
	if sockError(fd) {
		return ackReset
	}
	return ackPending
}
