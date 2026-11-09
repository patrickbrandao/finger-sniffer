package raw

import (
	"crypto/tls"
	"errors"
	"net"
	"syscall"
	"time"
)

// closeWriter é a conexão que sabe fechar só o sentido de escrita (TCP manda FIN; TLS manda close_notify).
type closeWriter interface {
	CloseWrite() error
}

// closeWrite fecha o sentido de escrita, se a conexão suportar.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.New("raw: connection without CloseWrite")
}

// ackState é o que a pilha sabe dos bytes já escritos num socket TCP.
type ackState int

const (
	ackPending ackState = iota // ainda há bytes sem ACK do cliente
	ackDone                    // o cliente confirmou (ACK) tudo o que foi escrito
	ackReset                   // o cliente mandou RST: os bytes não foram entregues
)

// Espera pelo ACK do half-close: começa curta e dobra até o teto, por no máximo halfCloseWait.
const (
	halfClosePollMin = 1 * time.Millisecond
	halfClosePollMax = 20 * time.Millisecond
)

// halfClose é o teste de meio-fechamento (spec 006 RF-05): o cliente já mandou FIN; o servidor ainda manda
// HalfCloseMessage e então fecha. server_sent_after_client_fin só é true se a mensagem chegou ao cliente:
// a pilha recebeu o ACK dela (TCP_INFO no Linux) sem RST. Escrita aceita pelo kernel mas respondida com RST
// (cliente que chamou close() sem shutdown) fica false, com bytes = o que foi escrito. O FIN do servidor só
// sai depois da decisão, para o ACK do FIN não se confundir com o dos dados.
func (s *session) halfClose() {
	err := s.write([]byte(HalfCloseMessage))
	hc := &HalfClose{}
	if err == nil {
		hc.Bytes = len(HalfCloseMessage)
		hc.ServerSentAfterClientFIN = waitDelivered(s.conn, halfCloseWait)
	}
	s.info.HalfClose = hc
	_ = closeWrite(s.conn)
}

// waitDelivered espera até max pelo ACK (ou RST) dos bytes já escritos em c. Sem acesso ao socket (ex.:
// net.Pipe) não há como saber e vale a escrita aceita.
func waitDelivered(c net.Conn, maxWait time.Duration) bool {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return true
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return true
	}
	deadline := time.Now().Add(maxWait)
	for delay := halfClosePollMin; ; delay = min(delay*2, halfClosePollMax) {
		st := ackPending
		if rc.Control(func(fd uintptr) { st = probeAck(int(fd)) }) != nil {
			return false
		}
		switch st {
		case ackDone:
			return true
		case ackReset:
			return false
		}
		if time.Now().After(deadline) {
			return timeoutDelivered
		}
		time.Sleep(delay)
	}
}

// sockError lê (e limpa) o SO_ERROR: ECONNRESET/EPIPE depois de um RST do cliente.
func sockError(fd int) bool {
	v, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	return err != nil || v != 0
}
