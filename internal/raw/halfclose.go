package raw

import (
	"errors"
	"net"
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

// halfClose é o teste de meio-fechamento (spec 006 RF-05): o cliente já mandou FIN; o servidor ainda manda
// HalfCloseMessage e então fecha. O registro diz se a escrita foi aceita pela pilha; se ela chegou ao
// cliente aparece no pcap e nos ACKs do cliente (spec 013).
func (s *session) halfClose() {
	err := s.write([]byte(HalfCloseMessage))
	hc := &HalfClose{ServerSentAfterClientFIN: err == nil}
	if err == nil {
		hc.Bytes = len(HalfCloseMessage)
	}
	s.info.HalfClose = hc
	_ = closeWrite(s.conn)
}
