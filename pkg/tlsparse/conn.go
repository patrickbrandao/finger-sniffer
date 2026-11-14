package tlsparse

import (
	"errors"
	"net"
	"sync"
)

// maxCapture limita os bytes guardados pela Conn: o ClientHello máximo mais cabeçalhos de registros
// pequenos (um cliente pode mandar a mensagem em registros minúsculos).
const maxCapture = 4 * MaxClientHelloLen

// Conn envolve um net.Conn e guarda, na leitura, os bytes do(s) registro(s) TLS que carregam o
// ClientHello, antes de o crypto/tls (ou o raw) consumi-los. A técnica é a do fingerproxy: Read devolve
// exatamente o que o net.Conn de baixo devolveu, sem reter, reordenar nem alterar bytes; a cópia é feita
// por fora e para assim que o ClientHello termina.
//
// Os métodos de consulta podem ser chamados de outra goroutine (por exemplo, no GetConfigForClient).
type Conn struct {
	net.Conn

	mu   sync.Mutex
	buf  []byte
	done bool
	err  error

	// Estado incremental da captura (task 166): Reassemble só roda quando o resultado é definitivo, e cada
	// Read examina só os registros novos. off é o fim dos registros completos já vistos, nrec quantos são,
	// have soma os bytes de handshake deles, hdr/hdrLen guardam o cabeçalho do handshake (que pode vir
	// espalhado em registros) e need é o tamanho total da mensagem quando o cabeçalho chegou (-1 antes).
	off    int
	nrec   int
	have   int
	hdr    [handshakeHeaderLen]byte
	hdrLen int
	need   int
}

// NewConn envolve c.
func NewConn(c net.Conn) *Conn {
	return &Conn{Conn: c, need: -1}
}

// Read lê do net.Conn de baixo e guarda a cópia enquanto o ClientHello não termina.
func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.capture(b[:n])
	}
	return n, err
}

func (c *Conn) capture(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	c.buf = append(c.buf, p...)
	if !c.advance() {
		// Reassemble daria ErrIncomplete: só o teto encerra a captura
		if len(c.buf) >= maxCapture {
			c.buf = c.buf[:maxCapture:maxCapture]
			c.done = true
			c.err = ErrTooLarge
		}
		return
	}
	r, err := Reassemble(c.buf)
	switch {
	case err == nil:
		// guarda só os registros do ClientHello; o que vier depois no mesmo Read não é dele
		c.buf = c.buf[:r.Consumed:r.Consumed]
		c.done = true
	case errors.Is(err, ErrIncomplete):
		if len(c.buf) >= maxCapture {
			c.buf = c.buf[:maxCapture:maxCapture]
			c.done = true
			c.err = ErrTooLarge
		}
	default:
		c.done = true
		c.err = err
	}
}

// advance percorre só os registros ainda não vistos e informa se Reassemble(c.buf) já tem resultado
// definitivo (ClientHello completo ou erro definitivo); falso equivale a ErrIncomplete. Custa os bytes
// novos, não o buffer inteiro. As checagens seguem a ordem de Reassemble, para que o erro definitivo seja
// detectado no mesmo byte.
func (c *Conn) advance() bool {
	for {
		if c.need >= 0 && c.have >= c.need {
			return true
		}
		rest := c.buf[c.off:]
		if len(rest) < RecordHeaderLen {
			return false
		}
		if rest[0] != RecordTypeHandshake || (c.nrec == 0 && rest[1] != 0x03) {
			return true
		}
		n := int(rest[3])<<8 | int(rest[4])
		body := rest[RecordHeaderLen:]
		cut := len(body) < n
		if !cut {
			body = body[:n]
		}
		// cabeçalho do handshake: vale também o pedaço que já chegou de um registro cortado
		hdr, hdrLen, need := c.hdr, c.hdrLen, c.need
		hdrLen += copy(hdr[hdrLen:], body)
		if need < 0 && hdrLen == handshakeHeaderLen {
			l := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
			if hdr[0] != HandshakeTypeClientHello || l > MaxClientHelloLen {
				return true
			}
			need = handshakeHeaderLen + l
		}
		if cut {
			return false
		}
		c.hdr, c.hdrLen, c.need = hdr, hdrLen, need
		c.have += n
		c.off += RecordHeaderLen + n
		c.nrec++
	}
}

// Complete informa se a captura terminou: ClientHello inteiro ou erro definitivo.
func (c *Conn) Complete() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.done
}

// Records devolve os bytes capturados (os registros do ClientHello, cabeçalhos incluídos) e o erro da
// remontagem: nil quando completo, ErrIncomplete se ainda faltam bytes, ou o erro definitivo. A fatia não
// muda depois que a captura termina.
func (c *Conn) Records() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.done {
		return append([]byte(nil), c.buf...), ErrIncomplete
	}
	return c.buf, c.err
}

// ClientHello analisa os bytes capturados (ver Parse).
func (c *Conn) ClientHello() (*ClientHello, error) {
	b, err := c.Records()
	ch, perr := Parse(b)
	if err != nil {
		return ch, err
	}
	return ch, perr
}
