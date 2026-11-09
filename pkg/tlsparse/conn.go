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
}

// NewConn envolve c.
func NewConn(c net.Conn) *Conn {
	return &Conn{Conn: c}
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
