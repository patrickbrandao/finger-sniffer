// Package detect identifica o protocolo de uma conexão pelos primeiros bytes do cliente, não pela porta
// (spec 005 RF-02, spec 006 RF-03/RF-04).
//
// Regras, na ordem:
//   - 0x16 0x03                → TLS
//   - "PRI * HTTP/2.0"         → HTTP/2 em claro por prior knowledge (h2c)
//   - "PROBE "                 → linha de probe das portas cruas
//   - método HTTP conhecido + espaço → HTTP/1.x
//   - qualquer outra coisa     → desconhecido (TCP cru)
//
// Os bytes lidos durante a detecção são devolvidos pela Conn retornada, de modo que quem vem depois
// (TLS, parser HTTP/1, raw) enxerga o fluxo completo, byte a byte.
package detect

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"time"
)

// Protocol é o protocolo detectado.
type Protocol int

// Valores possíveis de Protocol.
const (
	// Unknown: bytes que não casam com nenhuma regra (TCP cru).
	Unknown Protocol = iota
	// TLS: registro de handshake TLS (0x16 0x03).
	TLS
	// H2CPriorKnowledge: prefácio do HTTP/2 em claro.
	H2CPriorKnowledge
	// HTTP1: linha de requisição HTTP/1.x.
	HTTP1
	// ProbeLine: primeira linha "PROBE <id>" das portas cruas.
	ProbeLine
	// Silent: o cliente não mandou nada dentro do prazo (espera o servidor falar).
	Silent
	// Closed: o cliente fechou sem mandar nada.
	Closed
)

// String devolve o nome usado nos registros e logs.
func (p Protocol) String() string {
	switch p {
	case TLS:
		return "tls"
	case H2CPriorKnowledge:
		return "h2c"
	case HTTP1:
		return "http1"
	case ProbeLine:
		return "probe"
	case Silent:
		return "silent"
	case Closed:
		return "closed"
	default:
		return "unknown"
	}
}

// Valores padrão da detecção (spec 005: até 24 bytes ou 2 s).
const (
	DefaultMaxBytes = 24
	DefaultTimeout  = 2 * time.Second
)

// h2Preface é o início do prefácio do cliente HTTP/2 (RFC 9113 §3.4) que basta para decidir.
var h2Preface = []byte("PRI * HTTP/2.0")

var probePrefix = []byte("PROBE ")

// httpMethods são os métodos do registro IANA de métodos HTTP (RFC 9110 e extensões WebDAV etc.).
// Só método conhecido conta, para que protocolos de texto como SMTP ("EHLO x") não virem HTTP.
var httpMethods = [][]byte{
	[]byte("GET"), []byte("HEAD"), []byte("POST"), []byte("PUT"), []byte("DELETE"), []byte("CONNECT"),
	[]byte("OPTIONS"), []byte("TRACE"), []byte("PATCH"), []byte("QUERY"),
	[]byte("ACL"), []byte("BASELINE-CONTROL"), []byte("BIND"), []byte("CHECKIN"), []byte("CHECKOUT"),
	[]byte("COPY"), []byte("LABEL"), []byte("LINK"), []byte("LOCK"), []byte("MERGE"), []byte("MKACTIVITY"),
	[]byte("MKCALENDAR"), []byte("MKCOL"), []byte("MKREDIRECTREF"), []byte("MKWORKSPACE"), []byte("MOVE"),
	[]byte("ORDERPATCH"), []byte("PROPFIND"), []byte("PROPPATCH"), []byte("REBIND"), []byte("REPORT"),
	[]byte("SEARCH"), []byte("UNBIND"), []byte("UNCHECKOUT"), []byte("UNLINK"), []byte("UNLOCK"),
	[]byte("UPDATE"), []byte("UPDATEREDIRECTREF"), []byte("VERSION-CONTROL"),
}

// Classify decide o protocolo a partir dos bytes já recebidos. Quando os bytes ainda podem virar mais
// de uma coisa, devolve (Unknown, true): é preciso ler mais. Uma decisão definitiva nunca muda com mais
// bytes (propriedade testada por fuzz).
func Classify(b []byte) (p Protocol, needMore bool) {
	if len(b) == 0 {
		return Unknown, true
	}

	// TLS: tipo de registro handshake (22) e versão maior 3.
	if b[0] == 0x16 {
		if len(b) < 2 {
			return Unknown, true
		}
		if b[1] == 0x03 {
			return TLS, false
		}
	}

	candidate := false
	for _, rule := range []struct {
		prefix []byte
		proto  Protocol
	}{
		{h2Preface, H2CPriorKnowledge},
		{probePrefix, ProbeLine},
	} {
		switch {
		case bytes.HasPrefix(b, rule.prefix):
			return rule.proto, false
		case bytes.HasPrefix(rule.prefix, b):
			candidate = true
		}
	}

	for _, m := range httpMethods {
		switch {
		case len(b) > len(m) && bytes.HasPrefix(b, m) && b[len(m)] == ' ':
			return HTTP1, false
		case len(b) <= len(m) && bytes.HasPrefix(m, b):
			candidate = true
		}
	}

	if candidate {
		return Unknown, true
	}
	return Unknown, false
}

// Result descreve a detecção feita numa conexão.
type Result struct {
	Protocol Protocol
	// Peeked são os bytes lidos durante a detecção (já devolvidos pela Conn).
	Peeked []byte
	// Elapsed é o tempo entre o início da detecção e a decisão.
	Elapsed time.Duration
}

// Conn é uma net.Conn que entrega primeiro os bytes lidos na detecção.
type Conn struct {
	net.Conn
	pending []byte
}

// Read entrega os bytes pendentes da detecção antes de ler do socket.
func (c *Conn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// Detect lê do cliente até decidir o protocolo, até maxBytes bytes ou até o prazo timeout.
// O prazo de leitura da conexão é restaurado para "sem prazo" ao final.
// Um erro só é devolvido em falhas de leitura que não sejam prazo nem fechamento.
func Detect(conn net.Conn, maxBytes int, timeout time.Duration) (*Conn, Result, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	start := time.Now()
	buf := make([]byte, 0, maxBytes)
	if err := conn.SetReadDeadline(start.Add(timeout)); err != nil {
		return nil, Result{}, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var readErr error
	for len(buf) < maxBytes {
		n, err := conn.Read(buf[len(buf):maxBytes])
		buf = buf[:len(buf)+n]
		if p, more := Classify(buf); len(buf) > 0 && !more {
			return wrap(conn, buf), Result{Protocol: p, Peeked: buf, Elapsed: time.Since(start)}, nil
		}
		if err != nil {
			readErr = err
			break
		}
	}

	res := Result{Peeked: buf, Elapsed: time.Since(start)}
	switch {
	case len(buf) > 0:
		// Esgotou bytes, prazo ou o cliente fechou com algo ambíguo: decide com o que há.
		res.Protocol, _ = Classify(buf)
	case readErr == nil || isTimeout(readErr):
		res.Protocol = Silent
	case errors.Is(readErr, io.EOF):
		res.Protocol = Closed
	default:
		return nil, res, readErr
	}
	return wrap(conn, buf), res, nil
}

func wrap(conn net.Conn, buf []byte) *Conn {
	pending := make([]byte, len(buf))
	copy(pending, buf)
	return &Conn{Conn: conn, pending: pending}
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
