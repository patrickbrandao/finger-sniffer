package tlsparse

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// MaxCapturedRecords limita os registros crus guardados pela Conn (ADR 0070 item 7): acima disso a cópia crua
// para e RecordsTruncated fica verdadeiro, mas a mensagem continua sendo remontada (até MaxClientHelloLen),
// então os fingerprints saem com qualquer fragmentação.
const MaxCapturedRecords = 16 << 10

// ErrNoBudget indica que a reserva da captura foi recusada (Reserve devolveu falso); Read devolve este erro e o
// handshake termina antes de começar.
var ErrNoBudget = errors.New("tlsparse: client hello capture over budget")

// Conn envolve um net.Conn e guarda, na leitura, os bytes do(s) registro(s) TLS que carregam o
// ClientHello, antes de o crypto/tls (ou o raw) consumi-los. A técnica é a do fingerproxy: Read devolve
// exatamente o que o net.Conn de baixo devolveu, sem reter, reordenar nem alterar bytes; a cópia é feita
// por fora e para assim que o ClientHello termina.
//
// A captura é incremental (task 323): a mensagem de handshake é remontada à medida que os registros chegam
// (no máximo MaxClientHelloLen mais o cabeçalho, alocada no tamanho exato), e os registros crus são
// guardados só até MaxCapturedRecords. A memória por conexão fica em ~80 KiB no pior caso, com qualquer
// fragmentação, e Release a solta depois do uso.
//
// Os métodos de consulta podem ser chamados de outra goroutine (por exemplo, no GetConfigForClient).
type Conn struct {
	net.Conn

	// Reserve, quando definido, é chamado antes de cada alocação da captura com a capacidade nova; falso
	// recusa (ErrNoBudget). Unreserve devolve o reservado (fatias trocadas e Release). Ambos definidos antes
	// do primeiro Read.
	Reserve   func(n int) bool
	Unreserve func(n int)

	mu       sync.Mutex
	raw      []byte // registros crus até MaxCapturedRecords
	rawTrunc bool
	msg      []byte // mensagem de handshake remontada (cabeçalho de 4 bytes incluso)
	hdr      [handshakeHeaderLen]byte
	hdrLen   int
	need     int // tamanho total da mensagem (-1 antes do cabeçalho)
	rhdr     [RecordHeaderLen]byte
	rhdrLen  int
	recLeft  int // bytes do corpo do registro atual ainda por vir
	inRec    bool
	nrec     int
	recVer   uint16
	reserved int
	done     bool
	err      error
}

// NewConn envolve c.
func NewConn(c net.Conn) *Conn {
	return &Conn{Conn: c, need: -1}
}

// Read lê do net.Conn de baixo e guarda a cópia enquanto o ClientHello não termina. Sem orçamento para a
// captura devolve ErrNoBudget.
func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.capture(b[:n]) {
		return 0, ErrNoBudget
	}
	return n, err
}

// reserve reserva n bytes; falso quando o orçamento recusa.
func (c *Conn) reserve(n int) bool {
	if c.Reserve == nil || n <= 0 {
		return true
	}
	if !c.Reserve(n) {
		return false
	}
	c.reserved += n
	return true
}

// unreserve devolve n bytes reservados.
func (c *Conn) unreserve(n int) {
	if n <= 0 || c.reserved == 0 {
		return
	}
	n = min(n, c.reserved)
	c.reserved -= n
	if c.Unreserve != nil {
		c.Unreserve(n)
	}
}

// capture processa p; devolve verdadeiro quando a reserva foi recusada.
func (c *Conn) capture(p []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return false
	}
	for len(p) > 0 && !c.done {
		if !c.inRec {
			k := copy(c.rhdr[c.rhdrLen:], p)
			c.rhdrLen += k
			if !c.keepRaw(p[:k]) {
				return c.deny()
			}
			p = p[k:]
			if c.rhdrLen == RecordHeaderLen {
				c.startRecord()
			}
			continue
		}
		k := min(c.recLeft, len(p))
		if !c.keepRaw(p[:k]) || !c.body(p[:k]) {
			return c.deny()
		}
		c.recLeft -= k
		p = p[k:]
		if !c.done && c.recLeft == 0 {
			c.endRecord()
		}
	}
	return false
}

// deny encerra a captura por falta de orçamento e solta o que havia.
func (c *Conn) deny() bool {
	c.done = true
	c.err = ErrNoBudget
	c.raw, c.msg = nil, nil
	c.unreserve(c.reserved)
	return true
}

// startRecord confere o cabeçalho do registro recém-completo, na ordem de Reassemble.
func (c *Conn) startRecord() {
	h := c.rhdr
	if c.nrec == 0 && (h[0] != RecordTypeHandshake || h[1] != 0x03) {
		c.done, c.err = true, ErrNotHandshake
		return
	}
	if h[0] != RecordTypeHandshake {
		c.done = true
		c.err = fmt.Errorf("tlsparse: record %d has type 0x%02x before the end of the client hello", c.nrec+1, h[0])
		return
	}
	if c.nrec == 0 {
		c.recVer = uint16(h[1])<<8 | uint16(h[2])
	}
	c.nrec++
	c.recLeft = int(h[3])<<8 | int(h[4])
	c.inRec = true
	if c.recLeft == 0 {
		c.endRecord()
	}
}

// endRecord fecha o registro atual; a mensagem só conta como completa no fim de um registro (Reassemble).
func (c *Conn) endRecord() {
	c.inRec = false
	c.rhdrLen = 0
	if c.need >= 0 && len(c.msg) >= c.need {
		c.done = true
	}
}

// body acrescenta bytes de handshake à mensagem; falso quando a reserva foi recusada.
func (c *Conn) body(p []byte) bool {
	if c.need < 0 {
		k := copy(c.hdr[c.hdrLen:], p)
		c.hdrLen += k
		p = p[k:]
		if c.hdrLen < handshakeHeaderLen {
			return true
		}
		h := c.hdr
		c.msg = h[:]
		if h[0] != HandshakeTypeClientHello {
			c.done, c.err = true, ErrNotClientHello
			return true
		}
		l := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
		if l > MaxClientHelloLen {
			c.done, c.err = true, ErrTooLarge
			return true
		}
		c.need = handshakeHeaderLen + l
		if !c.reserve(c.need) {
			return false
		}
		c.msg = make([]byte, handshakeHeaderLen, c.need)
		copy(c.msg, h[:])
	}
	// bytes do registro depois do fim da mensagem não são dela (como em Reassemble)
	k := min(len(p), c.need-len(c.msg))
	c.msg = append(c.msg, p[:k]...)
	return true
}

// keepRaw guarda bytes crus até MaxCapturedRecords, reservando a capacidade antes de crescer.
func (c *Conn) keepRaw(p []byte) bool {
	if c.rawTrunc || len(p) == 0 {
		return true
	}
	if room := MaxCapturedRecords - len(c.raw); len(p) > room {
		p = p[:room]
		c.rawTrunc = true
	}
	if len(c.raw)+len(p) > cap(c.raw) {
		nc := min(max(2*cap(c.raw), len(c.raw)+len(p), 512), MaxCapturedRecords)
		if !c.reserve(nc) {
			return false
		}
		nb := make([]byte, len(c.raw), nc)
		copy(nb, c.raw)
		// a fatia antiga vira lixo: a reserva dela volta
		c.unreserve(cap(c.raw))
		c.raw = nb
	}
	c.raw = append(c.raw, p...)
	return true
}

// Complete informa se a captura terminou: ClientHello inteiro ou erro definitivo.
func (c *Conn) Complete() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.done
}

// RawRecords devolve os bytes crus capturados (os registros do ClientHello, cabeçalhos incluídos, até
// MaxCapturedRecords) e o erro da captura: nil quando completo, ErrIncomplete se ainda faltam bytes, ou o
// erro definitivo. A fatia não muda depois que a captura termina.
func (c *Conn) RawRecords() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.done {
		return append([]byte(nil), c.raw...), ErrIncomplete
	}
	return c.raw, c.err
}

// Records é como RawRecords, mas, quando a cópia crua foi cortada e a mensagem está completa, devolve
// registros sintéticos de até 16 KiB com a mensagem remontada (alocação temporária, não retida): Parse sobre
// eles dá o mesmo ClientHello, com a contagem de registros sintética. Compatibilidade para quem ainda chama
// Parse(Records()) (o raw, até adotar ClientHello e RecordsTruncated).
func (c *Conn) Records() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.done {
		return append([]byte(nil), c.raw...), ErrIncomplete
	}
	if !c.rawTrunc || c.err != nil || c.need < 0 || len(c.msg) < c.need {
		return c.raw, c.err
	}
	out := make([]byte, 0, len(c.msg)+RecordHeaderLen*(len(c.msg)/16384+1))
	for m := c.msg; len(m) > 0; {
		k := min(16384, len(m))
		out = append(out, RecordTypeHandshake, byte(c.recVer>>8), byte(c.recVer), byte(k>>8), byte(k)) //nolint:gosec // bytes da versão e do tamanho (≤ 16384)
		out = append(out, m[:k]...)
		m = m[k:]
	}
	return out, nil
}

// RecordsTruncated informa se a cópia crua parou em MaxCapturedRecords (client_hello_truncated).
func (c *Conn) RecordsTruncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rawTrunc
}

// ClientHello analisa a mensagem remontada; nunca devolve nil (ver Parse). Com ErrIncomplete, a parte
// recebida é analisada mesmo assim.
func (c *Conn) ClientHello() (*ClientHello, error) {
	c.mu.Lock()
	msg, err := c.msg, c.err
	if msg == nil && c.hdrLen > 0 {
		// cabeçalho do handshake ainda incompleto
		msg = append([]byte(nil), c.hdr[:c.hdrLen]...)
	}
	if !c.done {
		msg = append([]byte(nil), msg...)
		err = ErrIncomplete
	}
	ver, nrec := c.recVer, c.nrec
	c.mu.Unlock()
	ch, perr := ParseMessage(msg)
	ch.RecordVersion = ver
	ch.Records = nrec
	if err != nil {
		return ch, err
	}
	return ch, perr
}

// Release solta a captura e devolve a reserva (ADR 0070 item 7); a captura não recomeça. Idempotente.
func (c *Conn) Release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.done {
		c.done, c.err = true, ErrIncomplete
	}
	c.raw, c.msg = nil, nil
	c.unreserve(c.reserved)
}

// Reserved devolve os bytes reservados agora pela captura.
func (c *Conn) Reserved() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reserved
}
