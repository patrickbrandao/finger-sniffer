package quicparse

import (
	"errors"
	"slices"
)

// MaxCryptoLen limita os bytes do CRYPTO do Initial guardados para remontar o ClientHello (o mesmo teto
// do tlsparse: 64 KiB).
const MaxCryptoLen = 64 << 10

// ErrCryptoTooLarge indica um CRYPTO com offset ou tamanho acima de MaxCryptoLen.
var ErrCryptoTooLarge = errors.New("quicparse: CRYPTO acima do teto")

type fragment struct {
	off  uint64
	data []byte
}

// CryptoStream remonta o fluxo CRYPTO por offset, aceitando frames fora de ordem, sobrepostos e
// duplicados; o primeiro byte recebido para cada posição vale.
type CryptoStream struct {
	frags []fragment
	// prefix são os bytes contíguos desde o offset 0.
	prefix []byte
	stored int
	err    error
}

// Add acrescenta um frame CRYPTO. Os dados são copiados.
func (c *CryptoStream) Add(off uint64, data []byte) {
	if len(data) == 0 {
		return
	}
	end := off + uint64(len(data))
	if off > MaxCryptoLen || end > MaxCryptoLen {
		c.err = ErrCryptoTooLarge
		return
	}
	have := uint64(len(c.prefix))
	if end <= have {
		return // já temos tudo isso
	}
	if off < have {
		data = data[have-off:]
		off = have
	}
	if c.stored+len(data) > 2*MaxCryptoLen {
		// duplicatas sem fim: guarda no máximo o dobro do teto
		c.err = ErrCryptoTooLarge
		return
	}
	c.frags = append(c.frags, fragment{off: off, data: append([]byte(nil), data...)})
	c.stored += len(data)
	c.merge()
}

func (c *CryptoStream) merge() {
	slices.SortStableFunc(c.frags, func(a, b fragment) int {
		switch {
		case a.off < b.off:
			return -1
		case a.off > b.off:
			return 1
		}
		return 0
	})
	keep := c.frags[:0]
	for _, f := range c.frags {
		have := uint64(len(c.prefix))
		end := f.off + uint64(len(f.data))
		switch {
		case end <= have:
			c.stored -= len(f.data)
		case f.off <= have:
			c.prefix = append(c.prefix, f.data[have-f.off:]...)
			c.stored -= len(f.data)
		default:
			keep = append(keep, f)
		}
	}
	clear(c.frags[len(keep):])
	c.frags = keep
}

// Prefix devolve os bytes contíguos desde o offset 0.
func (c *CryptoStream) Prefix() []byte { return c.prefix }

// Err devolve o erro de teto, se houve.
func (c *CryptoStream) Err() error { return c.err }

// HandshakeMessage devolve a primeira mensagem de handshake TLS (tipo, tamanho de 3 bytes e corpo) se ela
// já está inteira no prefixo.
func (c *CryptoStream) HandshakeMessage() ([]byte, bool) {
	p := c.prefix
	if len(p) < 4 {
		return nil, false
	}
	n := 4 + (int(p[1])<<16 | int(p[2])<<8 | int(p[3]))
	if len(p) < n {
		return nil, false
	}
	return p[:n:n], true
}
