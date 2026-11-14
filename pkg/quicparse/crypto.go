package quicparse

import (
	"errors"
	"slices"
)

// MaxCryptoLen limita os bytes do CRYPTO do Initial guardados para remontar o ClientHello (o mesmo teto
// do tlsparse: 64 KiB).
const MaxCryptoLen = 64 << 10

// MaxCryptoFragments limita os fragmentos pendentes (fora do prefixo contíguo desde o offset 0): sem ele,
// frames de 1 byte que nunca encaixam custam memória e CPU sem teto (spec 011, ADR 0033, task 144). Um
// ClientHello legítimo, mesmo embaralhado pelo Chrome, vem em poucos frames.
const MaxCryptoFragments = 64

// ErrCryptoTooLarge indica um CRYPTO com offset ou tamanho acima de MaxCryptoLen, mais bytes guardados
// que o teto ou mais fragmentos pendentes que MaxCryptoFragments.
var ErrCryptoTooLarge = errors.New("quicparse: CRYPTO acima do teto")

type fragment struct {
	off  uint64
	data []byte
}

// CryptoStream remonta o fluxo CRYPTO por offset, aceitando frames fora de ordem, sobrepostos e
// duplicados; para cada posição vale o fragmento de menor offset (entre iguais, o que chegou primeiro).
// Depois de um erro de teto, Add não faz nada.
type CryptoStream struct {
	// frags são os fragmentos pendentes, ordenados por offset (estável: entre iguais, ordem de chegada).
	frags []fragment
	// prefix são os bytes contíguos desde o offset 0.
	prefix []byte
	stored int
	err    error
}

// Add acrescenta um frame CRYPTO. Os dados são copiados. O custo é O(log n + n) no pior caso por chamada,
// com n <= MaxCryptoFragments.
func (c *CryptoStream) Add(off uint64, data []byte) {
	if len(data) == 0 || c.err != nil {
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
	if off <= have {
		// encosta no prefixo: estende direto e funde os pendentes que passaram a encaixar
		c.prefix = append(c.prefix, data[have-off:]...)
		c.merge()
		return
	}
	// pendente: primeira posição com offset maior (mantém a ordem de chegada entre offsets iguais)
	i, _ := slices.BinarySearchFunc(c.frags, off+1, func(f fragment, t uint64) int {
		if f.off < t {
			return -1
		}
		return 1
	})
	for j := i - 1; j >= 0 && c.frags[j].off == off; j-- {
		if len(c.frags[j].data) >= len(data) {
			return // duplicata (ou parte) de um pendente com o mesmo offset: os bytes dele valem
		}
	}
	if len(c.frags) >= MaxCryptoFragments || c.stored+len(data) > 2*MaxCryptoLen {
		// fragmentos sem fim ou duplicatas sobrepostas: guarda no máximo o teto
		c.err = ErrCryptoTooLarge
		return
	}
	c.frags = slices.Insert(c.frags, i, fragment{off: off, data: append([]byte(nil), data...)})
	c.stored += len(data)
}

// merge consome, do início da lista ordenada, os pendentes que encostam no prefixo.
func (c *CryptoStream) merge() {
	n := 0
	for _, f := range c.frags {
		have := uint64(len(c.prefix))
		if f.off > have {
			break
		}
		if end := f.off + uint64(len(f.data)); end > have {
			c.prefix = append(c.prefix, f.data[have-f.off:]...)
		}
		c.stored -= len(f.data)
		n++
	}
	if n > 0 {
		c.frags = slices.Delete(c.frags, 0, n)
	}
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
