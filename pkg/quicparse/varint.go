// Package quicparse analisa, de forma passiva, o que o cliente QUIC/HTTP/3 manda (spec 011, ADR 0019):
// o Initial (cabeçalho longo, remoção da proteção de cabeçalho e decifragem com as chaves derivadas do
// DCID, QUIC v1 e v2), os frames do Initial na ordem, a remontagem do CRYPTO em vários pacotes e
// datagramas, os parâmetros de transporte na ordem, os frames h3 dos streams de controle e de requisição
// e o QPACK com a representação de cada linha.
//
// Nada é normalizado: ordem, GREASE e representação ficam como chegaram. O pacote não guarda estado
// global, nunca altera os bytes recebidos (decifra sobre cópias) e não entra em pânico com entrada hostil
// (alvos de fuzz em fuzz_test.go).
package quicparse

import "errors"

// MaxVarint é o maior valor de um inteiro de tamanho variável do QUIC (RFC 9000 seção 16).
const MaxVarint = 1<<62 - 1

// errShort indica que o campo acaba depois do fim dos dados.
var errShort = errors.New("quicparse: dados truncados")

// ReadVarint lê um inteiro de tamanho variável (RFC 9000 seção 16) e devolve o valor e quantos bytes
// usou; ok é false se b acaba antes do fim do inteiro.
func ReadVarint(b []byte) (v uint64, n int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, true
}

// AppendVarint acrescenta v codificado no menor tamanho possível. Valores acima de MaxVarint são
// cortados em MaxVarint.
//
//nolint:gosec // cada byte é uma fatia do valor, o corte é intencional
func AppendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	}
	v = min(v, MaxVarint)
	return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16),
		byte(v>>8), byte(v))
}

// reader lê campos em sequência de um buffer; depois do primeiro erro todas as leituras falham.
type reader struct {
	buf []byte
	off int
	bad bool
}

func (r *reader) empty() bool { return r.off >= len(r.buf) }

func (r *reader) rest() []byte { return r.buf[r.off:] }

func (r *reader) varint() uint64 {
	if r.bad {
		return 0
	}
	v, n, ok := ReadVarint(r.buf[r.off:])
	if !ok {
		r.bad = true
		return 0
	}
	r.off += n
	return v
}

func (r *reader) byte() byte {
	if r.bad || r.off >= len(r.buf) {
		r.bad = true
		return 0
	}
	r.off++
	return r.buf[r.off-1]
}

// bytes devolve os próximos n bytes (sem copiar).
//
//nolint:gosec // n <= len(buf)-off conferido antes das conversões
func (r *reader) bytes(n uint64) []byte {
	if r.bad || n > uint64(len(r.buf)-r.off) {
		r.bad = true
		return nil
	}
	b := r.buf[r.off : r.off+int(n)]
	r.off += int(n)
	return b
}
