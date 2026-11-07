// Package fspb codifica e decodifica lotes de pacotes no formato FSPB v1 (ADR 0015).
//
// Registro (little-endian): ts_ns u64 | dir u8 | flags u8 | reserved u16 | wire_len u32 | cap_len u32 | frame.
package fspb

import (
	"encoding/binary"
	"errors"
)

// HeaderLen é o tamanho do cabeçalho de cada registro.
const HeaderLen = 20

// Direções.
const (
	DirIn  = 0
	DirOut = 1
)

// Flags.
const (
	FlagOffloadSuspect = 1 << 0
	FlagTruncated      = 1 << 1
)

// Record é um pacote do lote.
type Record struct {
	TsNs    int64
	Dir     uint8
	Flags   uint8
	WireLen uint32
	Frame   []byte
}

// ErrShort indica um lote truncado.
var ErrShort = errors.New("fspb: short buffer")

// Append acrescenta um registro a buf e devolve o novo buffer.
func Append(buf []byte, r Record) []byte {
	var h [HeaderLen]byte
	binary.LittleEndian.PutUint64(h[0:8], uint64(r.TsNs)) //nolint:gosec // tempo positivo
	h[8] = r.Dir
	h[9] = r.Flags
	binary.LittleEndian.PutUint32(h[12:16], r.WireLen)
	binary.LittleEndian.PutUint32(h[16:20], uint32(len(r.Frame))) //nolint:gosec // frame < 64 KiB
	buf = append(buf, h[:]...)
	return append(buf, r.Frame...)
}

// Decode percorre o lote chamando fn para cada registro. Frame aponta para dentro de buf.
func Decode(buf []byte, fn func(Record) error) (int, error) {
	n := 0
	for len(buf) > 0 {
		if len(buf) < HeaderLen {
			return n, ErrShort
		}
		capLen := int(binary.LittleEndian.Uint32(buf[16:20]))
		if len(buf) < HeaderLen+capLen {
			return n, ErrShort
		}
		r := Record{
			TsNs:    int64(binary.LittleEndian.Uint64(buf[0:8])), //nolint:gosec // tempo positivo
			Dir:     buf[8],
			Flags:   buf[9],
			WireLen: binary.LittleEndian.Uint32(buf[12:16]),
			Frame:   buf[HeaderLen : HeaderLen+capLen],
		}
		if err := fn(r); err != nil {
			return n, err
		}
		n++
		buf = buf[HeaderLen+capLen:]
	}
	return n, nil
}
