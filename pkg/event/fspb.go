package event

import (
	"encoding/binary"
	"errors"
)

// FSPB v1 (ADR 0015): sequência de registros little-endian
// ts_ns u64 | dir u8 | flags u8 | reserved u16 | wire_len u32 | cap_len u32 | frame[cap_len].

// FSPBHeaderLen é o tamanho do cabeçalho de cada registro.
const FSPBHeaderLen = 20

// FSPBFormat é o valor do cabeçalho NATS Fs-Format.
const FSPBFormat = "fspb1"

// Cabeçalhos NATS do lote de pacotes.
const (
	HeaderSchemaVersion  = "Fs-Schema-Version"
	HeaderService        = "Fs-Service"
	HeaderServiceVersion = "Fs-Service-Version"
	HeaderFormat         = "Fs-Format"
	HeaderCount          = "Fs-Count"
	HeaderIface          = "Fs-Iface"
)

// Direção do pacote.
const (
	DirIn  uint8 = 0
	DirOut uint8 = 1
)

// Flags do registro.
const (
	FlagOffloadSuspect uint8 = 1 << 0
	FlagTruncated      uint8 = 1 << 1
)

// Packet é um registro do lote.
type Packet struct {
	TsNs    int64
	Dir     uint8
	Flags   uint8
	WireLen uint32
	Frame   []byte
}

// ErrShortBatch indica um lote truncado.
var ErrShortBatch = errors.New("event: short FSPB batch")

// AppendPacket acrescenta um registro ao lote.
func AppendPacket(buf []byte, p Packet) []byte {
	var h [FSPBHeaderLen]byte
	binary.LittleEndian.PutUint64(h[0:8], uint64(p.TsNs)) //nolint:gosec // tempo positivo
	h[8] = p.Dir
	h[9] = p.Flags
	binary.LittleEndian.PutUint32(h[12:16], p.WireLen)
	binary.LittleEndian.PutUint32(h[16:20], uint32(len(p.Frame))) //nolint:gosec // frame < 64 KiB
	return append(append(buf, h[:]...), p.Frame...)
}

// DecodePackets percorre o lote chamando fn para cada registro (Frame aponta para dentro de buf) e devolve
// quantos registros leu.
func DecodePackets(buf []byte, fn func(Packet) error) (int, error) {
	n := 0
	for len(buf) > 0 {
		if len(buf) < FSPBHeaderLen {
			return n, ErrShortBatch
		}
		capLen := int(binary.LittleEndian.Uint32(buf[16:20]))
		if capLen > len(buf)-FSPBHeaderLen {
			return n, ErrShortBatch
		}
		p := Packet{
			TsNs:    int64(binary.LittleEndian.Uint64(buf[0:8])), //nolint:gosec // tempo positivo
			Dir:     buf[8],
			Flags:   buf[9],
			WireLen: binary.LittleEndian.Uint32(buf[12:16]),
			Frame:   buf[FSPBHeaderLen : FSPBHeaderLen+capLen],
		}
		if err := fn(p); err != nil {
			return n, err
		}
		n++
		buf = buf[FSPBHeaderLen+capLen:]
	}
	return n, nil
}
