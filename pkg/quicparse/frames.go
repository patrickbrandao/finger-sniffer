package quicparse

import (
	"errors"
	"fmt"
)

// Tipos de frame QUIC que podem aparecer num Initial (RFC 9000 seção 17.2.2 e tabela 3).
const (
	FramePadding         = 0x00
	FramePing            = 0x01
	FrameACK             = 0x02
	FrameACKECN          = 0x03
	FrameCrypto          = 0x06
	FrameConnectionClose = 0x1c
	// FrameConnectionCloseApp não é permitido no Initial, mas é lido para registrar.
	FrameConnectionCloseApp = 0x1d
)

// ErrFrame indica um frame ilegível ou de tipo que não pode ser lido no Initial; a lista para nele.
var ErrFrame = errors.New("quicparse: frame inválido no Initial")

// frameNames são os nomes da RFC 9000 tabela 3, usados em `initial_frames`.
var frameNames = map[uint64]string{
	0x00: "PADDING", 0x01: "PING", 0x02: "ACK", 0x03: "ACK_ECN", 0x04: "RESET_STREAM", 0x05: "STOP_SENDING",
	0x06: "CRYPTO", 0x07: "NEW_TOKEN", 0x08: "STREAM", 0x09: "STREAM", 0x0a: "STREAM", 0x0b: "STREAM",
	0x0c: "STREAM", 0x0d: "STREAM", 0x0e: "STREAM", 0x0f: "STREAM", 0x10: "MAX_DATA",
	0x11: "MAX_STREAM_DATA", 0x12: "MAX_STREAMS", 0x13: "MAX_STREAMS", 0x14: "DATA_BLOCKED",
	0x15: "STREAM_DATA_BLOCKED", 0x16: "STREAMS_BLOCKED", 0x17: "STREAMS_BLOCKED", 0x18: "NEW_CONNECTION_ID",
	0x19: "RETIRE_CONNECTION_ID", 0x1a: "PATH_CHALLENGE", 0x1b: "PATH_RESPONSE", 0x1c: "CONNECTION_CLOSE",
	0x1d: "CONNECTION_CLOSE_APP", 0x1e: "HANDSHAKE_DONE", 0x30: "DATAGRAM", 0x31: "DATAGRAM",
}

// FrameName devolve o nome do tipo de frame (RFC 9000/9221), ou o tipo em hexadecimal.
func FrameName(t uint64) string {
	if n, ok := frameNames[t]; ok {
		return n
	}
	return fmt.Sprintf("0x%x", t)
}

// Frame é um frame de um Initial. Uma sequência de bytes PADDING vira um só frame com PaddingLen.
type Frame struct {
	Type uint64
	// PaddingLen é o número de bytes 0x00 seguidos (PADDING).
	PaddingLen int
	// Offset e Data do CRYPTO (Data aponta para o payload decifrado).
	Offset uint64
	Data   []byte
	// LargestAcked do ACK.
	LargestAcked uint64
	// ErrorCode, FrameType e Reason do CONNECTION_CLOSE.
	ErrorCode uint64
	FrameType uint64
	Reason    []byte
}

// Name é o nome do tipo do frame.
func (f Frame) Name() string { return FrameName(f.Type) }

// ParseFrames lê os frames de um payload de Initial em ordem. Para no primeiro frame ilegível ou de tipo
// que não pertence ao Initial e devolve os anteriores com o erro (o frame problemático vem por último
// na lista, só com o tipo, para que apareça em `initial_frames`).
func ParseFrames(p []byte) ([]Frame, error) {
	var out []Frame
	r := reader{buf: p}
	for !r.empty() {
		start := r.off
		t := r.varint()
		if r.bad {
			return out, fmt.Errorf("%w: tipo truncado no byte %d", ErrFrame, start)
		}
		f := Frame{Type: t}
		switch t {
		case FramePadding:
			n := 1
			for r.off < len(r.buf) && r.buf[r.off] == 0 {
				r.off++
				n++
			}
			f.PaddingLen = n
		case FramePing:
		case FrameACK, FrameACKECN:
			f.LargestAcked = r.varint()
			r.varint() // ack delay
			ranges := r.varint()
			r.varint() // first ack range
			for i := uint64(0); i < ranges && !r.bad; i++ {
				r.varint() // gap
				r.varint() // ack range length
			}
			if t == FrameACKECN {
				r.varint()
				r.varint()
				r.varint()
			}
		case FrameCrypto:
			f.Offset = r.varint()
			f.Data = r.bytes(r.varint())
		case FrameConnectionClose, FrameConnectionCloseApp:
			f.ErrorCode = r.varint()
			if t == FrameConnectionClose {
				f.FrameType = r.varint()
			}
			f.Reason = r.bytes(r.varint())
		default:
			out = append(out, f)
			return out, fmt.Errorf("%w: tipo %s no byte %d", ErrFrame, FrameName(t), start)
		}
		if r.bad {
			out = append(out, Frame{Type: t})
			return out, fmt.Errorf("%w: %s truncado no byte %d", ErrFrame, FrameName(t), start)
		}
		out = append(out, f)
	}
	return out, nil
}
