package web

import (
	"encoding/binary"
	"errors"
	"time"
)

// Opcodes do WebSocket (RFC 6455 §5.2).
const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xa
)

// wsMaxControlPayload é o maior payload de frame de controle (RFC 6455 §5.5); só ele é guardado.
const wsMaxControlPayload = 125

// errWSLength indica um tamanho de 64 bits com o bit mais alto ligado (RFC 6455 §5.2): a leitura para.
var errWSLength = errors.New("websocket: frame length with most significant bit set")

// wsFrame é um frame visto na cópia dos bytes (spec 012 RF-04).
type wsFrame struct {
	At      time.Time
	Fin     bool
	RSV     int // bits RSV1–3 (RSV1 = 4)
	Opcode  int
	Masked  bool
	MaskKey [4]byte
	Length  int64
	// Payload é o payload (já desmascarado) dos frames de controle, até 125 bytes.
	Payload []byte
}

// closeInfo devolve código e razão de um frame de close (sem código: nil, nil).
func (f *wsFrame) closeInfo() (*int, *string) {
	if len(f.Payload) < 2 {
		return nil, nil
	}
	code := int(binary.BigEndian.Uint16(f.Payload))
	reason := string(f.Payload[2:])
	return &code, &reason
}

// wsParser lê frames WebSocket de um sentido em pedaços, sem nunca falhar para quem consome os bytes:
// entrada malformada só para a leitura (err). Cada frame completo vai para onFrame.
type wsParser struct {
	onFrame func(wsFrame)
	err     error

	hdr  [14]byte
	hdrN int
	cur  wsFrame
	need int64 // bytes de payload ainda por vir
	pos  int64 // bytes de payload já vistos (para desmascarar)
	inPL bool
}

// headerLen devolve o tamanho do cabeçalho a partir dos 2 primeiros bytes.
func wsHeaderLen(b1 byte) int {
	n := 2
	switch b1 & 0x7f {
	case 126:
		n += 2
	case 127:
		n += 8
	}
	if b1&0x80 != 0 {
		n += 4
	}
	return n
}

// Feed consome mais um pedaço que chegou em at.
func (p *wsParser) Feed(at time.Time, b []byte) {
	for len(b) > 0 && p.err == nil {
		if !p.inPL {
			if p.hdrN == 0 {
				p.cur = wsFrame{At: at}
			}
			want := 2
			if p.hdrN >= 2 {
				want = wsHeaderLen(p.hdr[1])
			}
			n := copy(p.hdr[p.hdrN:want], b)
			p.hdrN += n
			b = b[n:]
			if p.hdrN < want {
				continue
			}
			if want == 2 && wsHeaderLen(p.hdr[1]) > 2 {
				continue
			}
			p.startFrame()
			continue
		}
		n := min(int64(len(b)), p.need)
		if p.cur.Opcode >= wsOpClose && len(p.cur.Payload) < wsMaxControlPayload {
			take := min(n, int64(wsMaxControlPayload-len(p.cur.Payload)))
			for i := int64(0); i < take; i++ {
				c := b[i]
				if p.cur.Masked {
					c ^= p.cur.MaskKey[(p.pos+i)%4]
				}
				p.cur.Payload = append(p.cur.Payload, c)
			}
		}
		p.pos += n
		p.need -= n
		b = b[n:]
		if p.need == 0 {
			p.endFrame()
		}
	}
}

// startFrame interpreta o cabeçalho completo.
func (p *wsParser) startFrame() {
	h := p.hdr[:p.hdrN]
	f := &p.cur
	f.Fin = h[0]&0x80 != 0
	f.RSV = int(h[0]>>4) & 0x7
	f.Opcode = int(h[0] & 0x0f)
	f.Masked = h[1]&0x80 != 0
	i := 2
	switch l := int64(h[1] & 0x7f); l {
	case 126:
		f.Length = int64(binary.BigEndian.Uint16(h[2:]))
		i += 2
	case 127:
		v := binary.BigEndian.Uint64(h[2:])
		if v>>63 != 0 {
			p.err = errWSLength
			return
		}
		f.Length = int64(v)
		i += 8
	default:
		f.Length = l
	}
	if f.Masked {
		copy(f.MaskKey[:], h[i:i+4])
	}
	p.hdrN = 0
	p.need, p.pos = f.Length, 0
	if p.need == 0 {
		p.endFrame()
		return
	}
	p.inPL = true
}

func (p *wsParser) endFrame() {
	p.inPL = false
	if p.onFrame != nil {
		p.onFrame(p.cur)
	}
	p.cur = wsFrame{}
}
