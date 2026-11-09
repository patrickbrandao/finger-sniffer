package web

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// wsEncode monta um frame (máscara opcional) para os testes.
func wsEncode(fin bool, rsv, opcode int, mask []byte, payload []byte) []byte {
	b0 := byte(opcode) | byte(rsv<<4)
	if fin {
		b0 |= 0x80
	}
	out := []byte{b0}
	var m byte
	if mask != nil {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		out = append(out, m|byte(n))
	case n < 1<<16:
		out = append(out, m|126, byte(n>>8), byte(n))
	default:
		out = append(out, m|127)
		out = binary.BigEndian.AppendUint64(out, uint64(n))
	}
	pl := append([]byte(nil), payload...)
	if mask != nil {
		out = append(out, mask...)
		for i := range pl {
			pl[i] ^= mask[i%4]
		}
	}
	return append(out, pl...)
}

func TestWSParser(t *testing.T) {
	key := []byte{1, 2, 3, 4}
	closePL := append([]byte{0x03, 0xe8}, "bye"...)
	var stream []byte
	stream = append(stream, wsEncode(false, 0, wsOpText, key, []byte("hel"))...)
	stream = append(stream, wsEncode(true, 0, wsOpContinuation, key, []byte("lo"))...)
	stream = append(stream, wsEncode(true, 4, wsOpBinary, nil, bytes.Repeat([]byte{'x'}, 300))...)
	stream = append(stream, wsEncode(true, 0, wsOpBinary, key, bytes.Repeat([]byte{'y'}, 70000))...)
	stream = append(stream, wsEncode(true, 0, wsOpPing, nil, nil)...)
	stream = append(stream, wsEncode(true, 0, wsOpClose, key, closePL)...)

	// Byte a byte e de uma vez dão o mesmo resultado.
	for _, step := range []int{1, 7, len(stream)} {
		var got []wsFrame
		p := wsParser{onFrame: func(f wsFrame) { got = append(got, f) }}
		for i := 0; i < len(stream); i += step {
			p.Feed(time.Time{}, stream[i:min(i+step, len(stream))])
		}
		if p.err != nil || len(got) != 6 {
			t.Fatalf("step %d: err %v frames %d", step, p.err, len(got))
		}
		if got[0].Fin || got[0].Opcode != wsOpText || !got[0].Masked || got[0].MaskKey != [4]byte{1, 2, 3, 4} ||
			got[0].Length != 3 {
			t.Fatalf("frame 0 %+v", got[0])
		}
		if !got[1].Fin || got[1].Opcode != wsOpContinuation {
			t.Fatalf("frame 1 %+v", got[1])
		}
		if got[2].RSV != 4 || got[2].Length != 300 || got[2].Masked {
			t.Fatalf("frame 2 %+v", got[2])
		}
		if got[3].Length != 70000 {
			t.Fatalf("frame 3 %+v", got[3])
		}
		code, reason := got[5].closeInfo()
		if got[5].Opcode != wsOpClose || code == nil || *code != 1000 || *reason != "bye" {
			t.Fatalf("close %+v", got[5])
		}
	}
}

func TestWSParserBadLength(t *testing.T) {
	p := wsParser{}
	p.Feed(time.Time{}, []byte{0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0, 1})
	if p.err != errWSLength {
		t.Fatalf("err %v", p.err)
	}
	p.Feed(time.Time{}, []byte{0x82, 0}) // depois do erro, nada
}

// FuzzWSParser: o parser nunca entra em pânico e, em qualquer divisão da entrada, vê os mesmos frames.
func FuzzWSParser(f *testing.F) {
	f.Add(wsEncode(true, 0, wsOpText, []byte{9, 9, 9, 9}, []byte("hi")), 3)
	f.Add(wsEncode(true, 0, wsOpClose, nil, []byte{3, 232, 'x'}), 1)
	f.Add([]byte{0x82, 127, 0, 0, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4, 5}, 2)
	f.Fuzz(func(t *testing.T, data []byte, step int) {
		if step <= 0 || step > len(data) {
			step = max(len(data), 1)
		}
		var a, b []wsFrame
		pa := wsParser{onFrame: func(f wsFrame) { a = append(a, f) }}
		pa.Feed(time.Time{}, data)
		pb := wsParser{onFrame: func(f wsFrame) { b = append(b, f) }}
		for i := 0; i < len(data); i += step {
			pb.Feed(time.Time{}, data[i:min(i+step, len(data))])
		}
		if len(a) != len(b) || (pa.err == nil) != (pb.err == nil) {
			t.Fatalf("split changes result: %d vs %d", len(a), len(b))
		}
		for i := range a {
			if a[i].Length != b[i].Length || !bytes.Equal(a[i].Payload, b[i].Payload) || len(a[i].Payload) > wsMaxControlPayload {
				t.Fatalf("frame %d differs", i)
			}
		}
	})
}
