package tlsparse

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// refCapture é a captura anterior à task 166 (Reassemble do buffer inteiro a cada Read), usada como
// referência de equivalência.
func refCapture(chunks [][]byte) ([]byte, error) {
	var buf []byte
	for _, p := range chunks {
		buf = append(buf, p...)
		r, err := Reassemble(buf)
		switch {
		case err == nil:
			return buf[:r.Consumed], nil
		case errors.Is(err, ErrIncomplete):
			if len(buf) >= maxCapture {
				return buf[:maxCapture], ErrTooLarge
			}
		default:
			return buf, err
		}
	}
	return buf, ErrIncomplete
}

// feed entrega os pedaços a uma Conn nova, como Reads sucessivos.
func feed(chunks [][]byte) ([]byte, error) {
	c := NewConn(nil)
	for _, p := range chunks {
		c.capture(p)
	}
	return c.Records()
}

// split corta data em pedaços cujos tamanhos vêm, em ciclo, de sizes (0 vira 1).
func split(data []byte, sizes []byte) [][]byte {
	var out [][]byte
	for i := 0; len(data) > 0; i++ {
		n := 1
		if len(sizes) > 0 {
			n = max(int(sizes[i%len(sizes)]), 1)
		}
		n = min(n, len(data))
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}

func checkEquivalent(t *testing.T, name string, chunks [][]byte) {
	t.Helper()
	ref := chunks
	if total := len(bytes.Join(chunks, nil)); total > 8<<10 && len(chunks) > 1 {
		// A referência é quadrática: entradas grandes cortadas são comparadas com a remontagem do total,
		// que dá o mesmo resultado quando ele não depende do corte (ClientHello completo ou teto de
		// maxCapture, atingido no Read que passa dele, em qualquer corte de até 255 bytes).
		all := bytes.Join(chunks, nil)
		ref = [][]byte{all}
		if len(all) > maxCapture {
			ref = [][]byte{all[:maxCapture], all[maxCapture:]}
		}
	}
	wantB, wantErr := refCapture(ref)
	gotB, gotErr := feed(chunks)
	if !bytes.Equal(gotB, wantB) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
		t.Fatalf("%s: got %d bytes err %v, want %d bytes err %v", name, len(gotB), gotErr, len(wantB), wantErr)
	}
}

// tinyRecords põe msg em registros de size bytes.
func tinyRecords(msg []byte, size int) []byte {
	var out []byte
	for len(msg) > 0 {
		n := min(size, len(msg))
		out = append(out, 0x16, 0x03, 0x01, byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

// TestConnIncrementalEquivalent: a captura incremental dá os mesmos bytes e o mesmo erro que a remontagem
// do buffer inteiro, em vários cortes e entradas (task 166).
func TestConnIncrementalEquivalent(t *testing.T) {
	rec := readSample(t, "chrome-2records")
	goRec := readSample(t, "go")
	msg := goRec[RecordHeaderLen:]
	after := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03}
	big := append([]byte{1, 0, 0x40, 0x00}, make([]byte, 16<<10)...)
	inputs := map[string][]byte{
		"chrome 2 records + extra":  append(append([]byte{}, rec...), after...),
		"go 1-byte records":         tinyRecords(msg, 1),
		"go 3-byte records + extra": append(tinyRecords(msg, 3), after...),
		"16 KiB 1-byte records":     tinyRecords(big, 1),
		"16 KiB 1000-byte records":  tinyRecords(big, 1000),
		"alert":                     {0x15, 0x03, 0x03, 0, 2, 2, 40},
		"http":                      []byte("GET / HTTP/1.1\r\n"),
		"sslv2 version":             {0x16, 0x02, 0x00, 0, 4, 1, 0, 0, 0},
		"server hello":              {0x16, 0x03, 0x03, 0, 4, 2, 0, 0, 0},
		"server hello split hdr":    {0x16, 0x03, 0x03, 0, 1, 2, 0x16, 0x03, 0x03, 0, 3, 0, 0, 0},
		"too large":                 {0x16, 0x03, 0x01, 0, 4, 1, 0x01, 0, 1},
		"too large in cut record":   {0x16, 0x03, 0x01, 0, 9, 1, 0x01, 0, 1},
		"other type mid":            append(append([]byte{0x16, 0x03, 0x01, 0, 10}, msg[:10]...), 0x17, 0x03, 0x03, 0, 1, 0),
		"zero-length records":       append(bytes.Repeat([]byte{0x16, 0x03, 0x01, 0, 0}, 50), goRec...),
		"later version not checked": append(append([]byte{0x16, 0x03, 0x01, 0, 10}, msg[:10]...), tinyRecords(msg[10:], 7)...),
		"max capture":               tinyRecords(append([]byte{1, 0, 0xea, 0x60}, make([]byte, 60000)...), 1),
		"short":                     goRec[:3],
	}
	for name, data := range inputs {
		for _, sizes := range [][]byte{{1}, {2}, {5}, {6}, {1, 4, 9}, {255}, nil} {
			checkEquivalent(t, fmt.Sprintf("%s/%v", name, sizes), split(data, sizes))
		}
		checkEquivalent(t, name+"/whole", [][]byte{data})
	}
}

// FuzzConnCapture: para qualquer entrada e qualquer corte, a captura incremental é igual à referência.
func FuzzConnCapture(f *testing.F) {
	goRec := readSample(f, "go")
	f.Add(goRec, []byte{1})
	f.Add(tinyRecords(goRec[RecordHeaderLen:], 2), []byte{3, 1})
	f.Add([]byte{0x16, 0x03, 0x03, 0, 1, 2, 0x16, 0x03, 0x03, 0, 3, 0, 0, 0}, []byte{2})
	f.Fuzz(func(t *testing.T, data, sizes []byte) {
		if len(data) > 8<<10 {
			return
		}
		checkEquivalent(t, "fuzz", split(data, sizes))
	})
}

// BenchmarkConnCaptureDribble: ClientHello de 60000 bytes entregue 1 byte por Read, em registros grandes e
// em registros de 1 byte. O custo por byte fica constante (linear no total).
func BenchmarkConnCaptureDribble(b *testing.B) {
	for _, n := range []int{6000, 60000} {
		msg := append([]byte{1, byte(n >> 16), byte(n >> 8), byte(n)}, make([]byte, n)...)
		for name, stream := range map[string][]byte{
			"big records": tinyRecords(msg, 16000),
			"1-byte":      tinyRecords(msg, 1),
		} {
			b.Run(fmt.Sprintf("%s/%d", name, n), func(b *testing.B) {
				b.SetBytes(int64(len(stream)))
				for b.Loop() {
					c := NewConn(nil)
					for i := range stream {
						c.capture(stream[i : i+1])
					}
				}
			})
		}
	}
}
