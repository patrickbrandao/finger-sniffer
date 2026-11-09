package tlsparse

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseClientHello: nenhuma entrada causa pânico, o ClientHello devolvido nunca é nil e o Info
// derivado sempre serializa.
func FuzzParseClientHello(f *testing.F) {
	m, _ := filepath.Glob("testdata/*.bin")
	for _, p := range m {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
		f.Add(b[:len(b)/2])
	}
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00})
	f.Add(buildHello(ext(ExtKeyShare, 0, 4, 0, 0x1d, 0, 0)))
	f.Fuzz(func(t *testing.T, data []byte) {
		ch, _ := Parse(data)
		if ch == nil {
			t.Fatal("Parse devolveu nil")
		}
		if _, err := json.Marshal(NewInfo(ch, data, 64)); err != nil {
			t.Fatal(err)
		}
		// a mesma entrada como mensagem de handshake (caminho do QUIC)
		if ch2, _ := ParseMessage(data); ch2 == nil {
			t.Fatal("ParseMessage devolveu nil")
		}
		// e pela Conn, em pedaços
		c := NewConn(&chunkConn{data: append([]byte{}, data...), chunk: 7})
		buf := make([]byte, 64)
		for {
			if _, err := c.Read(buf); err != nil {
				break
			}
		}
		_, _ = c.ClientHello()
	})
}
