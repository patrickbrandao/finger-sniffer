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
	// extensão repetida (task 386)
	f.Add(buildHello(append(ext(ExtALPN, 0, 3, 2, 'h', '2'), ext(ExtALPN, 0, 3, 2, 'x', '1')...)))
	// extensão malformada e cipher_suites ímpar (task 386)
	f.Add(buildHello(ext(ExtSupportedGroups, 0)))
	f.Fuzz(func(t *testing.T, data []byte) {
		ch, _ := Parse(data)
		if ch == nil {
			t.Fatal("Parse devolveu nil")
		}
		in := NewInfo(ch, data, 64)
		if _, err := json.Marshal(in); err != nil {
			t.Fatal(err)
		}
		// extension_errors e field_errors: no máximo 64, só códigos do contrato, posição não negativa (task 386)
		for _, l := range [][]ParseIssue{in.ExtensionErrors, in.FieldErrors} {
			if len(l) > MaxParseIssues {
				t.Fatalf("%d erros", len(l))
			}
			for _, it := range l {
				if it.Offset < 0 || (it.Error != IssueDuplicate && it.Error != IssueMalformed && it.Error != IssueOddLength) {
					t.Fatalf("item %v", it)
				}
			}
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
