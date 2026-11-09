package quicparse

import (
	"bytes"
	"strings"
	"testing"
)

// TestAppendFieldSection: o bloco escrito volta igual pelo decodificador, com a representação esperada.
func TestAppendFieldSection(t *testing.T) {
	in := [][2]string{
		{":status", "200"},                   // indexado
		{":status", "299"},                   // nome estático
		{"content-type", "text/plain"},       // indexado
		{"x-long", strings.Repeat("v", 300)}, // literal, tamanho com continuação
		{strings.Repeat("n", 20), "a"},       // nome literal longo (prefixo de 3 bits estoura)
		{"alt-svc", `h3=":443"; ma=60`},      // nome estático
	}
	b := AppendFieldSection(nil, in)
	_, fs, err := DecodeFieldSection(b, 0)
	if err != nil || len(fs) != len(in) {
		t.Fatal(err, fs)
	}
	repr := []string{ReprIndexed, ReprLiteralNameRef, ReprIndexed, ReprLiteral, ReprLiteral, ReprLiteralNameRef}
	for i, f := range fs {
		if f.Name != in[i][0] || f.Value != in[i][1] || f.Repr != repr[i] {
			t.Fatalf("%d: %+v", i, f)
		}
		if f.HuffmanValue != nil && *f.HuffmanValue {
			t.Fatalf("%d: Huffman", i)
		}
	}
	if !bytes.Equal(AppendFieldSection(nil, in), b) {
		t.Fatal("saída não determinística")
	}
	fr := AppendH3Frame(nil, H3FrameHeaders, b)
	r := NewRequestStream(0, 0)
	r.Feed(fr)
	r.Feed(append(AppendH3FrameHeader(nil, H3FrameData, 3), 1, 2, 3))
	if !r.HeadersSeen || len(r.Request.Fields) != len(in) || r.Request.BodyLen != 3 {
		t.Fatalf("%+v", r.Request)
	}
}
