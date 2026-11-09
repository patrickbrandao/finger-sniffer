package h2passive

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func ip(v int) *int   { return &v }
func bp(v bool) *bool { return &v }

func TestHPACKRepresentations(t *testing.T) {
	// RFC 7541 C.2 (sem Huffman) e C.4 (com Huffman), mais never-indexed e atualização de tamanho
	block := []byte{
		0x82,                                                                   // indexed :method GET
		0x44, 0x0c, '/', 's', 'a', 'm', 'p', 'l', 'e', '/', 'p', 'a', 't', 'h', // literal-indexed nome 4 (:path)
		0x10, 0x08, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x06, 's', 'e', 'c', 'r', 'e', 't', // never, nome literal
		0x01, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff, // not-indexed :authority Huffman
		0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf, // custom-key/custom-value Huffman
		0xbe, // indexed 62 = custom-key (mais nova)
		0xbf, // indexed 63 = :path /sample/path
	}
	d := newHPACKDecoder(4096, 100)
	got, err := d.decode(block)
	if err != nil {
		t.Fatal(err)
	}
	want := []HPACKField{
		{Name: ":method", Value: "GET", Repr: ReprIndexed, Index: ip(2)},
		{Name: ":path", Value: "/sample/path", Repr: ReprLiteralIndexed, Index: ip(4), HuffmanValue: bp(false)},
		{Name: "password", Value: "secret", Repr: ReprLiteralNeverIndexed, HuffmanName: bp(false), HuffmanValue: bp(false)},
		{Name: ":authority", Value: "www.example.com", Repr: ReprLiteralNotIndexed, Index: ip(1), HuffmanValue: bp(true)},
		{Name: "custom-key", Value: "custom-value", Repr: ReprLiteralIndexed, HuffmanName: bp(true), HuffmanValue: bp(true)},
		{Name: "custom-key", Value: "custom-value", Repr: ReprIndexed, Index: ip(62)},
		{Name: ":path", Value: "/sample/path", Repr: ReprIndexed, Index: ip(63)},
	}
	if s1, s2 := fmt.Sprint(dump(got)), fmt.Sprint(dump(want)); s1 != s2 {
		t.Fatalf("\n got %s\nwant %s", s1, s2)
	}
	if d.size != uint32(10+12+32+5+12+32) || len(d.dyn) != 2 {
		t.Fatalf("tabela: size=%d n=%d", d.size, len(d.dyn))
	}
}

func dump(fs []HPACKField) []string {
	var out []string
	for _, f := range fs {
		s := fmt.Sprintf("%s=%s/%s", f.Name, f.Value, f.Repr)
		if f.Index != nil {
			s += fmt.Sprintf("/i%d", *f.Index)
		}
		if f.HuffmanName != nil {
			s += fmt.Sprintf("/hn%v", *f.HuffmanName)
		}
		if f.HuffmanValue != nil {
			s += fmt.Sprintf("/hv%v", *f.HuffmanValue)
		}
		out = append(out, s)
	}
	return out
}

func TestHPACKEvictionAndSizeUpdate(t *testing.T) {
	d := newHPACKDecoder(100, 100)
	// cada entrada a=xxxx tem 1+4+32 = 37 bytes: cabem duas
	lit := func(v string) []byte { return append([]byte{0x40, 0x01, 'a', byte(len(v))}, v...) }
	b := append(append(lit("1111"), lit("2222")...), lit("3333")...)
	if _, err := d.decode(b); err != nil {
		t.Fatal(err)
	}
	if len(d.dyn) != 2 || d.dyn[0].value != "3333" || d.dyn[1].value != "2222" || d.size != 74 {
		t.Fatalf("dyn = %+v size=%d", d.dyn, d.size)
	}
	// atualização para 40: sobra só a mais nova
	if _, err := d.decode([]byte{0x3f, 0x09}); err != nil {
		t.Fatal(err)
	}
	if len(d.dyn) != 1 || d.dyn[0].value != "3333" || d.maxSize != 40 {
		t.Fatalf("dyn = %+v", d.dyn)
	}
	// entrada maior que a tabela esvazia a tabela
	if _, err := d.decode(lit("0123456789")); err != nil {
		t.Fatal(err)
	}
	if len(d.dyn) != 0 || d.size != 0 {
		t.Fatalf("dyn = %+v", d.dyn)
	}
	// tamanho 0 e de volta a 100
	if _, err := d.decode([]byte{0x20, 0x3f, 0x45}); err != nil || d.maxSize != 100 {
		t.Fatalf("maxSize=%d err=%v", d.maxSize, err)
	}
}

func TestHPACKErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		b   []byte
		err error
	}{
		"inteiro truncado":   {[]byte{0xff}, ErrHPACKTruncated},
		"inteiro enorme":     {[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, ErrHPACKInteger},
		"cadeia vazia":       {[]byte{0x40}, ErrHPACKTruncated},
		"nome truncado":      {[]byte{0x40, 0x05, 'a'}, ErrHPACKTruncated},
		"valor ausente":      {[]byte{0x41}, ErrHPACKTruncated},
		"huffman inválido":   {[]byte{0x41, 0x81, 0x00}, ErrHPACKHuffman},
		"huffman do nome":    {[]byte{0x00, 0x81, 0x00, 0x00}, ErrHPACKHuffman},
		"índice de nome":     {[]byte{0x7f, 0x10, 0x00}, ErrHPACKIndex},
		"atualização grande": {[]byte{0x3f, 0xe2, 0x1f}, ErrHPACKTableSize},
		"inteiro da tabela":  {[]byte{0x3f}, ErrHPACKTruncated},
		"never truncado":     {[]byte{0x1f}, ErrHPACKTruncated},
		"not truncado":       {[]byte{0x0f}, ErrHPACKTruncated},
	} {
		_, err := newHPACKDecoder(4096, 10).decode(tc.b)
		if !errors.Is(err, tc.err) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.err)
		}
	}
	// teto de campos
	fs, err := newHPACKDecoder(4096, 2).decode([]byte{0x82, 0x84, 0x86})
	if !errors.Is(err, ErrHPACKFieldsLimit) || len(fs) != 2 {
		t.Fatalf("fields=%d err=%v", len(fs), err)
	}
}

// TestHPACKAgainstXNet codifica sequências de blocos com o encoder do x/net e confere nomes e valores com o
// decoder do x/net, inclusive a tabela dinâmica ao longo de vários blocos.
func TestHPACKAgainstXNet(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	enc.SetMaxDynamicTableSizeLimit(256)
	enc.SetMaxDynamicTableSize(256)
	ref := hpack.NewDecoder(4096, nil)
	mine := newHPACKDecoder(4096, 1000)
	for i := range 50 {
		buf.Reset()
		fields := []hpack.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":authority", Value: fmt.Sprintf("h%d.example", i%7)},
			{Name: ":path", Value: fmt.Sprintf("/p/%d", i)},
			{Name: "x-long", Value: string(bytes.Repeat([]byte{'v'}, i*3))},
			{Name: "authorization", Value: "secret", Sensitive: true},
			{Name: fmt.Sprintf("x-n%d", i%5), Value: "\x00\xff binário"},
		}
		for _, f := range fields {
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		want, err := ref.DecodeFull(buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		got, err := mine.decode(buf.Bytes())
		if err != nil {
			t.Fatalf("bloco %d: %v", i, err)
		}
		if len(got) != len(want) {
			t.Fatalf("bloco %d: %d campos, x/net %d", i, len(got), len(want))
		}
		for j := range got {
			if got[j].Name != want[j].Name || got[j].Value != want[j].Value {
				t.Fatalf("bloco %d campo %d: %q=%q, x/net %q=%q", i, j, got[j].Name, got[j].Value, want[j].Name, want[j].Value)
			}
			if want[j].Sensitive != (got[j].Repr == ReprLiteralNeverIndexed) {
				t.Fatalf("bloco %d campo %d: repr %s, sensitive %v", i, j, got[j].Repr, want[j].Sensitive)
			}
		}
	}
	if mine.maxSize != 256 {
		t.Fatalf("maxSize = %d", mine.maxSize)
	}
}
