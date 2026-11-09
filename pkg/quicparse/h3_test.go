package quicparse

import (
	"errors"
	"slices"
	"testing"
)

func names(fs []QPACKField) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Name)
	}
	return out
}

// TestQPACKRFC: vetores da RFC 9204 apêndice B. B.1 só usa a tabela estática; nos de tabela dinâmica o que
// vem da tabela fica vazio e static=false.
func TestQPACKRFC(t *testing.T) {
	p, fs, err := DecodeFieldSection(unhex("0000510b2f696e6465782e68746d6c"), 0)
	if err != nil || p.EncodedRequiredInsertCount != 0 || len(fs) != 1 {
		t.Fatal(err, fs)
	}
	f := fs[0]
	if f.Name != ":path" || f.Value != "/index.html" || f.Repr != ReprLiteralNameRef || !*f.Static || *f.Index != 1 ||
		*f.NeverIndexed || *f.HuffmanValue || f.HuffmanName != nil {
		t.Fatalf("B.1: %+v", f)
	}

	// B.2, stream 4: Required Insert Count = 2 (codificado 3), Base = 0, dois indexados pós-base
	p, fs, err = DecodeFieldSection(unhex("03811011"), 0)
	if err != nil || p.EncodedRequiredInsertCount != 3 || !p.BaseSign || p.DeltaBase != 1 || len(fs) != 2 {
		t.Fatal(err, p, fs)
	}
	for i, f := range fs {
		if f.Repr != ReprIndexedPostBase || *f.Static || *f.Index != i || f.Name != "" {
			t.Fatalf("B.2 %d: %+v", i, f)
		}
	}

	// B.4: indexado dinâmico, indexado estático (:path /), indexado dinâmico
	_, fs, err = DecodeFieldSection(unhex("050080c181"), 0)
	if err != nil || len(fs) != 3 {
		t.Fatal(err, fs)
	}
	if fs[0].Repr != ReprIndexed || *fs[0].Static || fs[1].Name != ":path" || fs[1].Value != "/" || !*fs[1].Static ||
		*fs[2].Index != 1 || fs[0].HuffmanValue != nil {
		t.Fatalf("B.4: %+v", fs)
	}

	// literal com nome literal (N=1, Huffman no valor), literal pós-base, Huffman no nome
	// "www.example.com" em Huffman (RFC 7541 C.4.1)
	b := append([]byte{0, 0, 0x30 | 3, 'f', 'o', 'o', 0x80 | 12}, unhex("f1e3c2e5f23a6ba0ab90f4ff")...)
	_, fs, err = DecodeFieldSection(b, 0)
	if err != nil || fs[0].Repr != ReprLiteral || !*fs[0].NeverIndexed || *fs[0].HuffmanName || !*fs[0].HuffmanValue ||
		fs[0].Name != "foo" || fs[0].Value != "www.example.com" || fs[0].Static != nil || fs[0].Index != nil {
		t.Fatalf("literal: %+v %v", fs, err)
	}
	_, fs, err = DecodeFieldSection([]byte{0, 0, 0x08 | 2, 3, 'a', 'b', 'c', 0x28 | 2, 0x8c, 0xf1, 0x00}, 0)
	if !errors.Is(err, ErrQPACKHuffman) || len(fs) != 1 || fs[0].Repr != ReprLiteralPostBaseNameRef ||
		*fs[0].Static || !*fs[0].NeverIndexed || fs[0].Value != "abc" || *fs[0].Index != 2 {
		t.Fatalf("pós-base: %+v %v", fs, err)
	}
}

func TestQPACKErrors(t *testing.T) {
	for name, c := range map[string]struct {
		b   []byte
		err error
	}{
		"vazio":           {nil, ErrQPACKTruncated},
		"sem-base":        {[]byte{0}, ErrQPACKTruncated},
		"estatico-99":     {[]byte{0, 0, 0xff, 0x24}, ErrQPACKIndex},
		"nome-ref-99":     {[]byte{0, 0, 0x5f, 0x54, 0}, ErrQPACKIndex},
		"inteiro":         {[]byte{0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, ErrQPACKInteger},
		"inteiro-cortado": {[]byte{0xff, 0xff}, ErrQPACKTruncated},
		"huffman":         {[]byte{0, 0, 0x50, 0x81, 0xff}, ErrQPACKHuffman},
		"string-cortada":  {[]byte{0, 0, 0x50, 0x05, 'a'}, ErrQPACKTruncated},
		"literal-nome":    {[]byte{0, 0, 0x27}, ErrQPACKTruncated},
		"indexado-cort":   {[]byte{0, 0, 0x3f}, ErrQPACKTruncated},
		"pos-base-cort":   {[]byte{0, 0, 0x1f}, ErrQPACKTruncated},
		"pos-nome-cort":   {[]byte{0, 0, 0x07}, ErrQPACKTruncated},
		"ref-cortado":     {[]byte{0, 0, 0x4f}, ErrQPACKTruncated},
		"base-cortada":    {[]byte{0, 0x7f}, ErrQPACKTruncated},
		"str-vazia":       {[]byte{0, 0, 0x51}, ErrQPACKTruncated},
	} {
		if _, _, err := DecodeFieldSection(c.b, 0); !errors.Is(err, c.err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, fs, err := DecodeFieldSection([]byte{0, 0, 0xd1, 0xd1, 0xd1}, 2)
	if !errors.Is(err, ErrQPACKFieldsLimit) || len(fs) != 2 {
		t.Fatal(err, fs)
	}
	if _, _, ok := QPACKStatic(99); ok {
		t.Fatal("índice 99")
	}
	if n, v, ok := QPACKStatic(98); !ok || n != "x-frame-options" || v != "sameorigin" {
		t.Fatal(n, v)
	}
}

// TestChromeHeaders: HEADERS real do Chrome 107 (pcap da FoxIO com segredos, decifrado pelo tshark).
func TestChromeHeaders(t *testing.T) {
	p, fs, err := DecodeFieldSection(readHex(t, "h3-chrome-foxio-headers.hex"), 0)
	if err != nil || p.EncodedRequiredInsertCount != 0 {
		t.Fatal(err, p)
	}
	want := []string{
		":method", ":authority", ":scheme", ":path", "pragma", "cache-control", "sec-ch-ua",
		"sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language",
	}
	if !slices.Equal(names(fs), want) {
		t.Fatalf("nomes\n got %v\nwant %v", names(fs), want)
	}
	if fs[0].Repr != ReprIndexed || fs[0].Value != "GET" || fs[1].Value != "cloudflare-quic.com" ||
		fs[10].Value != "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "+
			"Chrome/107.0.0.0 Safari/537.36" || fs[16].Value != "gzip, deflate, br" {
		t.Fatalf("%+v", fs[:2])
	}
	s := NewUniStream()
	set := readHex(t, "h3-chrome-foxio-settings.hex")
	s.Feed(AppendVarint(AppendVarint([]byte{StreamTypeControl}, H3FrameSettings), uint64(len(set))))
	s.Feed(set)
	if !s.SettingsSeen || s.Err() != nil || s.Settings[0] != [2]uint64{SettingQPACKMaxTableCapacity, 65536} ||
		s.Settings[1] != [2]uint64{SettingMaxFieldSectionSize, 262144} {
		t.Fatalf("%v %v", s.Settings, s.Err())
	}
	var grease bool
	for _, st := range s.Settings {
		grease = grease || IsGREASEH3(st[0])
	}
	if !grease {
		t.Fatalf("SETTINGS do Chrome sem GREASE: %v", s.Settings)
	}
}

// TestCurlStreams: stream de requisição e stream de controle reais do curl 8.23 (ngtcp2 1.26, nghttp3 1.19),
// entregues byte a byte.
func TestCurlStreams(t *testing.T) {
	raw := readHex(t, "h3-curl-request.hex")
	r := NewRequestStream(0, 0)
	for i := range raw {
		r.Feed(raw[i : i+1])
	}
	req := r.Request
	if r.Err() != nil || !r.HeadersSeen ||
		!slices.Equal(req.PseudoOrder, []string{":method", ":scheme", ":authority", ":path"}) {
		t.Fatalf("%v %v", r.Err(), req.PseudoOrder)
	}
	if !slices.Equal(names(req.Fields), []string{
		":method", ":scheme", ":authority", ":path", "user-agent", "accept",
		"x-test",
	}) || req.Fields[3].Value != "/p/curltest/?status=200" || req.Fields[6].Value != "abc" ||
		req.HeadFields != 7 || req.Fields[6].Repr != ReprLiteral {
		t.Fatalf("%+v", req.Fields)
	}

	ctl := readHex(t, "h3-curl-control.hex")
	u := NewUniStream()
	for i := range ctl {
		u.Feed(ctl[i : i+1])
	}
	if !u.Typed || u.StreamType != StreamTypeControl || u.Bytes != int64(len(ctl)) ||
		!slices.Equal(u.Settings, [][2]uint64{{6, MaxVarint}, {1, 0}, {7, 0}}) {
		t.Fatalf("%+v", u)
	}
}

func h3frame(t uint64, p []byte) []byte {
	b := AppendVarint(nil, t)
	b = AppendVarint(b, uint64(len(p)))
	return append(b, p...)
}

func TestRequestStream(t *testing.T) {
	head := []byte{0, 0, 0xd1, 0xd7, 0xc1}  // GET https /
	trail := []byte{0, 0, 0x5f, 0x1d, 0x00} // user-agent "" como trailer (só para teste)
	b := h3frame(H3FrameHeaders, head)
	b = append(b, h3frame(0x21, []byte("grease"))...)
	b = append(b, h3frame(H3FrameData, make([]byte, 1000))...)
	b = append(b, h3frame(0x02, nil)...)
	b = append(b, h3frame(H3FrameData, make([]byte, 5))...)
	b = append(b, h3frame(H3FrameHeaders, trail)...)
	r := NewRequestStream(4, 0)
	r.Feed(b[:3])
	r.Feed(b[3:700])
	r.Feed(b[700:])
	q := r.Request
	if q.StreamID != 4 || q.BodyLen != 1005 || q.UnknownFrames != 2 || q.GREASEFrames != 1 || len(q.Fields) != 4 ||
		q.HeadFields != 3 || !slices.Equal(q.Frames, []uint64{1, 0x21, 0, 2, 0, 1}) {
		t.Fatalf("%+v", q)
	}

	// teto de campos
	r = NewRequestStream(0, 2)
	r.Feed(slices.Concat(h3frame(H3FrameHeaders, head), h3frame(H3FrameHeaders, trail)))
	if !r.Request.FieldsTruncated || len(r.Request.Fields) != 2 {
		t.Fatalf("%+v", r.Request)
	}
	// QPACK ilegível
	r = NewRequestStream(0, 0)
	r.Feed(h3frame(H3FrameHeaders, []byte{0, 0, 0xff, 0x24}))
	if !errors.Is(r.Err(), ErrQPACKIndex) {
		t.Fatal(r.Err())
	}
	// HEADERS acima do teto do buffer
	r = NewRequestStream(0, 0)
	r.Feed(AppendVarint(AppendVarint(nil, H3FrameHeaders), DefaultMaxFrameBuffer+1))
	if !errors.Is(r.Err(), ErrH3FrameTooLarge) {
		t.Fatal(r.Err())
	}
}

func TestUniStream(t *testing.T) {
	// tipo de stream em varint de 2 bytes (GREASE 0x21+0x1f*N exige isso para N grande) entregue cortado
	u := NewUniStream()
	gt := AppendVarint(nil, 0x21+0x1f*3)
	u.Feed(gt[:1])
	u.Feed(append(gt[1:], 1, 2, 3))
	if !u.Typed || !IsGREASEH3(u.StreamType) || u.Bytes != 5 || u.Err() != nil {
		t.Fatalf("%+v", u)
	}
	// controle com SETTINGS, GOAWAY, SETTINGS repetido e frame desconhecido
	u = NewUniStream()
	var s []byte
	for i := range DefaultMaxSettings + 2 {
		s = AppendVarint(s, uint64(i+0x21))
		s = AppendVarint(s, 1)
	}
	u.Feed(slices.Concat([]byte{0}, h3frame(H3FrameSettings, s), h3frame(H3FrameGoaway, []byte{8}),
		h3frame(H3FrameSettings, []byte{1, 1}), h3frame(0x99, []byte{1})))
	if !u.SettingsSeen || !u.SettingsTruncated || len(u.Settings) != DefaultMaxSettings || u.Goaway == nil ||
		*u.Goaway != 8 || !slices.Equal(u.Frames, []uint64{4, 7, 4, 0x99}) {
		t.Fatalf("%+v", u)
	}
	u = NewUniStream()
	u.Feed(slices.Concat([]byte{0}, h3frame(H3FrameSettings, []byte{1})))
	if !errors.Is(u.Err(), ErrH3Settings) {
		t.Fatal(u.Err())
	}
	u = NewUniStream()
	u.Feed([]byte{StreamTypeQPACKEncoder, 0x3f, 0xbd, 0x01})
	if u.StreamType != StreamTypeQPACKEncoder || len(u.Frames) != 0 || u.Bytes != 4 {
		t.Fatalf("%+v", u)
	}
	for ft, n := range map[uint64]string{
		0: "DATA", 1: "HEADERS", 3: "CANCEL_PUSH", 4: "SETTINGS", 5: "PUSH_PROMISE",
		7: "GOAWAY", 0x0d: "MAX_PUSH_ID", 0x21: "GREASE", 0x40: "GREASE", 0x41: "0x41",
	} {
		if H3FrameName(ft) != n {
			t.Errorf("%d: %s", ft, H3FrameName(ft))
		}
	}
}
