package h1

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// Chunked com extensões e trailers, registrado pedaço a pedaço, lido byte a byte.
func TestChunkedExtensionsAndTrailers(t *testing.T) {
	head := "POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
	body := "5;name=val\r\nhello\r\n" +
		"0A ; a=1;b=\"x y\"\r\n0123456789\r\n" +
		"003\nabc\n" +
		"0;last\r\n" +
		"X-Checksum: abc\r\n" +
		"x-trailer:  two \n" +
		"  folded\r\n" +
		"\r\n"
	next := "GET /next HTTP/1.1\r\n\r\n"
	r := NewReader(bufio.NewReaderSize(iotest.OneByteReader(strings.NewReader(head+body+next)), 16))
	req, err := r.ReadRequest(BodyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b := req.Body
	if b.Framing != FramingChunked || b.Size != 18 {
		t.Fatalf("%+v", b)
	}
	sum := sha256.Sum256([]byte("hello0123456789abc"))
	if *b.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("sha256 of decoded content")
	}
	if string(b.Raw) != body || b.WireSize != int64(len(body)) || b.RawTruncated {
		t.Fatalf("raw %q", b.Raw)
	}
	ext := func(s string) *string { return &s }
	want := []Chunk{
		{5, "5", ext(";name=val")},
		{10, "0A", ext(" ; a=1;b=\"x y\"")},
		{3, "003", nil},
		{0, "0", ext(";last")},
	}
	if len(b.Chunks) != len(want) {
		t.Fatalf("chunks %+v", b.Chunks)
	}
	for i, c := range want {
		g := b.Chunks[i]
		if g.Size != c.Size || g.SizeLiteral != c.SizeLiteral || (g.Ext == nil) != (c.Ext == nil) || (g.Ext != nil && *g.Ext != *c.Ext) {
			t.Errorf("chunk %d: %+v", i, g)
		}
	}
	wantTr := []Field{{"X-Checksum", ": ", "abc", TermCRLF}, {"x-trailer", ":  ", "two \n  folded", TermCRLF}}
	if len(b.Trailers) != 2 || b.Trailers[0] != wantTr[0] || b.Trailers[1] != wantTr[1] {
		t.Fatalf("trailers %q", b.Trailers)
	}
	nxt, err := r.ReadHead()
	if err != nil || nxt.RequestLine.Target != "/next" || nxt.InOffset != int64(len(head+body)) {
		t.Fatalf("%v %+v", err, nxt)
	}
}

func TestChunkedLimits(t *testing.T) {
	body := strings.Repeat("1\r\nx\r\n", 10) + "0\r\n\r\n"
	r := NewReader(bufio.NewReader(strings.NewReader(body)))
	req := &Request{}
	if err := r.ReadBodyFraming(req, FramingChunked, -1, BodyOptions{RawMax: 8, MaxChunks: 3}); err != nil {
		t.Fatal(err)
	}
	if len(req.Body.Chunks) != 3 || !req.Body.ChunksTruncated || req.Body.Size != 10 ||
		len(req.Body.Raw) != 8 || !req.Body.RawTruncated {
		t.Fatalf("%+v", req.Body)
	}
	// RawMax < 0 não guarda bytes crus.
	r = NewReader(bufio.NewReader(strings.NewReader("abc")))
	if err := r.ReadBodyFraming(req, FramingContentLength, 3, BodyOptions{RawMax: -1}); err != nil || req.Body.Raw != nil {
		t.Fatal(err)
	}
	// Trailers acima do teto.
	r = NewReader(bufio.NewReader(strings.NewReader("0\r\nA: " + strings.Repeat("b", 100) + "\r\n\r\n")))
	if err := r.ReadBodyFraming(req, FramingChunked, -1, BodyOptions{MaxTrailerBytes: 20}); !errors.Is(err, ErrHeadTooLarge) {
		t.Fatal(err)
	}
}

func TestChunkedErrors(t *testing.T) {
	cases := []struct {
		in  string
		err error
	}{
		{"", io.ErrUnexpectedEOF},
		{"zz\r\n", ErrBadChunk},
		{"5x\r\nhello\r\n0\r\n\r\n", ErrBadChunk},
		{"1234567890abcdef\r\n", ErrBadChunk},
		{"5\r\nhel", io.ErrUnexpectedEOF},
		{"5\r\nhelloX\r\n", ErrBadChunk},
		{"5\r\nhello\rX", ErrBadChunk},
		{"5\r\nhello\r", io.ErrUnexpectedEOF},
		{"5\r\nhello", io.ErrUnexpectedEOF},
		{"0\r\n", io.ErrUnexpectedEOF},
		{"0\r\nbad\r\n\r\n", ErrMalformedField},
		{"0\r\n folded\r\n\r\n", ErrObsFoldFirst},
		{strings.Repeat("0", 70000) + "\r\n", ErrBadChunk},
	}
	for _, c := range cases {
		r := NewReader(bufio.NewReader(strings.NewReader(c.in)))
		req := &Request{}
		err := r.ReadBodyFraming(req, FramingChunked, -1, BodyOptions{})
		if !errors.Is(err, c.err) {
			t.Errorf("%.30q: want %v, got %v", c.in, c.err, err)
		}
	}
}

func TestFramingDecision(t *testing.T) {
	cases := []struct {
		fields  string
		framing string
		length  int64
		err     error
	}{
		{"", FramingNone, 0, nil},
		{"Content-Length: 10\r\n", FramingContentLength, 10, nil},
		{"Content-Length: 10, 10\r\nContent-Length: 10\r\n", FramingContentLength, 10, nil},
		{"Content-Length: 10\r\nContent-Length: 11\r\n", "", 0, ErrBadContentLength},
		{"Content-Length: -1\r\n", "", 0, ErrBadContentLength},
		{"Content-Length: \r\n", "", 0, ErrBadContentLength},
		{"Content-Length: 1234567890123456789\r\n", "", 0, ErrBadContentLength},
		{"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n", FramingChunked, -1, nil},
		{"Transfer-Encoding: gzip\r\nTransfer-Encoding: Chunked \r\n", FramingChunked, -1, nil},
		{"Transfer-Encoding: chunked, gzip\r\n", "", 0, ErrBadTransferEncoding},
	}
	for _, c := range cases {
		req, err := NewReader(bufio.NewReader(strings.NewReader("POST / HTTP/1.1\r\n" + c.fields + "\r\n"))).ReadHead()
		if err != nil {
			t.Fatal(err)
		}
		f, n, err := req.Framing()
		if f != c.framing || n != c.length || !errors.Is(err, c.err) {
			t.Errorf("%q: %s %d %v", c.fields, f, n, err)
		}
	}
	// ReadBody com enquadramento inválido registra corpo vazio e devolve o erro.
	r := NewReader(bufio.NewReader(strings.NewReader("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n")))
	req, err := r.ReadRequest(BodyOptions{})
	if !errors.Is(err, ErrBadTransferEncoding) || req.Body == nil || req.Body.Framing != FramingNone {
		t.Fatal(err)
	}
}

func TestContentLengthAndClose(t *testing.T) {
	r := NewReader(bufio.NewReader(strings.NewReader("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort")))
	req, err := r.ReadRequest(BodyOptions{})
	if !errors.Is(err, io.ErrUnexpectedEOF) || req.Body.Size != 5 {
		t.Fatal(err)
	}
	payload := strings.Repeat("z", 100000)
	r = NewReader(bufio.NewReader(strings.NewReader(payload)))
	req = &Request{}
	if err := r.ReadBodyFraming(req, FramingClose, -1, BodyOptions{}); err != nil {
		t.Fatal(err)
	}
	if req.Body.Size != 100000 || len(req.Body.Raw) != 100000 || req.Body.SHA256 == nil {
		t.Fatalf("%d", req.Body.Size)
	}
	// Teto padrão de 128 KiB nos bytes crus, mas tamanho e hash do corpo inteiro.
	payload = strings.Repeat("y", DefaultRawBodyMax+10)
	r = NewReader(bufio.NewReader(strings.NewReader(payload)))
	if err := r.ReadBodyFraming(req, FramingContentLength, int64(len(payload)), BodyOptions{}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(payload))
	if len(req.Body.Raw) != DefaultRawBodyMax || !req.Body.RawTruncated || *req.Body.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("raw cap")
	}
	if err := r.ReadBodyFraming(req, "bogus", 0, BodyOptions{}); !errors.Is(err, ErrBadTransferEncoding) {
		t.Fatal(err)
	}
	if err := r.ReadBodyFraming(req, FramingNone, 0, BodyOptions{}); err != nil || req.Body.SHA256 != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	r = NewReader(bufio.NewReader(iotest.ErrReader(boom)))
	if err := r.ReadBodyFraming(req, FramingClose, -1, BodyOptions{}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	r = NewReader(bufio.NewReader(iotest.ErrReader(boom)))
	if err := r.ReadBodyFraming(req, FramingChunked, -1, BodyOptions{}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	r = NewReader(bufio.NewReader(io.MultiReader(strings.NewReader("0\r\n"), iotest.ErrReader(boom))))
	if err := r.ReadBodyFraming(req, FramingChunked, -1, BodyOptions{}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}
