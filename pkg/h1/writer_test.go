package h1

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

var update = flag.Bool("update", false, "regrava testdata/responses/*.golden")

// Respostas de referência em testdata/responses: o escritor tem de reproduzi-las byte a byte.
func TestWriterGolden(t *testing.T) {
	cases := []struct {
		name    string
		interim []Interim
		resp    Response
		body    string
	}{
		{
			name: "cl-exact-case",
			resp: Response{Status: 200, Framing: FramingContentLength, BodyLen: 5, Fields: []HeaderField{
				{"content-TYPE", "text/plain"}, {"X-Second", "b"}, {"x-first", "a"},
			}},
			body: "hello",
		},
		{
			name: "chunked-trailers",
			resp: Response{
				Status: 200, Framing: FramingChunked, ChunkSize: 4,
				Fields:   []HeaderField{{"Content-Type", "text/plain"}},
				Trailers: []HeaderField{{"X-Checksum", "abc"}, {"x-done", "1"}},
			},
			body: "0123456789",
		},
		{
			name: "close-http10",
			resp: Response{
				Version: "HTTP/1.0", Status: 200, Framing: FramingClose,
				Fields: []HeaderField{{"Connection", "close"}},
			},
			body: "until close",
		},
		{
			name:    "continue-and-early-hints",
			interim: []Interim{{Status: 100}, {Status: 103, Fields: []HeaderField{{"Link", "</s.css>; rel=preload"}}}},
			resp:    Response{Status: 204, Reason: "Nothing Here", Framing: FramingNone},
		},
		{
			name: "hsize-200",
			resp: Response{Status: 200, Framing: FramingContentLength, BodyLen: 2, HeadSize: 200},
			body: "ok",
		},
		{
			name: "explicit-content-length",
			resp: Response{
				Status: 599, Framing: FramingContentLength, BodyLen: 3,
				Fields: []HeaderField{{"CONTENT-LENGTH", "3"}, {"transfer-encoding", "identity"}},
			},
			body: "abc",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			w := NewResponseWriter(&out, 1<<20)
			if err := w.WriteResponse(c.interim, &c.resp, strings.NewReader(c.body)); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "responses", c.name+".golden")
			if *update {
				if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), want) {
				t.Fatalf("got\n%q\nwant\n%q", out.Bytes(), want)
			}
			s := w.Sent()
			if !bytes.Equal(s.Bytes, want) || s.Size != int64(len(want)) || s.Truncated {
				t.Fatalf("sent %+v", s)
			}
		})
	}
}

func TestWriterHeadSize(t *testing.T) {
	for _, n := range []int{100, 1000, 1 << 20} {
		r := Response{Status: 200, Framing: FramingContentLength, HeadSize: n}
		if h := r.Head(); len(h) != n {
			t.Errorf("hsize %d: got %d", n, len(h))
		}
	}
	// Teto menor que o cabeçalho natural: nenhum enchimento.
	r := Response{Status: 200, HeadSize: 10}
	if h := r.Head(); string(h) != "HTTP/1.1 200 OK\r\n\r\n" {
		t.Fatalf("%q", h)
	}
}

func TestWriterCaptureAndErrors(t *testing.T) {
	var out bytes.Buffer
	w := NewResponseWriter(&out, 10)
	r := Response{Status: 200, Framing: FramingContentLength, BodyLen: 100}
	if err := w.WriteResponse(nil, &r, strings.NewReader(strings.Repeat("x", 100))); err != nil {
		t.Fatal(err)
	}
	s := w.Sent()
	if len(s.Bytes) != 10 || !s.Truncated || s.Size != int64(out.Len()) {
		t.Fatalf("%+v", s)
	}
	w.Reset()
	if w.Sent().Size != 0 {
		t.Fatal("reset")
	}
	// Corpo curto.
	if err := w.WriteBody(&r, strings.NewReader("abc")); !errors.Is(err, ErrShortBody) {
		t.Fatal(err)
	}
	// BodyLen limita close e chunked.
	out.Reset()
	w = NewResponseWriter(&out, 0)
	if err := w.WriteBody(&Response{Framing: FramingClose, BodyLen: 3}, strings.NewReader("abcdef")); err != nil || out.String() != "abc" {
		t.Fatal(out.String())
	}
	if w.Sent().Bytes != nil || w.Sent().Truncated {
		t.Fatal("capture disabled")
	}
	out.Reset()
	if err := w.WriteBody(&Response{Framing: FramingChunked, BodyLen: 3}, strings.NewReader("abcdef")); err != nil ||
		out.String() != "3\r\nabc\r\n0\r\n\r\n" {
		t.Fatalf("%q", out.String())
	}
	// Corpo chunked vazio e pedaço padrão.
	out.Reset()
	if err := w.WriteBody(&Response{Framing: FramingChunked}, strings.NewReader("")); err != nil || out.String() != "0\r\n\r\n" {
		t.Fatalf("%q", out.String())
	}
	if err := w.WriteBody(&Response{Framing: "bogus"}, nil); !errors.Is(err, ErrBadTransferEncoding) {
		t.Fatal(err)
	}
	// Erros de leitura e de escrita são repassados.
	boom := errors.New("boom")
	for _, f := range []string{FramingContentLength, FramingClose, FramingChunked} {
		if err := w.WriteBody(&Response{Framing: f, BodyLen: 5}, iotest.ErrReader(boom)); !errors.Is(err, boom) {
			t.Errorf("%s: %v", f, err)
		}
	}
	fw := NewResponseWriter(failWriter{boom}, 10)
	if err := fw.WriteResponse([]Interim{{Status: 100}}, &Response{Status: 200}, nil); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if err := fw.WriteResponse(nil, &Response{Status: 200}, nil); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	for _, f := range []string{FramingContentLength, FramingChunked} {
		if err := fw.WriteBody(&Response{Framing: f, BodyLen: 1}, strings.NewReader("x")); !errors.Is(err, boom) {
			t.Errorf("%s: %v", f, err)
		}
	}
	// Escrita parcial: só o que saiu entra na captura.
	pw := NewResponseWriter(&partialWriter{n: 4}, 100)
	_ = pw.WriteHead(&Response{Status: 200})
	if string(pw.Sent().Bytes) != "HTTP" || pw.Sent().Size != 4 {
		t.Fatalf("%+v", pw.Sent())
	}
}

type failWriter struct{ err error }

func (f failWriter) Write([]byte) (int, error) { return 0, f.err }

type partialWriter struct{ n int }

func (p *partialWriter) Write(b []byte) (int, error) {
	if len(b) > p.n {
		return p.n, io.ErrShortWrite
	}
	return len(b), nil
}
