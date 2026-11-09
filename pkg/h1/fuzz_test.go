package h1

import (
	"bufio"
	"bytes"
	"errors"
	"testing"
)

// FuzzReadRequest lê requisições sucessivas de bytes arbitrários: nada de pânico, os bytes crus do
// cabeçalho são sempre um prefixo do que foi consumido e o teto do cabeçalho é respeitado.
func FuzzReadRequest(f *testing.F) {
	seeds := []string{
		"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
		"POST /x HTTP/1.0\nContent-Length: 3\n\nabc",
		"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;e=1\r\nhello\r\n0\r\nT: v\r\n\r\n",
		"GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\nGET /2 HTTP/1.1\r\n\r\n",
		"\r\nOPTIONS * HTTP/1.1\r\nUpgrade: h2c\r\nExpect: 100-continue\r\n\r\n",
		"CONNECT a:443 HTTP/1.1\r\nProxy-Authorization: Basic x\r\n\r\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(bufio.NewReaderSize(bytes.NewReader(data), 16))
		r.MaxHeadBytes = 4096
		for i := 0; i < 16; i++ {
			start := r.Consumed()
			req, err := r.ReadHead()
			if req != nil {
				if len(req.RawHead) > r.MaxHeadBytes || req.HeadSize != len(req.RawHead) {
					t.Fatalf("head size %d", len(req.RawHead))
				}
				if !bytes.HasPrefix(data[start:], req.RawHead) {
					t.Fatalf("raw head is not the input")
				}
				_ = DetectProxySignals(req, ProxyContext{Direct: true, SNI: "a"})
				_, _, _ = req.Framing()
			}
			if err != nil {
				return
			}
			if err := r.ReadBody(req, BodyOptions{RawMax: 64, MaxChunks: 8}); err != nil {
				return
			}
			if req.Body.Framing != FramingNone && req.Body.SHA256 == nil {
				t.Fatal("missing sha256")
			}
		}
	})
}

// FuzzChunked lê um corpo chunked arbitrário: sem pânico, tamanho decodificado nunca maior que o do fio e
// bytes crus sempre prefixo da entrada.
func FuzzChunked(f *testing.F) {
	for _, s := range []string{
		"5\r\nhello\r\n0\r\n\r\n",
		"0A ; a=1\r\n0123456789\n0;x\r\nT: 1\n\r\n",
		"ffffffffffffff\r\n",
		"1\r\nx\rX",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(bufio.NewReaderSize(bytes.NewReader(data), 16))
		req := &Request{}
		err := r.ReadBodyFraming(req, FramingChunked, -1, BodyOptions{RawMax: 1 << 20, MaxTrailerBytes: 4096})
		b := req.Body
		if b.Size > b.WireSize || b.WireSize > int64(len(data)) {
			t.Fatalf("size %d wire %d input %d", b.Size, b.WireSize, len(data))
		}
		if !bytes.HasPrefix(data, b.Raw) {
			t.Fatal("raw is not the input")
		}
		if err == nil && (len(b.Chunks) == 0 || b.Chunks[len(b.Chunks)-1].Size != 0) {
			t.Fatal("finished without last chunk")
		}
		if errors.Is(err, ErrHeadTooLarge) && len(b.Trailers) > 4096 {
			t.Fatal("trailers over limit")
		}
	})
}
