package h1

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// chunkedReq monta uma requisição chunked com n pedaços de 1 byte (com a extensão ext em cada um) e, com
// final, o pedaço de tamanho 0.
func chunkedReq(n int, ext string, final bool) []byte {
	var b bytes.Buffer
	b.WriteString("POST /r HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	for range n {
		b.WriteString("1" + ext + "\r\nX\r\n")
	}
	if final {
		b.WriteString("0\r\n\r\n")
	}
	return b.Bytes()
}

// TestChunkedAllocsPerByte (task 324, ADR 0070 item 5): 20 000 pedaços de 1 byte alocam menos de 64 bytes por
// byte recebido (antes, 32 KiB por pedaço: ~5,4 KB por byte), com tamanho e SHA-256 certos.
func TestChunkedAllocsPerByte(t *testing.T) {
	raw := chunkedReq(20000, "", true)
	var ms0, ms1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms0)
	rd := NewReader(bufio.NewReaderSize(bytes.NewReader(raw), 16<<10))
	req, err := rd.ReadHead()
	if err != nil {
		t.Fatal(err)
	}
	if err := rd.ReadBody(req, BodyOptions{}); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&ms1)
	perByte := float64(ms1.TotalAlloc-ms0.TotalAlloc) / float64(len(raw))
	t.Logf("%.1f bytes alocados por byte recebido, %d alocações", perByte, ms1.Mallocs-ms0.Mallocs)
	if perByte >= 64 {
		t.Fatalf("%.1f bytes por byte", perByte)
	}
	sum := sha256.Sum256(bytes.Repeat([]byte("X"), 20000))
	if req.Body.Size != 20000 || *req.Body.SHA256 != hex.EncodeToString(sum[:]) || !req.Body.ChunksTruncated ||
		len(req.Body.Chunks) != DefaultMaxChunks {
		t.Fatalf("body %d %v %d", req.Body.Size, req.Body.ChunksTruncated, len(req.Body.Chunks))
	}
}

// TestBodyReserve (task 325, ADR 0070 item 7): o corpo guardado reserva pelo ReserveBody; sem orçamento, o
// leitor para de guardar e marca raw_truncated/chunks_truncated, sem erro, com tamanho e hash do corpo inteiro.
func TestBodyReserve(t *testing.T) {
	raw := chunkedReq(4095, ";name=value", true)
	read := func(reserve func(int) bool) *Body {
		rd := NewReader(bufio.NewReaderSize(bytes.NewReader(raw), 16<<10))
		rd.ReserveBody = reserve
		req, err := rd.ReadHead()
		if err != nil {
			t.Fatal(err)
		}
		if err := rd.ReadBody(req, BodyOptions{}); err != nil {
			t.Fatal(err)
		}
		return req.Body
	}
	var asked int
	full := read(func(n int) bool { asked += n; return true })
	if full.RawTruncated || full.ChunksTruncated || len(full.Chunks) != 4096 || asked < len(full.Raw) {
		t.Fatalf("full: raw %d/%v chunks %d/%v asked %d", len(full.Raw), full.RawTruncated,
			len(full.Chunks), full.ChunksTruncated, asked)
	}
	budget := 8 << 10
	cut := read(func(n int) bool {
		if n > budget {
			return false
		}
		budget -= n
		return true
	})
	if !cut.RawTruncated || !cut.ChunksTruncated || len(cut.Chunks) == 0 || len(cut.Chunks) >= 4096 ||
		cut.Size != 4095 || *cut.SHA256 != *full.SHA256 || !bytes.HasPrefix(full.Raw, cut.Raw) {
		t.Fatalf("cut: raw %d/%v chunks %d/%v size %d", len(cut.Raw), cut.RawTruncated,
			len(cut.Chunks), cut.ChunksTruncated, cut.Size)
	}
	for i, ch := range cut.Chunks {
		if ch.SizeLiteral != "1" || ch.Ext == nil || *ch.Ext != ";name=value" {
			t.Fatalf("chunk %d %+v", i, ch)
		}
	}
}

// TestChunkLineLongerThanBuffer: a linha de tamanho maior que o bufio (extensão de 40 KiB) segue lida inteira.
func TestChunkLineLongerThanBuffer(t *testing.T) {
	ext := ";" + strings.Repeat("e", 40<<10)
	raw := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3" + ext + "\r\nabc\r\n0\r\n\r\n"
	rd := NewReader(bufio.NewReaderSize(strings.NewReader(raw), 16<<10))
	req, err := rd.ReadHead()
	if err != nil {
		t.Fatal(err)
	}
	if err := rd.ReadBody(req, BodyOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(req.Body.Chunks) != 2 || *req.Body.Chunks[0].Ext != ext || req.Body.Size != 3 ||
		rd.Consumed() != int64(len(raw)) {
		t.Fatalf("%+v consumed %d", req.Body, rd.Consumed())
	}
}

// maxWriter conta o maior Write recebido e guarda os bytes.
type maxWriter struct {
	buf bytes.Buffer
	max int
}

func (w *maxWriter) Write(p []byte) (int, error) {
	w.max = max(w.max, len(p))
	return w.buf.Write(p)
}

// TestWriterChunkCap (task 326, ADR 0070 item 4): chunked com ChunkSize de 1 MiB e corpo de 4 MiB, e
// HeadSize de 1 MiB, não passam de 32 KiB + enquadramento por Write e os bytes são os de sempre.
func TestWriterChunkCap(t *testing.T) {
	const size, chunk = 4 << 20, 1 << 20
	body := bytes.Repeat([]byte("0123456789abcdef"), size/16)
	var want bytes.Buffer
	for off := 0; off < size; off += chunk {
		want.WriteString(strconv.FormatInt(chunk, 16) + "\r\n")
		want.Write(body[off : off+chunk])
		want.WriteString("\r\n")
	}
	want.WriteString("0\r\n\r\n")
	r := &Response{Status: 200, Framing: FramingChunked, BodyLen: size, ChunkSize: chunk}
	var w maxWriter
	if err := NewResponseWriter(&w, 0).WriteBody(r, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if w.max > maxWriteChunk+20 || !bytes.Equal(w.buf.Bytes(), want.Bytes()) {
		t.Fatalf("max write %d, equal %v", w.max, bytes.Equal(w.buf.Bytes(), want.Bytes()))
	}

	h := &Response{Status: 200, Framing: FramingContentLength, BodyLen: 0, HeadSize: 1 << 20}
	var hw maxWriter
	if err := NewResponseWriter(&hw, 0).WriteHead(h); err != nil {
		t.Fatal(err)
	}
	if hw.max > maxWriteChunk || hw.buf.Len() != 1<<20 || !bytes.Equal(hw.buf.Bytes(), h.Head()) {
		t.Fatalf("head max write %d len %d", hw.max, hw.buf.Len())
	}
	// Corpo mais curto que BodyLen no modo de pedaços grandes: erro, sem pedaço final.
	var sw maxWriter
	err := NewResponseWriter(&sw, 0).WriteBody(r, bytes.NewReader(body[:chunk/2]))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short body: %v", err)
	}
}
