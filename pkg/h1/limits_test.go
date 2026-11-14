package h1

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// headWithFields monta um cabeçalho com n campos "aN: v".
func headWithFields(n int) string {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	for i := range n {
		b.WriteString("a" + strconv.Itoa(i) + ": v\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

// RF-10 (task 131): 1024 campos passam; o 1025º vira ErrHeadTooLarge sem ler o restante.
func TestReadHeadMaxFields(t *testing.T) {
	req, err := newReader(headWithFields(DefaultMaxFields)).ReadHead()
	if err != nil || req.FieldCount != DefaultMaxFields {
		t.Fatalf("1024 fields: %v %d", err, req.FieldCount)
	}
	raw := headWithFields(DefaultMaxFields+1) + strings.Repeat("z: 1\r\n", 1000)
	r := newReader(raw)
	req, err = r.ReadHead()
	if !errors.Is(err, ErrHeadTooLarge) || !req.HeadTooLarge || len(req.Fields) != DefaultMaxFields ||
		req.FieldCount != DefaultMaxFields {
		t.Fatalf("1025 fields: %v too_large=%v fields=%d", err, req.HeadTooLarge, len(req.Fields))
	}
	// Os bytes crus terminam no campo excedente: o restante não foi lido para o registro.
	if !strings.HasSuffix(string(req.RawHead), "a1024: v\r\n") || r.Consumed() >= int64(len(raw)) {
		t.Fatalf("raw head len %d consumed %d", len(req.RawHead), r.Consumed())
	}
	// O teto é configurável.
	r = newReader(headWithFields(3))
	r.MaxFields = 2
	if _, err := r.ReadHead(); !errors.Is(err, ErrHeadTooLarge) {
		t.Fatal(err)
	}
}

// RF-10 (task 131): 1 MiB de linhas "a:\n" não vira centenas de milhares de campos em memória.
func TestReadHeadManyFieldsAllocs(t *testing.T) {
	raw := "GET / HTTP/1.1\n" + strings.Repeat("a:\n", (DefaultMaxHeadBytes-20)/3) + "\n"
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	req, err := NewReader(bufio.NewReader(strings.NewReader(raw))).ReadHead()
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrHeadTooLarge) || !req.HeadTooLarge {
		t.Fatal(err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20+uint64(cap(req.RawHead)) {
		t.Fatalf("allocated %d bytes beyond raw head (%d)", got, cap(req.RawHead))
	}
}

// RF-10 (task 131): trailers acima de 1024 campos → ErrHeadTooLarge (400 no servidor); 1024 passam.
func TestTrailersMaxFields(t *testing.T) {
	trailers := func(n int) string {
		var b strings.Builder
		b.WriteString("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n")
		for i := range n {
			b.WriteString("t" + strconv.Itoa(i) + ": v\r\n")
		}
		b.WriteString("\r\n")
		return b.String()
	}
	req, err := newReader(trailers(DefaultMaxFields)).ReadRequest(BodyOptions{})
	if err != nil || len(req.Body.Trailers) != DefaultMaxFields {
		t.Fatalf("1024 trailers: %v", err)
	}
	req, err = newReader(trailers(DefaultMaxFields + 1)).ReadRequest(BodyOptions{})
	if !errors.Is(err, ErrHeadTooLarge) || len(req.Body.Trailers) != DefaultMaxFields {
		t.Fatalf("1025 trailers: %v %d", err, len(req.Body.Trailers))
	}
}

// naiveFold é o valor dobrado como a concatenação linha a linha o produzia (referência do valor literal).
func naiveFold(first string, conts, terms []string) string {
	v := first
	for i, c := range conts {
		v += termBytes(terms[i]) + c
	}
	return v
}

// task 132: 1 MiB de continuações obs-fold custa tempo linear e dá o mesmo valor literal.
func TestReadHeadObsFoldLinear(t *testing.T) {
	n := (DefaultMaxHeadBytes - 64) / 2
	raw := "GET / HTTP/1.1\r\nX: a\n" + strings.Repeat(" \n", n) + "\n"
	start := time.Now()
	req, err := newReader(raw).ReadHead()
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("obs-fold of 1 MiB took %v", d)
	}
	want := "a" + strings.Repeat("\n ", n)
	if req.FieldCount != 1 || req.Fields[0] != (Field{"X", ": ", want, TermLF}) {
		t.Fatalf("folded value len %d", len(req.Fields[0][2]))
	}
	// Terminadores mistos: mesmo valor da concatenação linha a linha.
	req, err = newReader("GET / HTTP/1.1\r\nX: a\r\n b\n\tc\r\n d\nY: z\r\n\r\n").ReadHead()
	if err != nil {
		t.Fatal(err)
	}
	v := naiveFold("a", []string{" b", "\tc", " d"}, []string{TermCRLF, TermLF, TermCRLF})
	if req.Fields[0] != (Field{"X", ": ", v, TermLF}) || req.Fields[1] != (Field{"Y", ": ", "z", TermCRLF}) {
		t.Fatalf("%q", req.Fields)
	}
}

// task 132: em erro no meio do cabeçalho, o campo parcial traz o valor dobrado já lido.
func TestReadHeadObsFoldPartialOnError(t *testing.T) {
	for name, raw := range map[string]string{
		"eof":       "GET / HTTP/1.1\r\nX: a\r\n b\r\n c\r\n",
		"malformed": "GET / HTTP/1.1\r\nX: a\r\n b\r\n c\r\nno colon\r\n\r\n",
	} {
		req, err := newReader(raw).ReadHead()
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if req.Fields[0] != (Field{"X", ": ", "a\r\n b\r\n c", TermCRLF}) {
			t.Fatalf("%s: %q", name, req.Fields[0])
		}
	}
	r := newReader("GET / HTTP/1.1\r\nX: a\r\n" + strings.Repeat(" b\r\n", 100))
	r.MaxHeadBytes = 100
	req, err := r.ReadHead()
	if !errors.Is(err, ErrHeadTooLarge) || !strings.HasPrefix(req.Fields[0][2], "a\r\n b\r\n b") {
		t.Fatalf("431: %v %q", err, req.Fields[0])
	}
}

// task 132: trailers com 1 MiB de continuações também em tempo linear, com o valor literal.
func TestTrailersObsFoldLinear(t *testing.T) {
	n := (DefaultMaxHeadBytes - 64) / 2
	raw := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nT: a\n" + strings.Repeat(" \n", n) + "\n"
	start := time.Now()
	req, err := newReader(raw).ReadRequest(BodyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("trailer obs-fold took %v", d)
	}
	if tr := req.Body.Trailers; len(tr) != 1 || tr[0] != (Field{"T", ": ", "a" + strings.Repeat("\n ", n), TermLF}) {
		t.Fatalf("trailers %d", len(tr))
	}
	// Erro no meio dos trailers: o parcial traz o valor dobrado.
	raw = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nT: a\r\n b\r\n"
	req, err = newReader(raw).ReadRequest(BodyOptions{})
	if err == nil || req.Body.Trailers[0] != (Field{"T", ": ", "a\r\n b", TermCRLF}) {
		t.Fatalf("%v %q", err, req.Body.Trailers)
	}
}

func BenchmarkReadHeadObsFold1MiB(b *testing.B) {
	raw := "GET / HTTP/1.1\r\nX: a\n" + strings.Repeat(" \n", (DefaultMaxHeadBytes-64)/2) + "\n"
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		if _, err := newReader(raw).ReadHead(); err != nil {
			b.Fatal(err)
		}
	}
}

// chunkedExtReader gera, sob demanda, um corpo chunked com n pedaços de 1 byte ("x") e extensão de extLen
// bytes cada, seguido do pedaço de tamanho 0.
type chunkedExtReader struct {
	n, extLen int
	i         int
	buf       []byte
	done      bool
}

func (c *chunkedExtReader) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		switch {
		case c.i < c.n:
			c.buf = append(c.buf, "1;"...)
			c.buf = append(c.buf, strings.Repeat("e", c.extLen-1)...)
			c.buf = append(c.buf, "\r\nx\r\n"...)
			c.i++
		case !c.done:
			c.buf = append(c.buf, "0\r\n\r\n"...)
			c.done = true
		default:
			return 0, io.EOF
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func chunkedRequest(n, extLen int) *Reader {
	head := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
	return NewReader(bufio.NewReader(io.MultiReader(strings.NewReader(head), &chunkedExtReader{n: n, extLen: extLen})))
}

// RF-03 (task 133): extensões somando mais de 256 KiB → lista prefixo, chunks_truncated, tamanho e SHA-256
// do corpo inteiro, e memória retida limitada.
func TestChunkedExtAggregateCap(t *testing.T) {
	const n, extLen = 4096, 63 << 10
	req, err := chunkedRequest(n, extLen).ReadRequest(BodyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b := req.Body
	sum := sha256.Sum256([]byte(strings.Repeat("x", n)))
	if !b.ChunksTruncated || b.Size != n || *b.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("truncated=%v size=%d", b.ChunksTruncated, b.Size)
	}
	total := 0
	for _, ch := range b.Chunks {
		if ch.Ext != nil {
			total += len(*ch.Ext)
		}
	}
	if total > maxChunkExtTotal || len(b.Chunks) != maxChunkExtTotal/extLen {
		t.Fatalf("ext total %d chunks %d", total, len(b.Chunks))
	}
	// Memória viva com a requisição retida: ordem de centenas de KiB, não os ~256 MiB recebidos.
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if ms.HeapAlloc > 32<<20 {
		t.Fatalf("heap %d after reading", ms.HeapAlloc)
	}
	runtime.KeepAlive(req)

	// Corpo chunked comum: até 4096 pedaços registrados (4095 de dados e o de tamanho 0), sem corte.
	req, err = chunkedRequest(DefaultMaxChunks-1, 8).ReadRequest(BodyOptions{})
	if err != nil || req.Body.ChunksTruncated || len(req.Body.Chunks) != DefaultMaxChunks {
		t.Fatalf("plain chunks: %v %v %d", err, req.Body.ChunksTruncated, len(req.Body.Chunks))
	}
	// Um a mais passa do teto de contagem: a lista continua prefixo.
	req, err = chunkedRequest(DefaultMaxChunks, 8).ReadRequest(BodyOptions{})
	if err != nil || !req.Body.ChunksTruncated || len(req.Body.Chunks) != DefaultMaxChunks {
		t.Fatalf("count cap: %v %v %d", err, req.Body.ChunksTruncated, len(req.Body.Chunks))
	}
}
