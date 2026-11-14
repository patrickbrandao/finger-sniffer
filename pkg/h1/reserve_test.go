package h1

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

// task 155: Reserve que nega depois de N bytes encerra o cabeçalho com ErrHeadTooLarge e o que já foi
// guardado; nega já no primeiro pedaço ainda devolve a requisição (431, não fechamento silencioso).
func TestReadHeadReserve(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: h\r\nX-Big: " + strings.Repeat("a", 8000) + "\r\n\r\n"
	r := NewReader(bufio.NewReaderSize(strings.NewReader(raw), 1024))
	reserved := 0
	r.Reserve = func(n int) bool {
		if reserved+n > 3000 {
			return false
		}
		reserved += n
		return true
	}
	req, err := r.ReadHead()
	if !errors.Is(err, ErrHeadTooLarge) || !req.HeadTooLarge || len(req.RawHead) != reserved ||
		!strings.HasPrefix(raw, string(req.RawHead)) || req.RequestLine.Method != "GET" {
		t.Fatalf("%v too_large=%v raw=%d reserved=%d", err, req.HeadTooLarge, len(req.RawHead), reserved)
	}
	// Sem orçamento algum.
	r = newReader(raw)
	r.Reserve = func(int) bool { return false }
	req, err = r.ReadHead()
	if req == nil || !errors.Is(err, ErrHeadTooLarge) || !req.HeadTooLarge || len(req.RawHead) != 0 {
		t.Fatalf("no budget: %v %+v", err, req)
	}
	// Orçamento folgado: reserva exatamente os bytes do cabeçalho e dos trailers (corpo e linhas de chunk não).
	head := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
	r = newReader(head + "3;e\r\nabc\r\n0\r\nT: 1\r\n\r\n")
	reserved = 0
	r.Reserve = func(n int) bool { reserved += n; return true }
	if _, err := r.ReadRequest(BodyOptions{}); err != nil {
		t.Fatal(err)
	}
	if want := len(head) + len("T: 1\r\n\r\n"); reserved != want {
		t.Fatalf("reserved %d, want %d (head + trailers)", reserved, want)
	}
}
