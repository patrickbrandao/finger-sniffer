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
	// A reserva acompanha a memória alocada (ADR 0036): cobre a capacidade de RawHead e as cópias.
	if !errors.Is(err, ErrHeadTooLarge) || !req.HeadTooLarge || cap(req.RawHead) > reserved || reserved > 3000 ||
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
	// Orçamento folgado: reserva a capacidade de RawHead, a linha de requisição, as cópias dos campos e as
	// fatias de campos do cabeçalho e dos trailers (ADR 0036); corpo e linhas de chunk não.
	head := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
	r = newReader(head + "3;e\r\nabc\r\n0\r\nT: 1\r\n\r\n")
	reserved = 0
	r.Reserve = func(n int) bool { reserved += n; return true }
	req, err = r.ReadRequest(BodyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := cap(req.RawHead) + len("POST / HTTP/1.1") + len("Transfer-Encoding: chunked") + 8*fieldSize +
		len("T: 1\r\n\r\n") + len("T: 1") + 8*fieldSize
	if reserved != want {
		t.Fatalf("reserved %d, want %d", reserved, want)
	}
}
