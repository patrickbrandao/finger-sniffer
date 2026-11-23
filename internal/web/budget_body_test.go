package web

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
)

// Testes da ADR 0070 nos caminhos do h1 e do sink: corpo em espera (task 325), buffers de saída (task 326) e
// reads_in (task 343).

// h1BodyReader prepara um leitor que já atendeu uma requisição pequena com corpo (o buffer de cópia, retenção
// fixa de 32 KiB, já existe) e tem em seguida a requisição big; a reserva do corpo vai para hold.
func h1BodyReader(t *testing.T, hold *budgetHold, big []byte) *h1.Reader {
	t.Helper()
	warm := "POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\nx"
	rd := h1.NewReader(bufio.NewReaderSize(io.MultiReader(strings.NewReader(warm), bytes.NewReader(big)), readBufSize))
	req, err := rd.ReadHead()
	if err != nil {
		t.Fatal(err)
	}
	if err := rd.ReadBody(req, h1.BodyOptions{}); err != nil {
		t.Fatal(err)
	}
	rd.ReserveBody = func(n int) bool { return hold.reserveQuiet(int64(n)) }
	return rd
}

// TestBudgetCoversH1Body (task 325, ADR 0070 item 7): corpo chunked parado com 4096 pedaços com extensão e
// corpo Content-Length parado com 128 KiB reservam ao menos 90% do que fica retido, e o contador volta a zero.
func TestBudgetCoversH1Body(t *testing.T) {
	var chunked bytes.Buffer
	chunked.WriteString("POST /r HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
	for range 4096 {
		chunked.WriteString("1;" + strings.Repeat("e", 61) + "\r\nX\r\n")
	}
	cl := append([]byte("POST /r HTTP/1.1\r\nContent-Length: 10000000\r\n\r\n"), bytes.Repeat([]byte("b"), 128<<10)...)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{{"chunked", chunked.Bytes()}, {"content-length", cl}} {
		t.Run(tc.name, func(t *testing.T) {
			b := newInputBudget(DefaultInputBudget, nil)
			hold := b.newHold(0)
			rd := h1BodyReader(t, hold, tc.raw)
			req, err := rd.ReadHead()
			if err != nil {
				t.Fatal(err)
			}
			before := heapInUse()
			// A conexão "para": o corpo não termina (EOF no meio), e o que foi lido fica guardado.
			if err := rd.ReadBody(req, h1.BodyOptions{}); err == nil {
				t.Fatal("want unexpected EOF")
			}
			retained := heapInUse() - before
			checkCoverage(t, "h1 body "+tc.name, hold.inUse(), retained)
			runtime.KeepAlive(req)
			runtime.KeepAlive(rd)
			hold.releaseAll()
			if b.inUse() != 0 {
				t.Fatalf("leftover %d", b.inUse())
			}
		})
	}
}

// TestH1BodyBudgetExhausted (task 325): com o orçamento esgotado, a requisição chunked é respondida e o
// evento sai com chunks_truncated e raw_truncated, sem contar recusa; o orçamento volta a zero.
func TestH1BodyBudgetExhausted(t *testing.T) {
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.InputBudget = 24 << 10 }})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	var req strings.Builder
	req.WriteString("POST /r HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	for range 4095 {
		req.WriteString("1;ext=value\r\nX\r\n")
	}
	req.WriteString("0\r\n\r\n")
	cl.send(req.String())
	if resp, _ := cl.response("POST"); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	ev := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0]
	body := ev.Payload["body"].(map[string]any)
	if body["chunks_truncated"] != true || body["raw_truncated"] != true || num(t, body["size"]) != 4095 {
		t.Fatalf("body chunks_truncated %v raw_truncated %v size %v", body["chunks_truncated"],
			body["raw_truncated"], body["size"])
	}
	if d := h.srv.metrics.Get(MetricInputBudgetDenied); d != 0 {
		t.Fatalf("denied %v", d)
	}
	_ = c.Close()
	waitBudgetZero(t, h)
}

// waitBudgetZero espera o orçamento do servidor voltar a zero.
func waitBudgetZero(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for h.srv.budget.inUse() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("budget in use %d", h.srv.budget.inUse())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// pipeConns abre n conexões net.Pipe no handle do servidor, manda req em cada uma e não lê nada: a resposta
// fica presa na escrita. Devolve o heap retido por conexão e a função que fecha as conexões.
func pipeConns(t *testing.T, h *harness, n int, req string) (perConn int64, closeAll func()) {
	t.Helper()
	before := heapInUse()
	clis := make([]net.Conn, n)
	for i := range clis {
		srvSide, cli := net.Pipe()
		clis[i] = cli
		go h.srv.handle(context.Background(), srvSide, time.Now())
		go func() { _, _ = io.WriteString(cli, req) }()
	}
	time.Sleep(300 * time.Millisecond)
	perConn = (heapInUse() - before) / int64(n)
	return perConn, func() {
		for _, c := range clis {
			_ = c.Close()
		}
	}
}

// TestControlOutputBuffersCapped (task 326, ADR 0070 item 4): conexões com hsize=1 MiB e chunk=1 MiB cujo
// cliente não lê retêm menos de 128 KiB de heap por conexão acima de uma resposta pequena também presa.
func TestControlOutputBuffersCapped(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	const n = 8
	base, closeBase := pipeConns(t, h, n, get("/r?size=1", "x"))
	closeBase()
	big, closeBig := pipeConns(t, h, n, get("/r?hsize=1048576&chunk=1048576&size=16777216", "x"))
	defer closeBig()
	t.Logf("por conexão: base %d, hsize/chunk %d", base, big)
	if big-base >= 128<<10 {
		t.Fatalf("retido %d bytes por conexão acima da base %d", big-base, base)
	}
}

// rawPipe abre uma conexão crua no handle do servidor por net.Pipe (cada Write vira uma leitura), manda
// reads escritas de 1 byte e devolve o heap retido pelas leituras depois da primeira e o evento raw.session.
func rawPipe(t *testing.T, h *harness, reads int) (retained int64, finish func() decoded) {
	t.Helper()
	srvSide, cli := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.srv.handle(context.Background(), srvSide, time.Now())
	}()
	if _, err := cli.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	before := heapInUse()
	for range reads - 1 {
		if _, err := cli.Write([]byte{'z'}); err != nil {
			t.Fatal(err)
		}
	}
	retained = heapInUse() - before
	return retained, func() decoded {
		_ = cli.Close()
		<-done
		return h.events.wait(t, event.SubjectWebRawSession, 0, 1)[0]
	}
}

// TestRawReadsRetention (task 343, ADR 0070 item 7): uma conexão crua com 8192 leituras retém no máximo
// 160 KiB de heap acima da linha de base (antes ~420 KiB, [2]any); com o orçamento esgotado a lista para nas
// 1024 entradas fixas com reads_in_truncated; o orçamento volta a zero no fim.
func TestRawReadsRetention(t *testing.T) {
	t.Run("retention", func(t *testing.T) {
		// Os fluxos stream.bytes (um por leitura) não vão ao coletor do teste, que os guardaria todos.
		h := newHarness(t, harnessOpts{deps: func(d *Deps) {
			pub := d.Publish
			d.Publish = func(m *nats.Msg) {
				if m.Subject != event.SubjectWebStreamBytes {
					pub(m)
				}
			}
		}})
		retained, finish := rawPipe(t, h, maxRawReads)
		t.Logf("retido %d bytes", retained)
		if retained > 160<<10 {
			t.Fatalf("retido %d bytes", retained)
		}
		rs := finish()
		reads := rs.Payload["reads_in"].([]any)
		if len(reads) != maxRawReads || num(t, reads[0].([]any)[1]) != 1 || rs.Payload["reads_in_truncated"] != false {
			t.Fatalf("reads_in %d truncated %v", len(reads), rs.Payload["reads_in_truncated"])
		}
		waitBudgetZero(t, h)
	})
	t.Run("budget-exhausted", func(t *testing.T) {
		h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.InputBudget = 1 }})
		_, finish := rawPipe(t, h, 2000)
		rs := finish()
		reads := rs.Payload["reads_in"].([]any)
		if len(reads) != rawReadsFixed || rs.Payload["reads_in_truncated"] != true {
			t.Fatalf("reads_in %d, want %d; truncated %v", len(reads), rawReadsFixed, rs.Payload["reads_in_truncated"])
		}
		waitBudgetZero(t, h)
	})
}
