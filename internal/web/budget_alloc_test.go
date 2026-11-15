package web

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// heapInUse devolve o HeapAlloc depois de duas coletas (o lixo das alocações intermediárias sai da conta).
func heapInUse() int64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc) //nolint:gosec // HeapAlloc cabe em int64
}

// checkCoverage confere que a reserva cobre ao menos 90% da memória retida medida (ADR 0036 item 2).
func checkCoverage(t *testing.T, path string, reserved, retained int64) {
	t.Helper()
	ratio := float64(reserved) / float64(retained)
	t.Logf("%s: reservado %d, retido %d, cobertura %.1f%%", path, reserved, retained, 100*ratio)
	if retained <= 0 || ratio < 0.9 {
		t.Fatalf("%s: reservado %d < 90%% do retido %d", path, reserved, retained)
	}
}

// h1BigHead monta um cabeçalho HTTP/1 de exatamente size bytes em linhas de ~1,1 KiB.
func h1BigHead(size int) []byte {
	var b bytes.Buffer
	b.WriteString("GET /p/" + testProbe + "/ HTTP/1.1\r\nHost: " + testSNI + "\r\n")
	const line = 1126
	for i := 0; b.Len() < size-2; i++ {
		name := fmt.Sprintf("X-Pad-%04d: ", i)
		n := min(line, size-2-b.Len())
		if n < len(name)+3 {
			// sobra pequena: alonga o último valor em vez de abrir uma linha sem espaço para o nome
			name = "X: "
		}
		b.WriteString(name)
		b.WriteString(strings.Repeat("a", max(n-len(name)-2, 0)))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// TestBudgetCoversH1Head (task 215, ADR 0036): um cabeçalho h1 de 999 424 bytes em linhas de 1,1 KiB
// reserva ao menos 90% do que fica retido no heap (RawHead, cópias dos campos, fatia de campos) e o contador
// volta a zero ao devolver.
func TestBudgetCoversH1Head(t *testing.T) {
	raw := h1BigHead(999424)
	if len(raw) != 999424 {
		t.Fatalf("head %d bytes", len(raw))
	}
	b := newInputBudget(DefaultInputBudget, nil)
	hold := b.newHold(0)
	rd := h1.NewReader(bufio.NewReaderSize(bytes.NewReader(raw), readBufSize))
	rd.Reserve = func(n int) bool { return hold.reserve(int64(n)) }
	before := heapInUse()
	req, err := rd.ReadHead()
	retained := heapInUse() - before
	if err != nil || req.HeadSize != len(raw) {
		t.Fatalf("%v %d", err, req.HeadSize)
	}
	checkCoverage(t, "h1", hold.inUse(), retained)
	// A entrada fica viva até depois da medida (senão a coleta a solta e o retido sai subestimado).
	runtime.KeepAlive(req)
	runtime.KeepAlive(rd)
	runtime.KeepAlive(raw)
	hold.releaseAll()
	if b.inUse() != 0 {
		t.Fatalf("leftover %d", b.inUse())
	}
}

// TestBudgetCoversH3Headers (task 215, ADR 0036): um HEADERS h3 de ~1 MiB em espera (falta o último byte)
// reserva ao menos 90% do buffer retido, e o contador volta a zero ao devolver o Held.
func TestBudgetCoversH3Headers(t *testing.T) {
	const size = 1 << 20
	frame := append(quicparse.AppendH3FrameHeader(nil, quicparse.H3FrameHeaders, size), make([]byte, size-1)...)
	b := newInputBudget(DefaultInputBudget, nil)
	hold := b.newHold(h3HeadersConnMax)
	rs := quicparse.NewRequestStream(0, 0)
	rs.SetBudget(func(n int) bool { return hold.reserve(int64(n)) }, func(n int) { hold.release(int64(n)) })
	before := heapInUse()
	for p := frame; len(p) > 0; { // pedaços do tamanho de um pacote QUIC
		n := min(len(p), 1200)
		rs.Feed(p[:n])
		p = p[n:]
	}
	retained := heapInUse() - before
	if rs.Err() != nil || rs.HeadersSeen {
		t.Fatalf("%v %v", rs.Err(), rs.HeadersSeen)
	}
	checkCoverage(t, "h3", hold.inUse(), retained)
	runtime.KeepAlive(rs)
	runtime.KeepAlive(frame)
	hold.release(int64(rs.Held()))
	if b.inUse() != 0 {
		t.Fatalf("leftover %d", b.inUse())
	}
}

// TestBudgetCoversWSMessage (task 215, ADR 0036): a mensagem de 1 MiB − 64 que o wc.Read do coder/websocket
// junta (e que fica viva enquanto o eco espera) cabe na reserva de wsSessionBudget com ao menos 90% de
// cobertura.
func TestBudgetCoversWSMessage(t *testing.T) {
	got := make(chan []byte, 1)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wc, err := websocket.Accept(w, r, acceptOptions(r))
		if err != nil {
			return
		}
		defer func() { _ = wc.CloseNow() }()
		wc.SetReadLimit(wsReadLimit)
		_, data, err := wc.Read(r.Context())
		if err != nil {
			close(got)
			return
		}
		got <- data
		<-release
	}))
	defer ts.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()
	msg := bytes.Repeat([]byte{'m'}, wsReadLimit-64)
	before := heapInUse()
	if err := c.Write(ctx, websocket.MessageBinary, msg); err != nil {
		t.Fatal(err)
	}
	data := <-got
	retained := heapInUse() - before
	if len(data) != len(msg) {
		t.Fatalf("message %d bytes", len(data))
	}
	checkCoverage(t, "websocket", wsSessionBudget, retained)
	runtime.KeepAlive(data)
	runtime.KeepAlive(msg)
}

// TestTapPendingBudget (task 215, ADR 0036): o pendente do tap reserva a capacidade alocada e devolve ao
// publicar; sem orçamento publica na hora um pedaço menor que 64 KiB, não retém e não conta recusa.
func TestTapPendingBudget(t *testing.T) {
	m := service.NewMetrics()
	b := newInputBudget(MinInputBudget, m)
	var got []event.StreamBytes
	s := streamDir{dir: event.DirectionIn, max: 1 << 30, budget: b, emit: func(e event.StreamBytes) { got = append(got, e) }}

	s.add(make([]byte, 1000))
	if len(got) != 0 || b.inUse() != int64(cap(s.pending)) || b.tapInUse() != b.inUse() || cap(s.pending) < 1000 {
		t.Fatalf("pending: events %d in use %d cap %d", len(got), b.inUse(), cap(s.pending))
	}
	s.flush()
	if len(got) != 1 || len(got[0].Data) != 1000 || b.inUse() != 0 || s.pending != nil {
		t.Fatalf("flush: events %d in use %d", len(got), b.inUse())
	}

	// Orçamento esgotado por outro caminho: o pedaço sai na hora, menor que 64 KiB, sem reter.
	if !b.reserve(MinInputBudget) {
		t.Fatal("reserve all")
	}
	denied := m.Get(MetricInputBudgetDenied)
	s.add(make([]byte, 3000))
	if len(got) != 2 || got[1].Offset != 1000 || len(got[1].Data) != 3000 || s.pending != nil || s.held != 0 {
		t.Fatalf("no budget: events %d pending %d held %d", len(got), len(s.pending), s.held)
	}
	if m.Get(MetricInputBudgetDenied) != denied || b.tapInUse() != 0 {
		t.Fatalf("denied %v→%v tap %d", denied, m.Get(MetricInputBudgetDenied), b.tapInUse())
	}
	b.release(MinInputBudget)

	// Um pedaço inteiro chega e sai direto; o resto fica pendente com a reserva e volta no fim.
	s.add(make([]byte, event.StreamChunkBytes+10))
	if len(got) != 3 || len(got[2].Data) != event.StreamChunkBytes || got[2].Offset != 4000 || len(s.pending) != 10 {
		t.Fatalf("chunk: events %d pending %d", len(got), len(s.pending))
	}
	s.flush()
	if b.inUse() != 0 || got[3].Offset != 4000+event.StreamChunkBytes {
		t.Fatalf("end: in use %d offset %d", b.inUse(), got[3].Offset)
	}
}

// TestWSBudgetDefault503 (task 215, ADR 0036): com orçamento de 24 MiB (o padrão até a ADR 0039; com os 192 MiB
// de hoje o teto de 32 sessões vem antes) e 2 MiB por sessão, no máximo 12 sessões recebem 101; a seguinte
// recebe 503 antes do 101 (resposta normal, a conexão segue) e conta como recusa.
func TestWSBudgetDefault503(t *testing.T) {
	const budget = 24 << 20
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.InputBudget = budget }})
	opened := 0
	for opened < 13 {
		cl := newClient(t, dial(t, h.addr80))
		cl.send(wsUpgradeRaw())
		resp, _ := cl.response("GET")
		if resp.StatusCode != http.StatusSwitchingProtocols {
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("after %d sessions: status %d", opened, resp.StatusCode)
			}
			break
		}
		opened++
	}
	// O pendente do tap da própria conexão do Upgrade também reserva: a 12ª pode já não caber.
	if opened < 11 || opened > 12 {
		t.Fatalf("sessions with 101: %d", opened)
	}
	if h.srv.metrics.Get(MetricInputBudgetDenied) < 1 || h.srv.budget.inUse() > budget {
		t.Fatalf("denied %v in use %d", h.srv.metrics.Get(MetricInputBudgetDenied), h.srv.budget.inUse())
	}
	// A 13ª, com as abertas ainda de pé, também recebe 503.
	cl := newClient(t, dial(t, h.addr80))
	cl.send(wsUpgradeRaw())
	if resp, _ := cl.response("GET"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("13th status %d", resp.StatusCode)
	}
}

// TestQUICReceiveWindows (task 215, ADR 0036): tetos das janelas de recepção do quic-go em 2 MiB (stream) e
// 4 MiB (conexão); as iniciais ficam no padrão (zero), para os transport parameters não mudarem.
func TestQUICReceiveWindows(t *testing.T) {
	s := &Server{cfg: Config{IdleDefault: time.Second}}
	qc := s.quicConfig()
	if qc.MaxStreamReceiveWindow != 2<<20 || qc.MaxConnectionReceiveWindow != 4<<20 ||
		qc.InitialStreamReceiveWindow != 0 || qc.InitialConnectionReceiveWindow != 0 {
		t.Fatalf("%+v", qc)
	}
}

// TestHTTP1ReadBuffer (task 215, ADR 0036): o bufio do HTTP/1 por conexão é de 16 KiB.
func TestHTTP1ReadBuffer(t *testing.T) {
	if readBufSize != 16<<10 {
		t.Fatalf("readBufSize %d", readBufSize)
	}
}
