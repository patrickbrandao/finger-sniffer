package bot

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/agg"
	"github.com/patrickbrandao/finger-sniffer/internal/bot/lists"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// fakeResolver confirma qualquer IP como crawl.googlebot.com (reverso e direto), sem rede.
type fakeResolver struct{}

func (fakeResolver) LookupAddr(context.Context, string) ([]string, error) {
	return []string{"crawl-1.googlebot.com."}, nil
}

func (fakeResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("198.51.100.7")}}, nil
}

// shortWaits encurta os prazos da CLI e o ciclo dos pedidos no teste.
func shortWaits(t *testing.T, forget, refresh time.Duration) {
	t.Helper()
	of, or, op := forgetWait, refreshWait, controlPoll
	forgetWait, refreshWait, controlPoll = forget, refresh, 10*time.Millisecond
	t.Cleanup(func() { forgetWait, refreshWait, controlPoll = of, or, op })
}

// runLoops roda os ciclos do serviço (pedidos da CLI a cada 20 ms, flush a cada 30 ms) até o fim do teste.
func runLoops(t *testing.T, s *Server) {
	t.Helper()
	s.reloadEvery = 20 * time.Millisecond
	s.cfg.FlushInterval = 30 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.loops(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		s.bg.Wait()
	})
}

// TestForgetRunningService: critério 1 da task 283 — com o serviço rodando, `forget` apaga o IP do índice (as duas
// visões, com o veredito), dos agregados (acumulador ainda não gravado e cache de comportamento) e do cache de
// verificação de robô; nem a memória nem os flushes seguintes o trazem de volta; o outro IP fica intacto; o pedido
// concluído sai no expurgo depois de 24 h.
func TestForgetRunningService(t *testing.T) {
	shortWaits(t, 5*time.Second, 5*time.Second)
	db, path := testDB(t)
	clock := newFakeClock(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	s := New(testConfig(path), Deps{DB: db, Now: clock.Now, Resolver: fakeResolver{}})
	ctx := context.Background()
	gone, kept := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.7")
	const goneID, keptID = "01JC0X3K8V2T7Q9N4M6P1R5S8W", "01JC0X3K8V2T7Q9N4M6P1R5S8X"
	for _, c := range []struct {
		id string
		ip netip.Addr
	}{{goneID, gone}, {keptID, kept}} {
		if err := s.feed.Handle(storeMessage("opened", c.id, c.ip.String(), 40000)); err != nil {
			t.Fatal(err)
		}
		s.index.UpdateFork(c.id, clock.Now(), func(f *ForkConn) {
			f.SrcIP, f.SrcPort, f.DstPort, f.HasSrc = c.ip, 40000, 443, true
			f.LastVerdict, f.LastClass = []byte(`{"class":"bot"}`), ClassBot
		})
		s.agg.Observe(agg.Request{Time: clock.Now(), IP: c.ip, Site: "s.com", Path: "/", Class: agg.ClassBot, UAFamily: "curl"})
		if r, _ := s.lists.Verifier().Verify(ctx, "googlebot", c.ip); r != lists.VerifyPassed {
			t.Fatalf("verificação falsa de %s: %s", c.ip, r)
		}
	}
	if err := s.flushAgg(ctx); err != nil { // disco com os dois IPs; depois um acumulador novo só na memória
		t.Fatal(err)
	}
	clock.Advance(time.Minute)
	s.agg.Observe(agg.Request{Time: clock.Now(), IP: gone, Site: "s.com", Path: "/x", Class: agg.ClassBot, UAFamily: "curl"})
	rows := func(ip netip.Addr) (n int) {
		t.Helper()
		if err := db.QueryRow("SELECT count(*) FROM ip_hourly WHERE ip = ?", ipKey(ip)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if rows(gone) != 1 || rows(kept) != 1 {
		t.Fatal("flush inicial não gravou")
	}

	runLoops(t, s)
	var out, errOut bytes.Buffer
	if err := RunCLI(ctx, []string{"forget", "192.0.2.1"}, path, &out, &errOut, clock.Now()); err != nil {
		t.Fatalf("%v %s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "forgot 192.0.2.1/32: 1 aggregate rows deleted") ||
		!strings.Contains(out.String(), "service memory: reached (2 connections, 1 aggregate entries, 1 robot checks") {
		t.Fatalf("saída: %s", out.String())
	}
	check := func(when string) {
		t.Helper()
		now := clock.Now()
		if _, ok := s.index.StoreByID(goneID, now); ok {
			t.Errorf("%s: conexão do store no índice", when)
		}
		if _, ok := s.index.Fork(goneID, now); ok {
			t.Errorf("%s: conexão do fork (com veredito) no índice", when)
		}
		if s.agg.Query(gone, "s.com", now).Known {
			t.Errorf("%s: IP no cache de comportamento", when)
		}
		if _, _, ok := s.lists.Verifier().Cached("googlebot", gone); ok {
			t.Errorf("%s: IP no cache de verificação", when)
		}
		if rows(gone) != 0 {
			t.Errorf("%s: IP no disco", when)
		}
		if _, ok := s.index.StoreByID(keptID, now); !ok || !s.agg.Query(kept, "s.com", now).Known || rows(kept) != 1 {
			t.Errorf("%s: o outro IP saiu", when)
		}
		if _, _, ok := s.lists.Verifier().Cached("googlebot", kept); !ok {
			t.Errorf("%s: verificação do outro IP saiu", when)
		}
	}
	check("depois do forget")
	time.Sleep(150 * time.Millisecond) // alguns flushes de 30 ms
	check("depois dos flushes")

	var pending, done int
	_ = db.QueryRow("SELECT count(*) FILTER (WHERE done_at IS NULL), count(*) FILTER (WHERE done_at IS NOT NULL) FROM control_requests").Scan(&pending, &done)
	if pending != 0 || done != 1 {
		t.Fatalf("control_requests: %d pendentes, %d concluídos", pending, done)
	}
	clock.Advance(23 * time.Hour)
	s.purge(ctx)
	_ = db.QueryRow("SELECT count(*) FROM control_requests").Scan(&done)
	if done != 1 {
		t.Fatal("pedido concluído saiu antes de 24 h")
	}
	clock.Advance(2 * time.Hour)
	s.purge(ctx)
	_ = db.QueryRow("SELECT count(*) FROM control_requests").Scan(&done)
	if done != 0 {
		t.Fatal("pedido concluído ficou depois de 24 h")
	}
}

// TestForgetServiceStopped: sem o serviço a CLI apaga o disco, avisa que a memória não foi alcançada e sai 0; o
// pedido fica pendente e o serviço o executa quando volta. Prefixo inválido no pedido sai concluído com o erro.
func TestForgetServiceStopped(t *testing.T) {
	shortWaits(t, 100*time.Millisecond, time.Second)
	db, path := testDB(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	var out, errOut bytes.Buffer
	if err := RunCLI(ctx, []string{"forget", "2001:db8::/32"}, path, &out, &errOut, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "service memory: not reached within 100ms") {
		t.Fatalf("saída: %s", out.String())
	}
	bad := "nope"
	if _, err := insertControl(ctx, db, opForget, &bad, now); err != nil {
		t.Fatal(err)
	}
	s := New(testConfig(path), Deps{DB: db, Now: func() time.Time { return now }})
	s.handleControls(ctx)
	var pending int
	_ = db.QueryRow("SELECT count(*) FROM control_requests WHERE done_at IS NULL").Scan(&pending)
	var res string
	_ = db.QueryRow("SELECT result FROM control_requests WHERE arg = 'nope'").Scan(&res)
	if pending != 0 || !strings.Contains(res, `"error":"bot: invalid ip or prefix`) {
		t.Fatalf("pendentes %d, resultado %s", pending, res)
	}
}

// listsUpstream é o publicador falso da lista aws (TLS, como exige a ADR 0050 item 5); fail faz responder 500.
func listsUpstream(t *testing.T) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("lists", "testdata", "aws.json"))
	if err != nil {
		t.Fatal(err)
	}
	fail := &atomic.Bool{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, fail
}

// TestListsRefreshCLI: critério 2 da task 283 — `lists refresh aws` com o serviço rodando baixa a lista pelo
// serviço (httptest), troca a cópia e a CLI mostra o resultado; com a origem falhando a CLI mostra o erro e sai com
// erro; lista desconhecida também.
func TestListsRefreshCLI(t *testing.T) {
	shortWaits(t, time.Second, 5*time.Second)
	up, fail := listsUpstream(t)
	db, path := testDB(t)
	cfg := testConfig(path)
	cfg.ListsDir = t.TempDir()
	cfg.ListURLs = map[string]string{"aws": up.URL + "/ip-ranges.json"}
	clock := newFakeClock(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	s := New(cfg, Deps{DB: db, Now: clock.Now, ListsClient: up.Client(), Metrics: service.NewMetrics()})
	runLoops(t, s)
	entries := func() int {
		for _, l := range s.Lists().Status(clock.Now()) {
			if l.Name == "aws" {
				return l.Entries
			}
		}
		return -1
	}
	if entries() != 0 {
		t.Fatal("aws já carregada")
	}
	ctx := context.Background()
	var out, errOut bytes.Buffer
	if err := RunCLI(ctx, []string{"lists", "refresh", "aws"}, path, &out, &errOut, clock.Now()); err != nil {
		t.Fatalf("%v %s", err, out.String())
	}
	if out.String() != "aws: ok\n" || entries() != 3 {
		t.Fatalf("saída %q, entradas %d", out.String(), entries())
	}
	if m := s.Lists().Lookup(netip.MustParseAddr("203.0.113.200")); len(m) == 0 || m[0].List != "aws" {
		t.Fatalf("lista nova não vale: %v", m)
	}

	fail.Store(true)
	out.Reset()
	err := RunCLI(ctx, []string{"lists", "refresh", "aws"}, path, &out, &errOut, clock.Now())
	if !errors.Is(err, errRefreshFailed) || !strings.HasPrefix(out.String(), "aws: ") || strings.Contains(out.String(), "aws: ok") {
		t.Fatalf("falha: %v %q", err, out.String())
	}
	if entries() != 3 {
		t.Fatal("falha trocou a cópia válida")
	}
	out.Reset()
	if err := RunCLI(ctx, []string{"lists", "refresh", "nope"}, path, &out, &errOut, clock.Now()); !errors.Is(err, errRefreshFailed) ||
		!strings.Contains(out.String(), "nope: lists: unknown list") {
		t.Fatalf("lista desconhecida: %v %q", err, out.String())
	}
	for _, args := range [][]string{{"lists"}, {"lists", "reload"}, {"lists", "refresh", "a", "b"}} {
		if err := RunCLI(ctx, args, path, &out, &errOut, clock.Now()); !errors.Is(err, ErrUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// TestListsRefreshNoService: serviço parado — depois do prazo a CLI diz que o serviço não respondeu e sai com
// erro; o pedido velho, quando o serviço volta, sai como expirado sem baixar nada.
func TestListsRefreshNoService(t *testing.T) {
	shortWaits(t, time.Second, 100*time.Millisecond)
	db, path := testDB(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	var out, errOut bytes.Buffer
	err := RunCLI(ctx, []string{"lists", "refresh"}, path, &out, &errOut, now)
	if !errors.Is(err, errNoService) || !strings.Contains(err.Error(), "is finger-sniffer-bot running?") {
		t.Fatalf("%v", err)
	}
	up, _ := listsUpstream(t)
	cfg := testConfig(path)
	cfg.ListsDir = t.TempDir()
	s := New(cfg, Deps{DB: db, Now: func() time.Time { return now.Add(time.Second) }, ListsClient: up.Client()})
	s.handleControls(ctx)
	s.bg.Wait()
	var res string
	_ = db.QueryRow("SELECT result FROM control_requests WHERE done_at IS NOT NULL").Scan(&res)
	if res != `{"error":"expired"}` {
		t.Fatalf("resultado %q", res)
	}
}
