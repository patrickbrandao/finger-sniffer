package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// counter é um registro de métricas falso.
type counter struct {
	mu   sync.Mutex
	vals map[string]float64
}

func newCounter() *counter { return &counter{vals: map[string]float64{}} }

func (c *counter) Add(name string, d float64) {
	c.mu.Lock()
	c.vals[name] += d
	c.mu.Unlock()
}

func (c *counter) Get(name string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.vals[name]
}

// fakeAfter registra as esperas pedidas e dispara na hora.
type fakeAfter struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (f *fakeAfter) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	f.delays = append(f.delays, d)
	f.mu.Unlock()
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

func (f *fakeAfter) Delays() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.delays...)
}

type received struct {
	header http.Header
	body   []byte
}

var testSecret = []byte("0123456789abcdef0123456789abcdef")

// newDispatcher cria o despachante apontado para srv (cliente que confia no certificado do httptest).
func newDispatcher(t *testing.T, srv *httptest.Server, now func() time.Time) (*Dispatcher, *counter, *fakeAfter, context.Context) {
	t.Helper()
	c, fa := newCounter(), &fakeAfter{}
	d := New(Options{Client: srv.Client(), Now: now, After: fa.After, Count: c.Add})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		d.Wait()
	})
	return d, c, fa, ctx
}

func target(url string) Target {
	return Target{
		KeyID: "K1", Prefix: "fsk_abcdefgh", URL: url, Secret: testSecret,
		Match: func(site string) bool { return site == "example.com" },
	}
}

func body(s string) func() []byte { return func() []byte { return []byte(s) } }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("tempo esgotado")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSignatureIndependentReceiver: um receptor httptest recalcula o HMAC por conta própria (sem Sign) e confere
// os três cabeçalhos; Verify aceita o mesmo envio e recusa corpo alterado e timestamp fora da janela.
func TestSignatureIndependentReceiver(t *testing.T) {
	got := make(chan received, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- received{r.Header.Clone(), b}
	}))
	defer srv.Close()
	now := time.Unix(1_800_000_000, 0)
	d, c, _, ctx := newDispatcher(t, srv, func() time.Time { return now })
	d.SetTargets(ctx, []Target{target(srv.URL)})
	const ev = `{"kind":"verdict","ts":"2026-11-16T12:00:00.000000Z"}`
	d.Publish("bot", "example.com", body(ev))
	r := <-got
	if string(r.body) != ev {
		t.Fatalf("corpo %q", r.body)
	}
	ts := r.header.Get("X-Fs-Timestamp")
	if ts != strconv.FormatInt(now.Unix(), 10) {
		t.Fatalf("timestamp %q", ts)
	}
	m := hmac.New(sha256.New, testSecret)
	m.Write([]byte(ts + "." + string(r.body)))
	want := "sha256=" + hex.EncodeToString(m.Sum(nil))
	if sig := r.header.Get("X-Fs-Signature"); sig != want {
		t.Fatalf("assinatura %q, esperada %q", sig, want)
	}
	if p := r.header.Get("X-Fs-Key-Prefix"); p != "fsk_abcdefgh" {
		t.Fatalf("prefixo %q", p)
	}
	if ct := r.header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	sig := r.header.Get("X-Fs-Signature")
	if !Verify(testSecret, ts, sig, r.body, now, 5*time.Minute) {
		t.Fatal("Verify recusou envio válido")
	}
	if Verify(testSecret, ts, sig, []byte(ev+" "), now, 5*time.Minute) {
		t.Fatal("Verify aceitou corpo alterado")
	}
	if Verify(testSecret, ts, sig, r.body, now.Add(10*time.Minute), 5*time.Minute) {
		t.Fatal("Verify aceitou timestamp velho")
	}
	if Verify([]byte("outro"), ts, sig, r.body, now, 0) {
		t.Fatal("Verify aceitou segredo errado")
	}
	waitFor(t, func() bool { return c.Get(`bot_webhook_sent_total{code="2xx"}`) == 1 })
}

// TestRetry5xx: 5xx repete em 1 s, 5 s e 30 s (relógio falso) e para depois da terceira nova tentativa.
func TestRetry5xx(t *testing.T) {
	var mu sync.Mutex
	n := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	d, c, fa, ctx := newDispatcher(t, srv, time.Now)
	d.SetTargets(ctx, []Target{target(srv.URL)})
	d.Publish("suspect", "example.com", body("{}"))
	waitFor(t, func() bool { return c.Get(`bot_webhook_sent_total{code="5xx"}`) == 4 })
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if n != 4 {
		t.Fatalf("%d envios, esperados 4", n)
	}
	want := []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}
	if got := fa.Delays(); !equalDurations(got, want) {
		t.Fatalf("esperas %v, esperadas %v", got, want)
	}
}

// TestNoRetry4xx: 4xx não repete; o envio seguinte da fila segue normalmente.
func TestNoRetry4xx(t *testing.T) {
	got := make(chan struct{}, 10)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		got <- struct{}{}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	d, c, fa, ctx := newDispatcher(t, srv, time.Now)
	d.SetTargets(ctx, []Target{target(srv.URL)})
	d.Publish("bot", "example.com", body("{}"))
	d.Publish("bot", "example.com", body("{}"))
	waitFor(t, func() bool { return c.Get(`bot_webhook_sent_total{code="4xx"}`) == 2 })
	time.Sleep(50 * time.Millisecond)
	if len(got) != 2 || len(fa.Delays()) != 0 {
		t.Fatalf("%d envios e esperas %v; esperados 2 envios sem nova tentativa", len(got), fa.Delays())
	}
}

// TestRetryNetworkError: erro de rede (servidor fechado) repete nos mesmos tempos e conta code="error".
func TestRetryNetworkError(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	d, c, fa, ctx := newDispatcher(t, srv, time.Now)
	d.SetTargets(ctx, []Target{target(url)})
	d.Publish("bot", "example.com", body("{}"))
	waitFor(t, func() bool { return c.Get(`bot_webhook_sent_total{code="error"}`) == 4 })
	want := []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}
	if got := fa.Delays(); !equalDurations(got, want) {
		t.Fatalf("esperas %v, esperadas %v", got, want)
	}
}

// TestFilter: classes padrão bot e suspect, classes escolhidas pela chave e domínios da chave.
func TestFilter(t *testing.T) {
	got := make(chan string, 10)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	defer srv.Close()
	d, _, _, ctx := newDispatcher(t, srv, time.Now)
	d.SetTargets(ctx, []Target{target(srv.URL)})
	calls := 0
	lazy := func(s string) func() []byte { return func() []byte { calls++; return []byte(s) } }
	d.Publish("human", "example.com", lazy("human"))
	d.Publish("unknown", "example.com", lazy("unknown"))
	d.Publish("bot", "other.org", lazy("other"))
	d.Publish("bot", "example.com", lazy("bot"))
	if b := <-got; b != "bot" {
		t.Fatalf("entregou %q", b)
	}
	if calls != 1 {
		t.Fatalf("corpo serializado %d vezes, esperado 1", calls)
	}
	tg := target(srv.URL)
	tg.Classes = []string{"human"}
	d.SetTargets(ctx, []Target{tg})
	d.Publish("bot", "example.com", body("bot2"))
	d.Publish("human", "example.com", body("human2"))
	if b := <-got; b != "human2" {
		t.Fatalf("entregou %q", b)
	}
}

// TestRejectNonHTTPS: URL que não é https fica sem entregador e é contada uma vez por URL.
func TestRejectNonHTTPS(t *testing.T) {
	c := newCounter()
	d := New(Options{Count: c.Add})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); d.Wait() }()
	tg := target("http://example.com/hook")
	for range 3 {
		d.SetTargets(ctx, []Target{tg})
	}
	if d.Active() {
		t.Fatal("http aceito")
	}
	if v := c.Get(metricURLRejected); v != 1 {
		t.Fatalf("recusas %v, esperada 1", v)
	}
	tg.URL = "ftp://example.com/"
	d.SetTargets(ctx, []Target{tg})
	if v := c.Get(metricURLRejected); v != 2 {
		t.Fatalf("recusas %v, esperadas 2", v)
	}
	if ValidURL("https://") || !ValidURL("https://h.example/x") {
		t.Fatal("ValidURL")
	}
}

// TestQueueFullBacklog: com o receptor travado, a fila de 1000 enche, o excesso é descartado e contado, e o
// backlog só aparece depois de 60 s cheia; com a fila esvaziada, some.
func TestQueueFullBacklog(t *testing.T) {
	release := make(chan struct{})
	first := make(chan struct{}, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case first <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(dt time.Duration) { mu.Lock(); now = now.Add(dt); mu.Unlock() }
	d, c, _, ctx := newDispatcher(t, srv, clock)
	d.SetTargets(ctx, []Target{target(srv.URL)})
	d.Publish("bot", "example.com", body("{}"))
	<-first // o entregador está preso no primeiro envio
	for range QueueSize + 5 {
		d.Publish("bot", "example.com", body("{}"))
	}
	if v := c.Get(metricDropped); v != 5 {
		t.Fatalf("descartes %v, esperados 5", v)
	}
	if d.Backlog(clock()) {
		t.Fatal("backlog logo ao encher")
	}
	advance(59 * time.Second)
	if d.Backlog(clock()) {
		t.Fatal("backlog antes de 60 s")
	}
	advance(2 * time.Second)
	if !d.Backlog(clock()) {
		t.Fatal("sem backlog depois de 60 s cheia")
	}
	close(release)
	waitFor(t, func() bool { return !d.Backlog(clock()) })
}

func equalDurations(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSentMetricByClass: o rótulo code leva a classe do status, não o status cru (ADR 0073 item 5); 999 (fora de
// 200–599) conta error e repete como erro de rede, 302 e 418 não repetem.
func TestSentMetricByClass(t *testing.T) {
	cases := []struct {
		status int
		class  string
		sends  float64
	}{
		{http.StatusNoContent, "2xx", 1},
		{http.StatusFound, "3xx", 1},
		{http.StatusTeapot, "4xx", 1},
		{http.StatusServiceUnavailable, "5xx", 4},
		{999, "error", 4},
	}
	for _, tc := range cases {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
		}))
		d, c, _, ctx := newDispatcher(t, srv, time.Now)
		d.SetTargets(ctx, []Target{target(srv.URL)})
		d.Publish("bot", "example.com", body("{}"))
		waitFor(t, func() bool { return c.Get(sentMetric(tc.class)) == tc.sends })
		time.Sleep(50 * time.Millisecond)
		for _, other := range []string{"2xx", "3xx", "4xx", "5xx", "error", strconv.Itoa(tc.status)} {
			want := 0.0
			if other == tc.class {
				want = tc.sends
			}
			if c.Get(sentMetric(other)) != want {
				t.Fatalf("%d: %s = %v, esperado %v", tc.status, sentMetric(other), c.Get(sentMetric(other)), want)
			}
		}
		srv.Close()
	}
}
