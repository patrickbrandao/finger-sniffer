package bot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/webhook"
)

// goldenSetup põe no índice a conexão do caso de verdictCases pelo nome (StoreConnection e lote do fork).
func (f *fixture) goldenSetup(name string) (verdictCase, int) {
	f.t.Helper()
	for i, c := range verdictCases {
		if c.name != name {
			continue
		}
		batch, store := c.build(f.t, i)
		if err := f.srv.feed.Handle(store); err != nil {
			f.t.Fatal(err)
		}
		if code, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, string(batch)); code != 202 {
			f.t.Fatalf("ingest: %d %s", code, b)
		}
		return c, i
	}
	f.t.Fatalf("caso %s", name)
	return verdictCase{}, 0
}

// authHeaders são os cabeçalhos do forwardAuth de uma requisição da conexão i.
func authHeaders(i int, ua string) map[string]string {
	fsID, _, port := goldenIDs(i)
	return map[string]string{
		"X-Fs-Src-Ip": goldenSrcIP, "X-Fs-Src-Port": strconv.Itoa(port), "X-Fs-Dst-Port": "443", "X-Fs-Conn-Id": fsID,
		"X-Fs-Proto": "h2", "X-Forwarded-Host": "www.example.com", "X-Forwarded-Uri": "/a", "X-Forwarded-Method": "GET",
		"User-Agent": ua,
	}
}

// requestRecord é um lote com só o resumo de uma requisição da conexão i.
func requestRecord(i int, path, ua string) string {
	fsID, _, _ := goldenIDs(i)
	return `{"records":[{"type":"request","fs_conn_id":"` + fsID + `","ts":"2026-11-16T12:00:01.000000000Z","proto":"h2",` +
		`"method":"GET","authority":"www.example.com","path":"` + path + `","http_version":"2.0","field_names":["user-agent","accept"],` +
		`"fields":{"user-agent":"` + ua + `","accept":"*/*"},"cookie_names":[],"ja4h":"ge20nn020000_5594a17e7e7e_000000000000_000000000000"}]}`
}

// TestVerdictPublishedOnce: critério 3 da task 282 — o feed e o webhook recebem cada requisição uma vez, venha o
// veredito do forwardAuth ou do ingest (o que chegar primeiro), e os agregados contam cada requisição uma vez.
func TestVerdictPublishedOnce(t *testing.T) {
	var (
		mu    sync.Mutex
		hooks int
	)
	rcv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		hooks++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer rcv.Close()
	f := newFixture(t)
	hc, hookURL := hookReceiver(t, rcv, "/hook")
	f.srv.hooks = webhook.New(webhook.Options{Client: hc, Now: f.clock.Now, Count: f.metrics.Add})
	f.srv.hub.SetSink(f.srv.publishWebhook)
	f.createWebhookKey(KeyOptions{
		Name: "site", Domains: []string{"*.example.com"}, WebhookURL: hookURL,
		WebhookClasses: []string{ClassBot, ClassSuspect, ClassHuman, ClassUnknown, ClassGoodBot},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); f.srv.hooks.Wait() }()
	f.srv.syncWebhooks(ctx)
	feed := &streamClient{queue: make(chan *Verdict, 16)}
	if err := f.srv.hub.add(feed); err != nil {
		t.Fatal(err)
	}

	// só o registro de conexão (o resumo da requisição chega depois da resposta)
	c := verdictCases[0]
	batch, store := c.build(t, 0)
	var b struct {
		Records []json.RawMessage `json:"records"`
	}
	_ = json.Unmarshal(batch, &b)
	if err := f.srv.feed.Handle(store); err != nil {
		t.Fatal(err)
	}
	f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, `{"records":[`+string(b.Records[0])+`]}`)

	step := func(what string, wantFeed int) {
		t.Helper()
		if len(feed.queue) != wantFeed {
			t.Fatalf("%s: feed com %d, quer %d", what, len(feed.queue), wantFeed)
		}
	}
	// 1: forwardAuth publica; o resumo dela pelo ingest não publica de novo
	if code, _, body := f.do(f.internal, "GET", "/bot/v1/auth", "", authHeaders(0, c.ua), ""); code != 200 {
		t.Fatalf("auth: %d %s", code, body)
	}
	step("forwardAuth 1", 1)
	f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, requestRecord(0, "/a", c.ua))
	step("ingest 1", 1)
	// 2: requisição sem forwardAuth (rota sem o middleware): o ingest publica
	f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, requestRecord(0, "/b", c.ua))
	step("ingest 2", 2)
	// 3: forwardAuth e ingest de novo
	f.do(f.internal, "GET", "/bot/v1/auth", "", authHeaders(0, c.ua), "")
	f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, requestRecord(0, "/c", c.ua))
	step("requisição 3", 3)

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := hooks
		mu.Unlock()
		if n == 3 {
			break
		}
		if n > 3 || time.Now().After(deadline) {
			t.Fatalf("webhook recebeu %d, quer 3", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st := f.srv.agg.Query(mustAddr(goldenSrcIP), "www.example.com", f.clock.Now()); st.HourRequests != 3 || st.HourReused != 2 {
		t.Fatalf("agregados: %+v", st)
	}
	// métricas: 2 forwardAuth (source=auth)
	var auth float64
	for k, v := range f.metrics.Snapshot() {
		if strings.HasPrefix(k, metricVerdicts+"{") && strings.Contains(k, `source="auth"`) {
			auth += v
		}
	}
	if auth != 2 {
		t.Errorf("bot_verdicts_total source=auth %v", auth)
	}
}

// TestVerdictQueries: a consulta pela origem e pelo fs_conn_id devolve o veredito guardado da última requisição;
// site fora da chave, outra origem e outro site dão o mesmo 404; wait espera a visão que falta.
func TestVerdictQueries(t *testing.T) {
	f := newFixture(t)
	_, key := f.createKey(KeyOptions{Name: "k", Domains: []string{"*.example.com"}})
	_, other := f.createKey(KeyOptions{Name: "o", Domains: []string{"example.net"}})
	_, i := f.goldenSetup("chrome")
	fsID, connID, port := goldenIDs(i)
	q := "/bot/v1/verdict?src_ip=::ffff:" + goldenSrcIP + "&src_port=" + strconv.Itoa(port) + "&site=www.example.com"
	code, _, b := f.do(f.public, "GET", q, key, nil, "")
	if code != 200 {
		t.Fatalf("pela origem: %d %s", code, b)
	}
	var v Verdict
	_ = json.Unmarshal(b, &v)
	if v.Class != ClassHuman || v.Subject.Kind != "request" || *v.Subject.FsConnID != fsID || *v.Subject.ConnID != connID {
		t.Fatalf("pela origem: %s", b)
	}
	_, _, b2 := f.do(f.public, "GET", "/bot/v1/verdict/conn/"+fsID, key, nil, "")
	if string(b2) != string(b) {
		t.Errorf("pelo id difere:\n%s\n%s", b2, b)
	}
	_, _, nf := f.do(f.public, "GET", "/bot/v1/verdict/conn/"+fsID, other, nil, "")
	for _, path := range []string{
		"/bot/v1/verdict?src_ip=" + goldenSrcIP + "&src_port=1&site=www.example.com",
		"/bot/v1/verdict?src_ip=" + goldenSrcIP + "&src_port=" + strconv.Itoa(port) + "&site=api.example.com",
		"/bot/v1/verdict/conn/01JC0X3K8V2T7Q9F4M6P1R5S99",
	} {
		if c, _, b := f.do(f.public, "GET", path, key, nil, ""); c != 404 || string(b) != string(nf) {
			t.Errorf("%s: %d %s", path, c, b)
		}
	}
	// sem veredito guardado: o da conexão, depois de esperar a visão do store
	const late = "01JC0X3K8V2T7Q9F4M6P1R5S90"
	f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, strings.Replace(
		`{"records":[{"type":"connection","fs_conn_id":"ID","ts":"2026-11-16T12:00:00Z","src":{"ip":"198.51.100.99","port":555},`+
			`"dst":{"ip":"10.249.0.2","port":443},"entry_point":"websecure","sni":"www.example.com"}]}`, "ID", late, 1))
	go func() {
		time.Sleep(30 * time.Millisecond)
		msg := storeMessageWith(t, "01JC0X3K8V2T7Q9N4M6P1R5S90", "", 555, map[string]any{
			"src": map[string]any{"ip": "198.51.100.99", "port": 555},
		})
		_ = f.srv.feed.Handle(msg)
	}()
	code, _, b = f.do(f.public, "GET", "/bot/v1/verdict/conn/"+late+"?wait=1000", key, nil, "")
	v = Verdict{}
	_ = json.Unmarshal(b, &v)
	if code != 200 || v.Subject.Kind != "connection" || !v.View.TCP || v.Subject.ConnID == nil {
		t.Fatalf("wait: %d %s", code, b)
	}
	if c, _, _ := f.do(f.public, "GET", "/bot/v1/verdict/conn/"+late+"?wait=1001", key, nil, ""); c != 400 {
		t.Errorf("wait acima de 1000: %d", c)
	}
}

// TestProbeVerdict: o veredito do probe sai das conexões do probe vistas pelo store, com o domínio pelo Origin;
// chave de outro domínio e probe sem conexões dão o mesmo 404.
func TestProbeVerdict(t *testing.T) {
	f := newFixture(t)
	_, key := f.createKey(KeyOptions{Name: "k", Domains: []string{"app.example.net"}})
	_, other := f.createKey(KeyOptions{Name: "o", Domains: []string{"example.org"}})
	msg := storeMessageWith(t, "01JC0X3K8V2T7Q9N4M6P1R5S70", "probe1234", 4444, map[string]any{
		"http2": map[string]any{"streams": []any{h2Stream(1)}},
		"tcp":   map[string]any{"ja4t": ja4tMac, "os_guess": "Mac OS X"},
	})
	if err := f.srv.feed.Handle(msg); err != nil {
		t.Fatal(err)
	}
	code, _, b := f.do(f.public, "GET", "/bot/v1/probes/probe1234/verdict", key, nil, "")
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	var v Verdict
	_ = json.Unmarshal(b, &v)
	if v.Subject.Kind != "probe" || *v.Subject.ProbeID != "probe1234" || *v.Subject.Site != "app.example.net" ||
		!slices.Contains(signalIDList(v.Signals), "library_client") || !v.View.HTTP || !v.View.TCP {
		t.Fatalf("probe: %s", b)
	}
	_, _, nf := f.do(f.public, "GET", "/bot/v1/probes/nonexistent1/verdict", key, nil, "")
	if c, _, b := f.do(f.public, "GET", "/bot/v1/probes/probe1234/verdict", other, nil, ""); c != 404 || string(b) != string(nf) {
		t.Errorf("outro domínio: %d %s", c, b)
	}
	if got := f.metrics.Get(metricVerdicts + `{class="` + v.Class + `",source="probe"}`); got != 1 {
		t.Errorf("métrica probe %v", got)
	}
}

// TestIPAndFingerprintLabels: /ip traz as listas (vazias sem download) e /fingerprints o rótulo da base própria;
// ja4db desligada dá ja4db_label null.
func TestIPAndFingerprintLabels(t *testing.T) {
	f := newFixture(t)
	code, _, b := f.do(f.internal, "GET", "/bot/v1/fingerprints/ja4/t13d1517h2_8daaf6152771_cb7bf5808d99", "", nil, "")
	if code != 200 || !strings.Contains(string(b), `"known_client":"chrome,headless"`) || !strings.Contains(string(b), `"ja4db_label":null`) {
		t.Fatalf("fingerprints: %d %s", code, b)
	}
	_, _, b = f.do(f.internal, "GET", "/bot/v1/fingerprints/ja4h/ge20nn020000_5594a17e7e7e_x_y", "", nil, "")
	if !strings.Contains(string(b), `"known_client":"curl"`) {
		t.Errorf("ja4h: %s", b)
	}
	_, _, b = f.do(f.internal, "GET", "/bot/v1/ip/192.0.2.1", "", nil, "")
	if !strings.Contains(string(b), `"lists":[]`) || !strings.Contains(string(b), `"crawler_verified":null`) {
		t.Errorf("ip: %s", b)
	}
}

// TestAuthLongConnection: o forwardAuth que chega antes do registro de conexão do traefix cria a conexão do fork
// sem inventar o início dela; requisições seguintes na mesma conexão, minutos depois do SYN, continuam casadas com
// a visão do store (RF-04) e não esperam FS_BOT_VIEW_WAIT.
func TestAuthLongConnection(t *testing.T) {
	f := newFixture(t)
	f.putStore() // SYN às 11:59:59.9
	hdr := forkHeadersFor()
	for i := range 3 {
		f.clock.Advance(time.Minute)
		start := time.Now()
		_, _, b := f.do(f.internal, "GET", "/bot/v1/auth", "", hdr, "")
		var v Verdict
		_ = json.Unmarshal(b, &v)
		if !v.View.TCP || v.Subject.ConnID == nil {
			t.Fatalf("requisição %d sem a visão do store: %s", i, b)
		}
		if i > 0 && time.Since(start) > 40*time.Millisecond {
			t.Errorf("requisição %d esperou a visão (%v)", i, time.Since(start))
		}
	}
}

// TestAuthMetrics: bot_auth_seconds e bot_auth_wait_seconds saem como histogramas cumulativos com os limites da
// spec 018 RF-12, sem o bucket +Inf (ADR 0057 item 3); bot_view_wait_total conta a visão que faltou.
func TestAuthMetrics(t *testing.T) {
	f := newFixture(t)
	f.do(f.internal, "GET", "/bot/v1/auth", "", forkHeadersFor(), "") // sem visões: espera e conta as duas
	snap := f.metrics.Snapshot()
	for k := range snap {
		if strings.Contains(k, "+Inf") || strings.Contains(k, "Inf") {
			t.Errorf("bucket infinito enviado: %s", k)
		}
	}
	var les []float64
	for k, v := range snap {
		if rest, ok := strings.CutPrefix(k, metricAuthSeconds+`_bucket{le="`); ok {
			le, err := strconv.ParseFloat(strings.TrimSuffix(rest, `"}`), 64)
			if err != nil {
				t.Fatal(k)
			}
			les = append(les, le)
			if le >= 0.2 && v != 1 {
				t.Errorf("%s = %v", k, v)
			}
		}
	}
	sort.Float64s(les)
	if !slices.Equal(les, authBuckets) {
		t.Errorf("limites %v", les)
	}
	if snap[metricAuthSeconds+"_count"] != 1 || snap[metricAuthWaitSecs+"_count"] != 1 || snap[metricAuthWaitSecs+"_sum"] < 0.04 {
		t.Errorf("count/sum: %v %v %v", snap[metricAuthSeconds+"_count"], snap[metricAuthWaitSecs+"_count"], snap[metricAuthWaitSecs+"_sum"])
	}
	if snap[viewWaitMetric("tcp")] != 1 || snap[viewWaitMetric("fork")] != 1 {
		t.Errorf("view_wait: %v %v", snap[viewWaitMetric("tcp")], snap[viewWaitMetric("fork")])
	}
	if snap[metricVerdicts+`{class="suspect",source="auth"}`] != 1 {
		t.Errorf("verdicts_total: %v", snap)
	}
}

// TestForwardAuthLatency: critério 7 da task 282 — forwardAuth com a visão pronta tem p99 < 5 ms num núcleo (o
// RNF-01 de verdade é medido na carga, task 285). Sob o detector de corrida o tempo não vale e o teste é pulado.
// Padrão dos testes de tempo (task 426, como o teto absoluto da retenção): aquecimento e várias rodadas, valendo o
// menor p99 entre elas (uma rodada atrapalhada pelo escalonador não conta). O limite de 5 ms só é exigido com
// FS_STRICT_TIMING=1 (job norace do CI); fora dele, no Mac compartilhado do verify-quick, vale um teto folgado que
// ainda pega regressão grosseira (10x) e o excesso sobre 5 ms só vai para o log.
func TestForwardAuthLatency(t *testing.T) {
	if raceEnabled {
		t.Skip("latência não vale com -race")
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	f := newFixture(t)
	_, i := f.goldenSetup("chrome")
	h := f.srv.Handler(true)
	hdr := authHeaders(i, uaChrome)
	call := func() time.Duration {
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/bot/v1/auth", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		start := time.Now()
		h.ServeHTTP(w, req)
		el := time.Since(start)
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		return el
	}
	// Aquecimento: caches da CPU, alocador e pools antes de medir.
	for range 300 {
		call()
	}
	const (
		rounds = 5
		n      = 1000
		strict = 5 * time.Millisecond
		loose  = 50 * time.Millisecond
	)
	best, bestP50 := time.Duration(1<<62), time.Duration(0)
	d := make([]time.Duration, n)
	for r := range rounds {
		for j := range n {
			d[j] = call()
		}
		slices.Sort(d)
		p99 := d[n*99/100]
		t.Logf("round %d: forwardAuth p50 %v p99 %v", r, d[n/2], p99)
		if p99 < best {
			best, bestP50 = p99, d[n/2]
		}
		// Já abaixo do limite estrito: as rodadas restantes não mudam o resultado.
		if best <= strict {
			break
		}
	}
	t.Logf("forwardAuth best p50 %v p99 %v", bestP50, best)
	if best <= strict {
		return
	}
	if os.Getenv("FS_STRICT_TIMING") == "1" {
		t.Fatalf("p99 %v > %v (FS_STRICT_TIMING=1)", best, strict)
	}
	if best > loose {
		t.Fatalf("p99 %v > %v (loose ceiling; regression?)", best, loose)
	}
	t.Logf("p99 %v above the %v limit: loaded machine? (FS_STRICT_TIMING=1 makes it fail)", best, strict)
}

// BenchmarkForwardAuth mede o forwardAuth com as duas visões prontas (veredito, registro e publicação).
func BenchmarkForwardAuth(b *testing.B) {
	f := newFixture(b)
	_, i := f.goldenSetup("chrome")
	h := f.srv.Handler(true)
	hdr := authHeaders(i, uaChrome)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/bot/v1/auth", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	b.ReportAllocs()
	for b.Loop() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatal(w.Code)
		}
	}
}
