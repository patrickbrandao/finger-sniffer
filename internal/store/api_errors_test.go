package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// errorCasesFile é a tabela de casos de erro, compartilhada com o e2e (test/e2e TestAPIErrorContractLive).
const errorCasesFile = "testdata/api-error-cases.json"

type apiErrorCase struct {
	Name    string            `json:"name"`
	Op      string            `json:"op"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Want    int               `json:"want"`
	Fault   string            `json:"fault"`
	Issue   string            `json:"issue"`
}

type apiErrorTable struct {
	Cases      []apiErrorCase    `json:"cases"`
	Untestable map[string]string `json:"untestable"`
}

// openapiOp é uma operação do openapi.yaml com os códigos de resposta declarados.
type openapiOp struct {
	ID, Method, Path string
	Codes            map[int]bool
}

var (
	reOAPath   = regexp.MustCompile(`^  (/\S+):\s*$`)
	reOAMethod = regexp.MustCompile(`^    (get|put|post|delete|patch|head|options):\s*$`)
	reOAOpID   = regexp.MustCompile(`^      operationId:\s*(\w+)`)
	reOACode   = regexp.MustCompile(`^        "(\d{3})":`)
)

// parseOpenAPIOps lê as operações de `paths:` do openapi.yaml como texto (sem biblioteca YAML), pela indentação
// fixa do arquivo: caminho com 2 espaços, método com 4, operationId com 6 e código de resposta com 8.
func parseOpenAPIOps(spec []byte) ([]openapiOp, error) {
	var ops []openapiOp
	var path string
	var cur *openapiOp
	in := false
	sc := bufio.NewScanner(bytes.NewReader(spec))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, " ") && strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "#") {
			in = line == "paths:"
			continue
		}
		if !in {
			continue
		}
		if m := reOAPath.FindStringSubmatch(line); m != nil {
			path, cur = m[1], nil
			continue
		}
		if m := reOAMethod.FindStringSubmatch(line); m != nil {
			ops = append(ops, openapiOp{Method: strings.ToUpper(m[1]), Path: path, Codes: map[int]bool{}})
			cur = &ops[len(ops)-1]
			continue
		}
		if cur == nil {
			continue
		}
		if m := reOAOpID.FindStringSubmatch(line); m != nil {
			cur.ID = m[1]
		}
		if m := reOACode.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			cur.Codes[n] = true
		}
	}
	for _, op := range ops {
		if op.ID == "" || len(op.Codes) == 0 {
			return nil, fmt.Errorf("openapi: %s %s sem operationId ou sem respostas (o leitor de texto não entendeu o arquivo)", op.Method, op.Path)
		}
	}
	return ops, sc.Err()
}

// matchTemplate confere se o caminho concreto (sem query) casa com o modelo do openapi ({x} = um segmento).
func matchTemplate(tmpl, path string) bool {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	a, b := strings.Split(tmpl, "/"), strings.Split(path, "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.HasPrefix(a[i], "{") && strings.HasSuffix(a[i], "}") {
			if b[i] == "" {
				return false
			}
			continue
		}
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// loadErrorContract lê o openapi.yaml e a tabela e confere a própria tabela: cada caso aponta para uma operação
// existente (método e caminho batem), o código esperado está declarado nela, e todo código de erro (4xx/5xx)
// declarado em toda operação tem um caso ou um motivo em untestable. Assim o teste falha quando o openapi ganha
// uma rota ou um código sem caso de erro.
func loadErrorContract(t *testing.T) (apiErrorTable, map[string]openapiOp) {
	t.Helper()
	spec, err := os.ReadFile(openapiFile)
	if err != nil {
		t.Fatal(err)
	}
	list, err := parseOpenAPIOps(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) < 11 {
		t.Fatalf("openapi: só %d operações lidas; o leitor de texto não entendeu o arquivo", len(list))
	}
	ops := map[string]openapiOp{}
	for _, op := range list {
		ops[op.ID] = op
	}
	raw, err := os.ReadFile(errorCasesFile)
	if err != nil {
		t.Fatal(err)
	}
	var tab apiErrorTable
	if err := json.Unmarshal(raw, &tab); err != nil {
		t.Fatalf("%s: %v", errorCasesFile, err)
	}
	covered := map[string]bool{}
	names := map[string]bool{}
	for _, c := range tab.Cases {
		if names[c.Name] {
			t.Errorf("caso %q repetido", c.Name)
		}
		names[c.Name] = true
		if c.Op == "" {
			// rota inexistente (404) ou pré-voo CORS (204), regras gerais do contrato
			if c.Want != http.StatusNotFound && c.Want != http.StatusNoContent {
				t.Errorf("caso %q sem operação: só 404 (rota inexistente) ou 204 (OPTIONS), não %d", c.Name, c.Want)
			}
			for _, op := range list {
				if op.Method == c.Method && matchTemplate(op.Path, c.Path) {
					t.Errorf("caso %q diz rota inexistente, mas %s %s é a operação %s", c.Name, c.Method, c.Path, op.ID)
				}
			}
			continue
		}
		op, ok := ops[c.Op]
		if !ok {
			t.Errorf("caso %q: operação %q não existe no openapi", c.Name, c.Op)
			continue
		}
		if op.Method != c.Method || !matchTemplate(op.Path, c.Path) {
			t.Errorf("caso %q: %s %s não é a operação %s (%s %s)", c.Name, c.Method, c.Path, op.ID, op.Method, op.Path)
		}
		if !op.Codes[c.Want] {
			t.Errorf("caso %q espera %d, que a operação %s não declara", c.Name, c.Want, op.ID)
		}
		covered[fmt.Sprintf("%s %d", c.Op, c.Want)] = true
	}
	var missing []string
	for _, op := range list {
		for code := range op.Codes {
			key := fmt.Sprintf("%s %d", op.ID, code)
			if code < 400 || covered[key] {
				continue
			}
			if tab.Untestable[key] == "" {
				missing = append(missing, key)
			}
		}
	}
	for key := range tab.Untestable {
		if covered[key] {
			t.Errorf("untestable %q já tem caso na tabela; remova o motivo", key)
		}
		id, code, _ := strings.Cut(key, " ")
		n, _ := strconv.Atoi(code)
		if !ops[id].Codes[n] {
			t.Errorf("untestable %q não é um código declarado no openapi", key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("códigos de erro declarados no openapi sem caso em %s: %s", errorCasesFile, strings.Join(missing, ", "))
	}
	return tab, ops
}

// errorResult é o que voltou de uma requisição de erro.
type errorResult struct {
	Code        int
	ContentType string
	Body        []byte
}

// checkErrorResult confere código e corpo contra a regra: 204 sem corpo; 101 nunca é erro; o resto é
// application/json com o schema Error ({"error": string}). Devolve a lista de desvios.
func checkErrorResult(c apiErrorCase, r errorResult) []string {
	var bad []string
	if r.Code != c.Want {
		bad = append(bad, fmt.Sprintf("código %d, esperava %d", r.Code, c.Want))
	}
	if c.Want == http.StatusNoContent {
		if len(r.Body) != 0 {
			bad = append(bad, fmt.Sprintf("204 com corpo de %d bytes", len(r.Body)))
		}
		return bad
	}
	if !strings.HasPrefix(r.ContentType, "application/json") {
		bad = append(bad, fmt.Sprintf("Content-Type %q, esperava application/json", r.ContentType))
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(r.Body, &body); err != nil {
		bad = append(bad, fmt.Sprintf("corpo não é um objeto JSON (%v): %q", err, truncate(r.Body)))
		return bad
	}
	var msg string
	if err := json.Unmarshal(body["error"], &msg); err != nil || msg == "" {
		bad = append(bad, fmt.Sprintf("corpo sem \"error\" string não vazio: %q", truncate(r.Body)))
	}
	return bad
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "…"
	}
	return string(b)
}

// doErrorCase faz a requisição do caso; não segue redirecionamentos e lê no máximo 64 KiB do corpo (um /stream
// aceito por engano não prende o teste: o prazo do cliente corta).
func doErrorCase(client *http.Client, base string, c apiErrorCase) (errorResult, error) {
	req, err := http.NewRequest(c.Method, base+c.Path, nil)
	if err != nil {
		return errorResult{}, err
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return errorResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return errorResult{Code: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: body}, nil
}

// TestAPIErrorContract provoca, para cada operação do openapi, as respostas de erro declaradas (400/404/500/503)
// mais rota inexistente e OPTIONS, e confere código e corpo contra o contrato (spec 004 "Erros da API", openapi
// 0.3.3, task 089). Os corpos de erro também passam pelo Redocly contra o schema Error.
func TestAPIErrorContract(t *testing.T) {
	tab, _ := loadErrorContract(t)
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// servidores: normal, com o banco fechado (500) e com o tempo real lotado (503)
	_, _, ok := liveAPI(t, 16, 4)
	inBroken, _, broken := liveAPI(t, 16, 4)
	if err := inBroken.db.Close(); err != nil {
		t.Fatal(err)
	}
	_, hubFull, full := liveAPI(t, 16, 1)
	hold, err := hubFull.join(LiveFilter{DstPort: -1}, "sse")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hubFull.leave(hold) })
	// e com as vagas de ?wait e de download ocupadas (503, ADR 0032)
	waitFull := newAPIFixture(t)
	for range probeWaitMax {
		waitFull.q.waiters <- struct{}{}
	}
	blobFull := newAPIFixture(t)
	for range blobMax {
		blobFull.q.blobs <- struct{}{}
	}
	// e com o orçamento das respostas JSON esgotado (503, ADR 0066)
	budgetFull := newAPIFixture(t)
	budgetFull.q.budget = newJSONBudget(1)
	// e no desligamento: sinal ligado e contexto da requisição cancelado (503, ADR 0066 item 3)
	closing := shuttingDownServer(t)

	var bodies [][]byte
	for _, c := range tab.Cases {
		t.Run(c.Name, func(t *testing.T) {
			base := ok.URL
			switch c.Fault {
			case "":
			case "db_closed":
				base = broken.URL
			case "live_full":
				base = full.URL
			case "probe_wait_full":
				base = waitFull.srv.URL
			case "blob_full":
				base = blobFull.srv.URL
			case "json_budget_full":
				base = budgetFull.srv.URL
			case "shutting_down":
				base = closing.URL
			default:
				t.Fatalf("fault desconhecida %q", c.Fault)
			}
			r, err := doErrorCase(client, base, c)
			if err != nil {
				t.Fatal(err)
			}
			if bad := checkErrorResult(c, r); len(bad) > 0 {
				msg := fmt.Sprintf("%s %s: %s", c.Method, c.Path, strings.Join(bad, "; "))
				if c.Issue != "" {
					t.Skipf("desvio conhecido (%s): %s", c.Issue, msg)
				}
				t.Error(msg)
				return
			}
			if c.Want != http.StatusNoContent {
				bodies = append(bodies, r.Body)
			}
		})
	}
	if len(bodies) > 0 {
		validateContract(t, "Error", bodies...)
	}
}

// TestParseOpenAPIOps protege o leitor de texto do openapi: as operações conhecidas e seus códigos.
func TestParseOpenAPIOps(t *testing.T) {
	spec, err := os.ReadFile(openapiFile)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := parseOpenAPIOps(spec)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, op := range ops {
		codes := make([]int, 0, len(op.Codes))
		for c := range op.Codes {
			codes = append(codes, c)
		}
		sort.Ints(codes)
		got[op.ID] = fmt.Sprintf("%s %s %v", op.Method, op.Path, codes)
	}
	for id, want := range map[string]string{
		"getProbe":         "GET /api/v1/probes/{id} [200 400 404 500 503]",
		"deleteProbe":      "DELETE /api/v1/probes/{id} [204 400 404 500 503]",
		"getConnectionRaw": "GET /api/v1/connections/{conn_id}/raw [200 400 404 500 503]",
		"websocketEvents":  "GET /api/v1/ws [101 400 503]",
	} {
		if got[id] != want {
			t.Errorf("%s: %q, esperava %q", id, got[id], want)
		}
	}
	if !matchTemplate("/api/v1/connections/{conn_id}/raw", "/api/v1/connections/X/raw?dir=in") ||
		matchTemplate("/api/v1/connections/{conn_id}", "/api/v1/connections/") ||
		matchTemplate("/api/v1/connections/{conn_id}", "/api/v1/connections/X/pcap") {
		t.Error("matchTemplate")
	}
}

// shuttingDownServer é a API com o sinal de desligamento ligado e cada requisição já cancelada, como no Run depois
// do sinal e do cancelamento do contexto base.
func shuttingDownServer(t *testing.T) *httptest.Server {
	t.Helper()
	f := newAPIFixture(t)
	api := &API{OpenAPI: []byte("x"), Health: func(context.Context, time.Time) Health { return Health{} }, Now: time.Now, Q: f.q, W: f.q.db}
	api.BeginShutdown()
	h := api.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		cancel()
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func int64p(v int64) *int64 { return &v }

// syncBuf é um io.Writer seguro para o log de teste.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) { b.mu.Lock(); defer b.mu.Unlock(); return b.b.Write(p) }

func (b *syncBuf) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

// TestAPIInternalErrorLogged: com o banco de leitura fechado, a rota devolve 500 "internal error" e o erro vai para
// o log da API com a rota, um por segundo por rota; a métrica conta code=500 (task 379).
func TestAPIInternalErrorLogged(t *testing.T) {
	db, _ := testDB(t)
	_ = db.Close()
	var logBuf syncBuf
	prom := newStoreMetrics(func(context.Context) Health { return Health{} }, func() int { return 0 }, nil)
	api := &API{
		OpenAPI: []byte("x"), Health: func(context.Context, time.Time) Health { return Health{} }, Now: time.Now,
		Q: NewQueries(db, nil, 65535), W: db, Prom: prom, Log: slog.New(slog.NewJSONHandler(&logBuf, nil)),
	}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	for range 3 {
		resp, err := http.Get(srv.URL + "/api/v1/connections")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 500 || !strings.Contains(string(b), "internal error") || strings.Contains(string(b), "closed") {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
	}
	out := logBuf.String()
	if strings.Count(out, `"msg":"api request failed"`) != 1 || !strings.Contains(out, `"route":"GET /api/v1/connections"`) ||
		!strings.Contains(out, "database is closed") {
		t.Fatalf("log: %s", out)
	}
	if v := testutil.ToFloat64(prom.apiRequests.WithLabelValues("GET /api/v1/connections", "500")); v != 3 {
		t.Fatalf("code=500 counted %v", v)
	}
}

// TestLogLimiter: um registro por chave a cada segundo, com a contagem dos suprimidos no seguinte.
func TestLogLimiter(t *testing.T) {
	var l logLimiter
	t0 := time.Unix(100, 0)
	if ok, n := l.allow("a", t0); !ok || n != 0 {
		t.Fatal("first must pass")
	}
	if ok, _ := l.allow("a", t0.Add(500*time.Millisecond)); ok {
		t.Fatal("second within 1 s must be suppressed")
	}
	if ok, _ := l.allow("b", t0); !ok {
		t.Fatal("keys are independent")
	}
	if ok, n := l.allow("a", t0.Add(time.Second)); !ok || n != 1 {
		t.Fatalf("after 1 s: ok %v suppressed %d", ok, n)
	}
}

// TestAPICanceledCounts499: a requisição que o cliente abandona (contexto cancelado) conta como 499 em
// fs_store_api_requests_total, não como 200, e nada é escrito (task 379).
func TestAPICanceledCounts499(t *testing.T) {
	prom := newStoreMetrics(func(context.Context) Health { return Health{} }, func() int { return 0 }, nil)
	h := prom.instrument(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, context.Canceled)
	}), nil)
	mux := http.NewServeMux()
	mux.Handle("GET /x", h)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Body.Len() != 0 {
		t.Fatalf("canceled request wrote %q", rec.Body.String())
	}
	if v := testutil.ToFloat64(prom.apiRequests.WithLabelValues("GET /x", "499")); v != 1 {
		t.Fatalf("code=499 counted %v", v)
	}
	if v := testutil.ToFloat64(prom.apiRequests.WithLabelValues("GET /x", "200")); v != 0 {
		t.Fatalf("code=200 counted %v", v)
	}
}

// TestHealthStatsUnavailable: com o leitor fechado, o health não devolve connections 0 como se fosse válido (o
// campo fica ausente e oldest null) e o /metrics não publica fs_store_connections (task 379).
func TestHealthStatsUnavailable(t *testing.T) {
	s := exampleStore(t)
	if c := s.HealthAt(context.Background(), t0).Host.Store.Connections; c == nil || *c != 0 {
		t.Fatalf("open reader: connections %v", c)
	}
	rdb, _ := testDB(t)
	_ = rdb.Close()
	s.rdb = rdb
	h := s.HealthAt(context.Background(), t0)
	st := h.Host.Store
	if st.Connections != nil || st.Oldest != nil {
		t.Fatalf("closed reader: connections %v oldest %v", st.Connections, st.Oldest)
	}
	b, _ := json.Marshal(st)
	if strings.Contains(string(b), `"connections"`) {
		t.Fatalf("health store %s", b)
	}
	prom := newStoreMetrics(func(ctx context.Context) Health { return s.HealthAt(ctx, t0) }, func() int { return 0 }, nil)
	api := &API{OpenAPI: []byte("x"), Health: s.HealthAt, Now: func() time.Time { return t0 }, Prom: prom}
	rec := httptest.NewRecorder()
	api.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if body := rec.Body.String(); !strings.Contains(body, "fs_store_db_bytes") || strings.Contains(body, "fs_store_connections ") {
		t.Fatalf("metrics without stats:\n%s", body)
	}
}
