package store

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// shutdownAPI monta a API sobre o leitor do fixture num servidor cujo contexto base o teste cancela, como o Run.
func shutdownAPI(t *testing.T, q *Queries, wrap func(http.Handler) http.Handler) (*API, *httptest.Server, context.CancelFunc) {
	t.Helper()
	base, cancel := context.WithCancel(context.Background())
	api := &API{OpenAPI: []byte("x"), Health: func(context.Context, time.Time) Health { return Health{} }, Now: time.Now, Q: q, W: q.db}
	srv := httptest.NewUnstartedServer(wrap(api.Handler()))
	srv.Config.BaseContext = func(net.Listener) context.Context { return base }
	srv.Start()
	t.Cleanup(func() { cancel(); srv.Close() })
	return api, srv, cancel
}

// seedOpenProbe grava uma conexão aberta do probe: o wait não termina por conta própria.
func seedOpenProbe(t *testing.T, q *Queries, pr string) {
	t.Helper()
	st := time.Now().UnixNano()
	if _, err := q.db.Exec(`INSERT INTO connections (conn_id, probe_id, l4, family, src_ip, src_port, dst_ip, dst_port, proto,
		started_ns, ended_ns, record_json, updated_ns) VALUES (?, ?, 'tcp', 4, '192.0.2.1', 1, '198.51.100.1', 443, 'h2', ?, NULL, '{}', ?)`,
		ulid.Make().String(), pr, st, st); err != nil {
		t.Fatal(err)
	}
}

// TestAPIShutdownDuringWait: um ?wait em curso quando o store desliga (sinal ligado e contexto base cancelado)
// recebe 503 com Retry-After e corpo Error, não um 200 vazio (task 340, ADR 0066 item 3).
func TestAPIShutdownDuringWait(t *testing.T) {
	f := newAPIFixture(t)
	const pr = "shutdown1"
	seedOpenProbe(t, f.q, pr)
	api, srv, cancel := shutdownAPI(t, f.q, func(h http.Handler) http.Handler { return h })
	time.AfterFunc(300*time.Millisecond, func() { api.BeginShutdown(); cancel() })
	resp, err := http.Get(srv.URL + "/api/v1/probes/" + pr + "?wait=10s") //nolint:noctx,gosec // teste
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var e struct{ Error string }
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" ||
		resp.Header.Get("Content-Type") != "application/json" || json.Unmarshal(b, &e) != nil || e.Error != "shutting down" {
		t.Fatalf("%d Retry-After=%q Content-Type=%q %s", resp.StatusCode, resp.Header.Get("Retry-After"), resp.Header.Get("Content-Type"), b)
	}
}

// TestAPIShutdownFiniteRoutes: com o sinal ligado, toda rota finita cuja consulta é cancelada responde 503
// "shutting down", inclusive DELETE, /pcap e /raw, e conta em fs_store_api_rejected_total (ADR 0066 itens 3 e 4).
func TestAPIShutdownFiniteRoutes(t *testing.T) {
	f := newAPIFixture(t)
	m := newStoreMetrics(func(context.Context) Health { return Health{} }, func() int { return 0 }, nil)
	api := &API{OpenAPI: []byte("x"), Health: func(context.Context, time.Time) Health { return Health{} }, Now: time.Now, Q: f.q, W: f.q.db, Prom: m}
	api.BeginShutdown()
	h := api.Handler()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []struct{ method, path, route string }{
		{"GET", "/api/v1/connections", "GET /api/v1/connections"},
		{"GET", "/api/v1/connections/" + f.closed, "GET /api/v1/connections/{conn_id}"},
		{"GET", "/api/v1/connections/" + f.closed + "/pcap", "GET /api/v1/connections/{conn_id}/pcap"},
		{"GET", "/api/v1/connections/" + f.closed + "/raw?dir=in", "GET /api/v1/connections/{conn_id}/raw"},
		{"GET", "/api/v1/dns", "GET /api/v1/dns"},
		{"GET", "/api/v1/packets", "GET /api/v1/packets"},
		{"GET", "/api/v1/probes/" + probeID, "GET /api/v1/probes/{id}"},
		{"DELETE", "/api/v1/probes/" + probeID, "DELETE /api/v1/probes/{id}"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, c.method, c.path, nil))
		var e struct{ Error string }
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" ||
			json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.Error != "shutting down" {
			t.Errorf("%s %s: %d %q", c.method, c.path, rec.Code, rec.Body.String())
		}
		if got := testutil.ToFloat64(m.apiReject.WithLabelValues(c.route, "shutting_down")); got != 1 {
			t.Errorf("%s: rejected_total = %v, want 1", c.route, got)
		}
	}
}

// TestAPIClientGoneDuringWait: sem o sinal de desligamento, o cliente que fecha a conexão no meio do wait não
// recebe nada: o handler não escreve resposta (task 340).
func TestAPIClientGoneDuringWait(t *testing.T) {
	f := newAPIFixture(t)
	const pr = "clientgone1"
	seedOpenProbe(t, f.q, pr)
	wrote := make(chan bool, 1)
	_, srv, _ := shutdownAPI(t, f.q, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
			h.ServeHTTP(sw, r)
			wrote <- sw.wrote
		})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/probes/"+pr+"?wait=10s", nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("got a response: %d", resp.StatusCode)
	}
	select {
	case w := <-wrote:
		if w {
			t.Fatal("handler wrote a response to a client that left")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler still waiting after the client left")
	}
}
