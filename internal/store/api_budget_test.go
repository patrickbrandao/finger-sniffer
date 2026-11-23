package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// budgetAPI monta a API sobre o leitor do fixture, com métricas, para conferir as recusas.
func budgetAPI(t *testing.T, q *Queries) (*httptest.Server, *storeMetrics) {
	t.Helper()
	m := newStoreMetrics(func(context.Context) Health { return Health{} }, func() int { return 0 }, nil)
	m.registerAPIBudget(q.budget)
	api := &API{OpenAPI: []byte("x"), Health: func(context.Context, time.Time) Health { return Health{} }, Now: time.Now, Q: q, Prom: m}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv, m
}

// seedProbe grava n conexões encerradas do probe com registros de size bytes e d consultas DNS de dsize bytes.
func seedProbe(t *testing.T, q *Queries, probe string, n, size, d, dsize int) {
	t.Helper()
	pad := func(k int) string { return `{"pad":"` + strings.Repeat("x", max(k-10, 0)) + `"}` }
	st := time.Now().UnixNano()
	for i := range n {
		id := ulid.MustNew(ulid.Timestamp(time.Unix(0, st)), ulid.DefaultEntropy()).String()
		if _, err := q.db.Exec(`INSERT INTO connections (conn_id, probe_id, l4, family, src_ip, src_port, dst_ip, dst_port, proto,
			started_ns, ended_ns, record_json, updated_ns) VALUES (?, ?, 'tcp', 4, '192.0.2.1', 1, '198.51.100.1', 443, 'h2', ?, ?, ?, ?)`,
			id, probe, st+int64(i), st+int64(i)+1, pad(size), st); err != nil {
			t.Fatal(err)
		}
	}
	for i := range d {
		if _, err := q.db.Exec(`INSERT INTO dns_queries (ts_ns, probe_id, resolver_ip, resolver_port, proto, qname, qtype, record_json)
			VALUES (?, ?, '198.51.100.53', 53, 'udp', 'x.', 'A', ?)`, st+int64(i), probe, pad(dsize)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAPIJSONBudgetRefuses: com o orçamento das respostas JSON esgotado, cada rota finita com orçamento responde
// 503 com Retry-After e {"error":"busy"}, conta em fs_store_api_rejected_total e devolve a reserva (ADR 0066).
func TestAPIJSONBudgetRefuses(t *testing.T) {
	f := newAPIFixture(t)
	f.q.budget = newJSONBudget(1)
	srv, m := budgetAPI(t, f.q)
	routes := map[string]string{
		"/api/v1/connections":                       "GET /api/v1/connections",
		"/api/v1/connections/" + f.closed:           "GET /api/v1/connections/{conn_id}",
		"/api/v1/dns":                               "GET /api/v1/dns",
		"/api/v1/packets":                           "GET /api/v1/packets",
		"/api/v1/probes/" + probeID:                 "GET /api/v1/probes/{id}",
		"/api/v1/probes/" + probeID + "?wait=0s":    "GET /api/v1/probes/{id}",
		"/api/v1/connections?probe=" + probeID:      "GET /api/v1/connections",
		"/api/v1/dns?probe=" + probeID + "&limit=1": "GET /api/v1/dns",
	}
	for path, route := range routes {
		before := testutil.ToFloat64(m.apiReject.WithLabelValues(route, "busy"))
		resp, err := http.Get(srv.URL + path) //nolint:noctx,gosec // teste
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var e struct{ Error string }
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" ||
			json.Unmarshal(b, &e) != nil || e.Error != "busy" {
			t.Errorf("%s: %d Retry-After=%q %s", path, resp.StatusCode, resp.Header.Get("Retry-After"), b)
		}
		if got := testutil.ToFloat64(m.apiReject.WithLabelValues(route, "busy")) - before; got != 1 {
			t.Errorf("%s: rejected_total Δ %v, want 1", path, got)
		}
		if u := f.q.budget.used.Load(); u != 0 {
			t.Fatalf("%s: %d bytes still reserved", path, u)
		}
	}
	// Com folga, a mesma rota responde 200 e a reserva volta a zero.
	f.q.budget = newJSONBudget(jsonBudgetMax)
	resp, err := http.Get(srv.URL + "/api/v1/probes/" + probeID) //nolint:noctx,gosec // teste
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || f.q.budget.used.Load() != 0 {
		t.Fatalf("with budget: %d, %d bytes reserved", resp.StatusCode, f.q.budget.used.Load())
	}
}

// TestAPIJSONResponseCap: o teto de bytes por resposta corta o probe com truncated e as listas abaixo do limit;
// o registro único nunca é cortado (ADR 0066 item 2).
func TestAPIJSONResponseCap(t *testing.T) {
	f := newAPIFixture(t)
	const pr = "capprobe1"
	seedProbe(t, f.q, pr, 5, 1000, 3, 600)
	f.q.respMax = 2500

	code, body := f.get(t, "/api/v1/probes/"+pr)
	var p struct {
		Truncated   bool
		Connections []json.RawMessage
		DNS         []json.RawMessage
	}
	if code != 200 || json.Unmarshal([]byte(body), &p) != nil || !p.Truncated || len(p.Connections) != 2 {
		t.Fatalf("probe: %d truncated=%v conns=%d", code, p.Truncated, len(p.Connections))
	}

	f.q.respMax = 1000
	code, body = f.get(t, "/api/v1/dns?probe="+pr)
	var dns []json.RawMessage
	if code != 200 || json.Unmarshal([]byte(body), &dns) != nil || len(dns) != 1 {
		t.Fatalf("dns: %d %d items", code, len(dns))
	}
	code, body = f.get(t, "/api/v1/connections?probe="+pr)
	var list []summaryJSON
	if code != 200 || json.Unmarshal([]byte(body), &list) != nil || len(list) == 0 || len(list) >= 5 {
		t.Fatalf("connections: %d %d items", code, len(list))
	}
	// Sem teto: tudo.
	f.q.respMax = jsonResponseMax
	p.Truncated = false
	code, body = f.get(t, "/api/v1/probes/"+pr)
	if code != 200 || json.Unmarshal([]byte(body), &p) != nil || p.Truncated || len(p.Connections) != 5 || len(p.DNS) != 3 {
		t.Fatalf("probe without cap: %d truncated=%v conns=%d dns=%d", code, p.Truncated, len(p.Connections), len(p.DNS))
	}
	// Registro único maior que o teto sai inteiro.
	f.q.respMax = 10
	if code, body = f.get(t, "/api/v1/connections/"+f.closed); code != 200 || !json.Valid([]byte(body)) || len(body) < 100 {
		t.Fatalf("connection: %d %d bytes", code, len(body))
	}
}

// TestAPISlowReadersBudget: clientes que pedem /probes/{id} e não leem seguram no máximo o orçamento; acima dele
// recebem 503 na hora, e no prazo de escrita a reserva e o heap voltam ao patamar anterior (task 319, ADR 0066).
func TestAPISlowReadersBudget(t *testing.T) {
	old := jsonWriteTimeout
	jsonWriteTimeout = 500 * time.Millisecond
	t.Cleanup(func() { jsonWriteTimeout = old })

	f := newAPIFixture(t)
	const pr = "slowread1"
	const conns, size = 200, 20 << 10 // resposta de ~4 MiB, bem acima dos buffers de socket
	seedProbe(t, f.q, pr, conns, size, 0, 0)
	resp := int64(conns * size)
	const held = 3
	f.q.budget = newJSONBudget(held*resp + resp/2)
	srv, m := budgetAPI(t, f.q)

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	baseline := ms.HeapInuse

	const clients = 6
	var cs []net.Conn
	defer func() {
		for _, c := range cs {
			_ = c.Close()
		}
	}()
	for i := range clients {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(4 << 10)
		}
		if _, err := fmt.Fprintf(c, "GET /api/v1/probes/%s HTTP/1.1\r\nHost: x\r\n\r\n", pr); err != nil {
			t.Fatal(err)
		}
		// Espera a requisição reservar (ou ser recusada) antes da próxima, para a ordem ser a da chegada.
		want := int64(min(i+1, held)) * resp
		deadline := time.Now().Add(5 * time.Second)
		for f.q.budget.used.Load() < want && i < held && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	}
	route := "GET /api/v1/probes/{id}"
	deadline := time.Now().Add(5 * time.Second)
	for testutil.ToFloat64(m.apiReject.WithLabelValues(route, "busy")) < clients-held && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := testutil.ToFloat64(m.apiReject.WithLabelValues(route, "busy")); got != clients-held {
		t.Fatalf("rejected = %v, want %d", got, clients-held)
	}
	if u := f.q.budget.used.Load(); u < held*resp || u > f.q.budget.max {
		t.Fatalf("in flight = %d, want %d..%d", u, held*resp, f.q.budget.max)
	}
	// Os clientes continuam conectados sem ler: no prazo de escrita a reserva volta a zero.
	deadline = time.Now().Add(jsonWriteTimeout + 5*time.Second)
	for f.q.budget.used.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if u := f.q.budget.used.Load(); u != 0 {
		t.Fatalf("%d bytes still reserved past the write deadline", u)
	}
	runtime.GC()
	runtime.ReadMemStats(&ms)
	if ms.HeapInuse > baseline+uint64(resp) {
		t.Fatalf("heap in use %d MiB, baseline %d MiB (response %d MiB)", ms.HeapInuse>>20, baseline>>20, resp>>20)
	}
}
