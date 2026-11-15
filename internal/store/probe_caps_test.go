package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestProbeWaitBusyCORS: o 503 do wait pedido de outra origem expõe o Retry-After ao navegador (task 212).
func TestProbeWaitBusyCORS(t *testing.T) {
	f := newAPIFixture(t)
	for range probeWaitMax {
		f.q.waiters <- struct{}{}
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+"/api/v1/probes/"+probeID+"?wait=10s", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://example.test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	expose := resp.Header.Get("Access-Control-Expose-Headers")
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" ||
		!strings.Contains(strings.ToLower(expose), "retry-after") {
		t.Fatalf("%d Retry-After=%q Expose=%q", resp.StatusCode, resp.Header.Get("Retry-After"), expose)
	}
}

// TestProbeWaitBusy: com as 64 vagas de wait ocupadas, um novo ?wait recebe 503 na hora com Retry-After; sem
// wait (ou com wait=0s) a rota responde normalmente (ADR 0032, task 152).
func TestProbeWaitBusy(t *testing.T) {
	f := newAPIFixture(t)
	for range probeWaitMax {
		f.q.waiters <- struct{}{}
	}
	start := time.Now()
	resp, err := http.Get(f.srv.URL + "/api/v1/probes/" + probeID + "?wait=10s") //nolint:gosec,noctx // teste
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" || time.Since(start) > time.Second {
		t.Fatalf("%d Retry-After=%q em %v", resp.StatusCode, resp.Header.Get("Retry-After"), time.Since(start))
	}
	for _, q := range []string{"", "?wait=0s"} {
		if code, body := f.get(t, "/api/v1/probes/"+probeID+q); code != 200 {
			t.Fatalf("%q com o teto ocupado: %d %s", q, code, body)
		}
	}
	// uma vaga livre basta para o wait seguinte, e ela volta ao fim
	<-f.q.waiters
	if code, body := f.get(t, "/api/v1/probes/"+probeID+"?wait=1s"); code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	if n := len(f.q.waiters); n != probeWaitMax-1 {
		t.Fatalf("vagas ocupadas depois do wait: %d", n)
	}
}

// TestProbeWaitSlotReleased: a vaga volta quando a espera termina pelo critério, pelo prazo ou pela desistência do
// cliente.
func TestProbeWaitSlotReleased(t *testing.T) {
	f := newAPIFixture(t)
	if code, _ := f.get(t, "/api/v1/probes/"+probeID+"?wait=5s"); code != 200 { // critério
		t.Fatal(code)
	}
	if code, _ := f.get(t, "/api/v1/probes/zzzzzzzz?wait=100ms"); code != 404 { // prazo
		t.Fatal(code)
	}
	if n := len(f.q.waiters); n != 0 {
		t.Fatalf("vagas presas: %d", n)
	}
	// desistência: o cliente cancela no meio da espera
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.srv.URL+"/api/v1/probes/zzzzzzzz?wait=30s", nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, err := http.DefaultClient.Do(req); err == nil { //nolint:gosec // teste
			_ = resp.Body.Close()
		}
	}()
	eventually(t, 2*time.Second, func() bool { return len(f.q.waiters) == 1 }, "wait não ocupou vaga")
	cancel()
	<-done
	eventually(t, 2*time.Second, func() bool { return len(f.q.waiters) == 0 }, "vaga não voltou com o cliente desistindo")
}

// TestProbeWaitReadsRecordOnce: durante um wait com conexão aberta, o laço só lê o resumo; record_json (e o
// estado ao vivo) é lido uma vez, na saída (task 152).
func TestProbeWaitReadsRecordOnce(t *testing.T) {
	f := newAPIFixture(t)
	if _, err := f.in.db.Exec("UPDATE connections SET probe_id = ? WHERE conn_id = ?", probeID, f.opened); err != nil {
		t.Fatal(err)
	}
	before := f.q.probeReads.Load()
	start := time.Now()
	code, body := f.get(t, "/api/v1/probes/"+probeID+"?wait=400ms")
	p := probeResp(t, body)
	if code != 200 || time.Since(start) < 400*time.Millisecond || p.AllClosed || p.WaitMet == nil || *p.WaitMet || len(p.Connections) != 2 {
		t.Fatalf("%d %s", code, body)
	}
	if n := f.q.probeReads.Load() - before; n != 1 {
		t.Fatalf("leituras completas do probe durante o wait: %d (quer 1; o laço roda a cada 20 ms)", n)
	}
}

// fillProbe grava n conexões fechadas (record_json com pad bytes) e n consultas DNS do probe direto no banco, numa
// consulta recursiva (rápida também com -race).
func fillProbe(t testing.TB, db *sql.DB, id string, n, pad int) {
	t.Helper()
	const seq = "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < ? - 1) "
	if _, err := db.Exec(`INSERT INTO connections (conn_id, probe_id, l4, family, src_ip, src_port, dst_ip, dst_port, proto,
		started_ns, ended_ns, record_json, updated_ns) `+seq+`SELECT printf('01JD%022d', i), ?, 'tcp', 4, '192.0.2.30', i % 65536,
		'170.247.40.86', 8443, 'tcp', (i + 1) * 1000, (i + 1) * 1000 + 1,
		json_object('conn_id', printf('01JD%022d', i), 'i', i, 'pad', ?), 1 FROM n`, n, id, strings.Repeat("x", pad)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_queries (ts_ns, probe_id, resolver_ip, resolver_port, proto, qname, qtype, record_json) `+
		seq+`SELECT (i + 1) * 1000, ?, '198.51.100.53', 53, 'udp', 'x.', 'A', json_object('i', i) FROM n`, n, id); err != nil {
		t.Fatal(err)
	}
}

// TestProbeTruncated: 1000 conexões e 1000 consultas cabem sem corte; com 1001 as listas param em 1000 (as
// primeiras pela ordem), truncated vem true e all_closed olha o conjunto inteiro (ADR 0032, task 153).
func TestProbeTruncated(t *testing.T) {
	f := newAPIFixture(t)
	const id = "trunc0001"
	fillProbe(t, f.in.db, id, probeMaxItems, 0)
	code, body := f.get(t, "/api/v1/probes/"+id)
	p := probeResp(t, body)
	if code != 200 || p.Truncated || strings.Contains(body, "truncated") || len(p.Connections) != probeMaxItems ||
		len(p.DNS) != probeMaxItems || !p.AllClosed {
		t.Fatalf("no teto: %d truncated=%v conns=%d dns=%d", code, p.Truncated, len(p.Connections), len(p.DNS))
	}
	// a 1001ª conexão (a última pelo início) fica aberta; a 1001ª consulta é a mais nova
	if _, err := f.in.db.Exec(`INSERT INTO connections (conn_id, probe_id, l4, family, src_ip, src_port, dst_ip, dst_port, proto,
		started_ns, record_json, updated_ns) VALUES ('01JDZZZZZZZZZZZZZZZZZZZZZZ', ?, 'tcp', 4, '192.0.2.30', 1, '170.247.40.86', 8443,
		'tcp', 9000000000000000, '{"last":true}', 1)`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.in.db.Exec(`INSERT INTO dns_queries (ts_ns, probe_id, resolver_ip, resolver_port, proto, qname, qtype, record_json)
		VALUES (9000000000000000, ?, '198.51.100.53', 53, 'udp', 'x.', 'A', '{"last":true}')`, id); err != nil {
		t.Fatal(err)
	}
	code, body = f.get(t, "/api/v1/probes/"+id+"?wait=0s")
	p = probeResp(t, body)
	if code != 200 || !p.Truncated || len(p.Connections) != probeMaxItems || len(p.DNS) != probeMaxItems || p.AllClosed ||
		p.WaitMet == nil || *p.WaitMet {
		t.Fatalf("acima do teto: %d truncated=%v conns=%d dns=%d all_closed=%v", code, p.Truncated, len(p.Connections), len(p.DNS), p.AllClosed)
	}
	if strings.Contains(string(p.Connections[probeMaxItems-1]), "last") || strings.Contains(string(p.DNS[probeMaxItems-1]), "last") ||
		!strings.Contains(string(p.Connections[0]), `"i": 0,`) {
		t.Fatal("o corte não ficou com os primeiros pela ordem")
	}
	// só a lista de DNS acima do teto também marca o corte
	if _, err := f.in.db.Exec("DELETE FROM connections WHERE conn_id = '01JDZZZZZZZZZZZZZZZZZZZZZZ'"); err != nil {
		t.Fatal(err)
	}
	code, body = f.get(t, "/api/v1/probes/"+id)
	if p = probeResp(t, body); code != 200 || !p.Truncated || !p.AllClosed {
		t.Fatalf("só dns acima do teto: %d truncated=%v", code, p.Truncated)
	}
	// contrato: um Probe real (registros completos da fixture) com truncated passa no schema Probe
	_, body = f.get(t, "/api/v1/probes/"+probeID)
	var v map[string]any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	v["truncated"] = true
	b, _ := json.Marshal(v)
	validateContract(t, "Probe", b)
}

// TestWriteProbeSameAsWriteJSON: a escrita registro a registro sai byte a byte igual à do Encoder indentado.
func TestWriteProbeSameAsWriteJSON(t *testing.T) {
	yes, no := true, false
	rec := json.RawMessage(`{"conn_id":"01JD0000000000000000000000","tls":{"ja4":"t13d","list":[1,2,{"a":"\u003cb\u003e"}]},"e":[],"o":{}}`)
	for _, p := range []probeJSON{
		{ProbeID: "abc12345", Connections: []json.RawMessage{}, DNS: []json.RawMessage{}},
		{ProbeID: "abc12345", AllClosed: true, WaitMet: &yes, Connections: []json.RawMessage{rec}, DNS: []json.RawMessage{rec, rec}},
		{ProbeID: "abc12345", Truncated: true, WaitMet: &no, Connections: []json.RawMessage{rec, rec}, DNS: []json.RawMessage{}},
	} {
		a, b := httptest.NewRecorder(), httptest.NewRecorder()
		writeJSON(a, http.StatusOK, p)
		writeProbe(b, p)
		if a.Body.String() != b.Body.String() || b.Header().Get("Content-Type") != "application/json" || b.Code != 200 {
			t.Fatalf("writeJSON:\n%s\nwriteProbe:\n%s", a.Body, b.Body)
		}
	}
}

// TestProbeLargeMemory: 10 chamadas paralelas a um probe de 50 mil conexões (1 KiB cada, ~50 MiB de registros)
// não elevam o heap do store em mais de 50 MiB (task 153).
func TestProbeLargeMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("probe de 50 mil conexões")
	}
	f := newAPIFixture(t)
	const id = "big00001"
	fillProbe(t, f.in.db, id, 50000, 1024)
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	baseline := ms.HeapAlloc
	var peak atomic.Uint64
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			q := ""
			if i%2 == 1 {
				q = "?wait=0s"
			}
			if code, body := f.get(t, "/api/v1/probes/"+id+q); code != 200 || !probeResp(t, body).Truncated {
				t.Errorf("%d", code)
			}
		})
	}
	wg.Wait()
	close(stop)
	<-sampled
	grow := int64(peak.Load()) - int64(baseline)
	t.Logf("pico do heap: +%d MiB", grow>>20)
	if grow > 50<<20 {
		t.Fatalf("heap cresceu %d MiB (teto 50 MiB)", grow>>20)
	}
}
