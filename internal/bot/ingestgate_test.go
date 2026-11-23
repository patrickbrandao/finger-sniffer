package bot

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestIngestGate: tetos total, da 9002 e por chave; a 9003 não usa a parte da 9002 nem a da chave; release devolve
// a vaga uma vez.
func TestIngestGate(t *testing.T) {
	g := newIngestGate(3, 2, 1)
	r1, why := g.acquire(true, "k1")
	if why != "" {
		t.Fatal(why)
	}
	if _, why := g.acquire(true, "k1"); why != refusedKeyConcurrent {
		t.Fatalf("segunda da chave: %q", why)
	}
	r2, _ := g.acquire(true, "k2")
	if _, why := g.acquire(true, "k3"); why != refusedBusy {
		t.Fatalf("terceira da 9002: %q", why)
	}
	r3, why := g.acquire(false, "")
	if why != "" {
		t.Fatalf("9003 com a 9002 cheia: %q", why)
	}
	if _, why := g.acquire(false, ""); why != refusedBusy {
		t.Fatalf("acima do total: %q", why)
	}
	r1()
	r1()
	if g.inUse() != 2 {
		t.Fatalf("em uso %d", g.inUse())
	}
	if r, why := g.acquire(true, "k1"); why != "" {
		t.Fatalf("depois de devolver: %q", why)
	} else {
		r()
	}
	r2()
	r3()
	if g.inUse() != 0 || len(g.perKey) != 0 {
		t.Fatalf("sobrou %d %v", g.inUse(), g.perKey)
	}
}

// slowUpload abre um POST do ingest com Content-Length maior que o mandado e devolve a conexão, para o corpo parar
// no meio.
func slowUpload(t *testing.T, base *httptest.Server, key string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(base.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	hdr := "POST /bot/v1/ingest/traefik HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(1<<20) + "\r\n"
	if key != "" {
		hdr += "Authorization: Bearer " + key + "\r\n"
	}
	if _, err := io.WriteString(c, hdr+"\r\n"+`{"records":[`); err != nil {
		t.Fatal(err)
	}
	return c, bufio.NewReader(c)
}

// waitInUse espera o semáforo chegar a n lotes em andamento.
func waitInUse(t *testing.T, g *ingestGate, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for g.inUse() != n {
		if time.Now().After(deadline) {
			t.Fatalf("em uso %d, quer %d", g.inUse(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestIngestSlowUploadHoldsAndTimesOut: com o semáforo em 1, um upload lento segura a vaga e o lote seguinte
// recebe 503 busy com Retry-After 1 sem ler o corpo; o corpo que para no meio é cortado no prazo (400, body_timeout)
// e a vaga volta (task 370, ADR 0073 item 2).
func TestIngestSlowUploadHoldsAndTimesOut(t *testing.T) {
	f := newFixture(t)
	f.srv.api.gate = newIngestGate(1, 1, 1)
	f.srv.api.bodyTimeout = 300 * time.Millisecond
	c, br := slowUpload(t, f.internal, "")
	waitInUse(t, f.srv.api.gate, 1)
	code, h, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, validBatch())
	if code != http.StatusServiceUnavailable || errorCode(t, b) != errBusy || h.Get("Retry-After") != "1" {
		t.Fatalf("segundo lote: %d %v %s", code, h, b)
	}
	if f.metrics.Get(ingestRefusedMetric(refusedBusy)) != 1 {
		t.Errorf("busy %v", f.metrics.Snapshot())
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("upload lento sem resposta no prazo: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, body) != errBadRequest {
		t.Fatalf("upload lento: %d %s", resp.StatusCode, body)
	}
	if f.metrics.Get(ingestRefusedMetric(refusedBodyTimeout)) != 1 {
		t.Errorf("body_timeout %v", f.metrics.Snapshot())
	}
	waitInUse(t, f.srv.api.gate, 0)
	if code, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, validBatch()); code != http.StatusAccepted {
		t.Fatalf("depois do prazo: %d %s", code, b)
	}
}

// TestIngestKeyConcurrency: na 9002 a chave tem no máximo MaxIngestBatchesPerKey lotes ao mesmo tempo (429
// rate_limited com Retry-After 1); outra chave segue; na 9003 a mesma chave não tem parte própria.
func TestIngestKeyConcurrency(t *testing.T) {
	f := newFixture(t)
	f.srv.api.gate = newIngestGate(8, 6, 1)
	_, k1 := f.createKey(KeyOptions{Name: "a", Domains: []string{"www.example.com"}, Burst: 100})
	_, k2 := f.createKey(KeyOptions{Name: "b", Domains: []string{"www.example.com"}, Burst: 100})
	slowUpload(t, f.public, k1)
	waitInUse(t, f.srv.api.gate, 1)
	code, h, b := f.do(f.public, "POST", "/bot/v1/ingest/traefik", k1, nil, validBatch())
	if code != http.StatusTooManyRequests || errorCode(t, b) != errRateLimited || h.Get("Retry-After") != "1" {
		t.Fatalf("segundo lote da chave: %d %v %s", code, h, b)
	}
	if f.metrics.Get(ingestRefusedMetric(refusedKeyConcurrent)) != 1 || f.metrics.Get(metricRateLimited) != 1 {
		t.Errorf("métricas %v", f.metrics.Snapshot())
	}
	if code, _, b := f.do(f.public, "POST", "/bot/v1/ingest/traefik", k2, nil, validBatch()); code != http.StatusAccepted {
		t.Fatalf("outra chave: %d %s", code, b)
	}
	if code, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", k1, nil, validBatch()); code != http.StatusAccepted {
		t.Fatalf("mesma chave na 9003: %d %s", code, b)
	}
}
