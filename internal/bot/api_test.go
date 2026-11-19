package bot

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const (
	testForkConnID  = "01JC0X3K8V2T7Q9N4M6P1R5S8W"
	testStoreConnID = "01JC0X3K8V2T7Q9N4M6P1R5S8Z"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// validBatch é um lote do fork com a conexão (TLS + h2 do cliente Go dos goldens) e uma requisição.
func validBatch() string {
	return batchWith(base64.StdEncoding.EncodeToString(goldenBytes("tls/go.bin")),
		base64.StdEncoding.EncodeToString(goldenBytes("h2/go.prefix")))
}

// batchWith é o lote de validBatch com o client_hello e o h2_prefix dados (base64).
func batchWith(ch, h2 string) string {
	return `{"sender":"v3.6.2-fs.1","records":[` +
		`{"type":"connection","fs_conn_id":"` + testForkConnID + `","ts":"2026-11-16T12:00:00.000000000Z",` +
		`"src":{"ip":"::ffff:198.51.100.7","port":51234},"dst":{"ip":"10.249.0.2","port":443},"entry_point":"websecure",` +
		`"sni":"www.example.com","alpn_offered":["h2","http/1.1"],"alpn":"h2","tls_version":"1.3","cipher":"TLS_AES_128_GCM_SHA256",` +
		`"client_hello":"` + ch + `","client_hello_truncated":false,"h2_prefix":"` + h2 + `","h2_prefix_truncated":false},` +
		`{"type":"request","fs_conn_id":"` + testForkConnID + `","ts":"2026-11-16T12:00:00.050000000Z","proto":"h2","method":"GET",` +
		`"authority":"www.example.com","path":"/index.html?secret=1","http_version":"2.0","field_names":["user-agent","accept","cookie"],` +
		`"fields":{"user-agent":"curl/8.10.1","accept":"*/*","cookie":"sid=abc"},"cookie_names":["sid"],"ja4h":"ge20nn030000_x_y_z",` +
		`"status":200,"ended":"2026-11-16T12:00:00.060000000Z","router":"site@docker","service":"site@docker"}]}`
}

// forkHeadersFor são os X-Fs-* da conexão de validBatch.
func forkHeadersFor() map[string]string {
	return map[string]string{
		"X-Fs-Src-Ip": "198.51.100.7", "X-Fs-Src-Port": "51234", "X-Fs-Dst-Port": "443", "X-Fs-Conn-Id": testForkConnID,
		"X-Fs-Proto": "h2", "X-Forwarded-Host": "www.example.com", "X-Forwarded-Uri": "/index.html?secret=1",
		"X-Forwarded-Method": "GET",
	}
}

// putStore põe no índice a visão do store da mesma conexão.
func (f *fixture) putStore() {
	f.srv.Index().PutStore(&StoreConn{
		ConnID: testStoreConnID, Stage: StageOpened, L4: "tcp", SrcIP: mustAddr("198.51.100.7"), SrcPort: 51234,
		DstIP: mustAddr("203.0.113.10"), DstPort: 443, Started: time.Date(2026, 11, 16, 11, 59, 59, 900e6, time.UTC),
	}, f.clock.Now())
}

// TestKeyAuthDomainsAndLimits: critério 1 da task 267 — chave criada dá 200, sem chave 401, domínio fora 404
// (igual a recurso inexistente), acima do balde 429 com Retry-After.
func TestKeyAuthDomainsAndLimits(t *testing.T) {
	f := newFixture(t)
	_, key := f.createKey(KeyOptions{Name: "site", Domains: []string{"*.example.com"}, RatePerS: 1, Burst: 3})

	if c, _, b := f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", key, nil, ""); c != 200 {
		t.Fatalf("com chave: %d %s", c, b)
	}
	if c, _, b := f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", "", nil, ""); c != 401 || errorCode(t, b) != errInvalidKey {
		t.Fatalf("sem chave: %d %s", c, b)
	}
	bad := "fsk_" + strings.Repeat("a", 52)
	if c, _, b := f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", bad, nil, ""); c != 401 || errorCode(t, b) != errInvalidKey {
		t.Fatalf("chave desconhecida: %d %s", c, b)
	}
	_, _, outBody := f.do(f.public, "GET", "/bot/v1/verdict?src_ip=192.0.2.1&src_port=1&site=other.com", key, nil, "")
	if errorCode(t, outBody) != errNotFound {
		t.Fatalf("domínio fora: %s", outBody)
	}
	// Domínio dentro e conexão desconhecida dão o mesmo corpo (spec 020 RF-03).
	c, _, inBody := f.do(f.public, "GET", "/bot/v1/verdict?src_ip=192.0.2.1&src_port=1&site=a.example.com", key, nil, "")
	if c != 404 || string(inBody) != string(outBody) {
		t.Fatalf("404 distinguível: %d %s × %s", c, inBody, outBody)
	}
	// Balde de 3 já gasto (3 chamadas acima com a chave válida): a próxima é 429.
	c, h, b := f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", key, nil, "")
	if c != 429 || errorCode(t, b) != errRateLimited || h.Get("Retry-After") != "1" {
		t.Fatalf("acima do balde: %d %v %s", c, h, b)
	}
	if f.metrics.Get(metricRateLimited) != 1 {
		t.Errorf("bot_rate_limited_total = %v", f.metrics.Get(metricRateLimited))
	}
	// O balde enche com o tempo.
	f.clock.Advance(2 * time.Second)
	if c, _, b := f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", key, nil, ""); c != 200 {
		t.Fatalf("depois de encher o balde: %d %s", c, b)
	}
	// Health e openapi não pedem chave.
	if c, _, _ := f.do(f.public, "GET", "/bot/v1/health", "", nil, ""); c != 200 {
		t.Errorf("health: %d", c)
	}
	c, h, b = f.do(f.public, "GET", "/bot/v1/openapi.yaml", "", nil, "")
	if c != 200 || h.Get("Content-Type") != "application/yaml" || !strings.Contains(string(b), "openapi: 3.1.0") {
		t.Errorf("openapi: %d %s", c, h.Get("Content-Type"))
	}
	// Rota desconhecida: 404 em JSON.
	if c, _, b := f.do(f.public, "GET", "/bot/v1/nope", key, nil, ""); c != 404 || errorCode(t, b) != errNotFound {
		t.Errorf("rota desconhecida: %d %s", c, b)
	}
}

// TestRevokedKey: chave revogada responde 401 depois da recarga.
func TestRevokedKey(t *testing.T) {
	f := newFixture(t)
	k, key := f.createKey(KeyOptions{Name: "x", Domains: []string{"example.com"}})
	if _, err := RevokeKey(t.Context(), f.db, k.ID, f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.Keys().Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", key, nil, ""); c != 401 {
		t.Fatalf("revogada: %d", c)
	}
}

// TestIngest: critério 2 da task 267 — lote válido aceito, registro inválido conta em rejected, 413 acima de
// 4 MiB, e o registro vira a conexão do fork no índice, sem query nem valor de cookie.
func TestIngest(t *testing.T) {
	f := newFixture(t)
	c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, validBatch())
	if c != 202 || string(b) != `{"accepted":2,"rejected":0}`+"\n" {
		t.Fatalf("lote válido: %d %s", c, b)
	}
	fc, ok := f.srv.Index().Fork(testForkConnID, f.clock.Now())
	if !ok {
		t.Fatal("conexão do fork fora do índice")
	}
	if fc.SrcIP != mustAddr("198.51.100.7") || fc.SrcPort != 51234 || fc.DstPort != 443 || fc.Site() != "www.example.com" {
		t.Errorf("origem/site: %+v", fc)
	}
	if fc.TLS == nil || fc.TLS.JA4 == "" || fc.H2 == nil || fc.H2.Akamai == "" || fc.ParseError() || len(fc.Requests) != 1 {
		t.Fatalf("conexão: tls %+v h2 %+v reqs %d", fc.TLS, fc.H2, len(fc.Requests))
	}
	r := fc.Requests[0]
	if r.Path != "/index.html" || r.Fields["cookie"] != "" || r.Fields["user-agent"] != "curl/8.10.1" {
		t.Errorf("minimização: %+v", r)
	}

	// Um registro inválido no meio não derruba o lote.
	var batch map[string][]json.RawMessage
	_ = json.Unmarshal([]byte(validBatch()), &batch)
	recs := append(batch["records"][:1:1], json.RawMessage(`{"type":"request","fs_conn_id":"not-a-ulid","ts":"2026-11-16T12:00:00Z"}`))
	body, _ := json.Marshal(map[string]any{"records": recs})
	if c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, string(body)); c != 202 ||
		string(b) != `{"accepted":1,"rejected":1}`+"\n" {
		t.Fatalf("lote com inválido: %d %s", c, b)
	}
	if f.metrics.Get(metricIngestRecords) != 3 || f.metrics.Get(metricIngestDropped) != 1 {
		t.Errorf("métricas: %v", f.metrics.Snapshot())
	}
	for _, bad := range []string{`{`, `{"records":null}`, `[]`, `{"records":[]} x`} {
		if c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, bad); c != 400 || errorCode(t, b) != errBadRequest {
			t.Errorf("%q: %d %s", bad, c, b)
		}
	}
	many := `{"records":[` + strings.TrimSuffix(strings.Repeat(`{},`, MaxIngestRecords+1), ",") + `]}`
	if c, _, _ := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, many); c != 400 {
		t.Errorf("mais de %d registros: %d", MaxIngestRecords, c)
	}
	// 413: pelo Content-Length e pela leitura (sem Content-Length).
	big := `{"records":[],"sender":"` + strings.Repeat("x", MaxIngestBytes) + `"}`
	if c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, big); c != 413 || errorCode(t, b) != errPayloadTooLarge {
		t.Errorf("acima de 4 MiB: %d %s", c, b)
	}
	req := httptest.NewRequest("POST", "/bot/v1/ingest/traefik", strings.NewReader(big))
	req.ContentLength = -1
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	f.srv.Handler(true).ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Errorf("acima de 4 MiB sem Content-Length: %d", rec.Code)
	}
}

// TestIngestKeyDomains: na 9002 o ingest exige chave e recusa registros de site fora dos domínios dela.
func TestIngestKeyDomains(t *testing.T) {
	f := newFixture(t)
	if c, _, _ := f.do(f.public, "POST", "/bot/v1/ingest/traefik", "", nil, validBatch()); c != 401 {
		t.Fatalf("sem chave na 9002: %d", c)
	}
	_, key := f.createKey(KeyOptions{Name: "other", Domains: []string{"example.net"}})
	if c, _, b := f.do(f.public, "POST", "/bot/v1/ingest/traefik", key, nil, validBatch()); c != 202 ||
		string(b) != `{"accepted":0,"rejected":2}`+"\n" {
		t.Fatalf("site fora da chave: %d %s", c, b)
	}
}

// TestInternalOrigin: critério 2 da task 267 — a 9003 recusa origem fora do loopback e da rede permitida (403).
func TestInternalOrigin(t *testing.T) {
	f := newFixture(t)
	h := f.srv.Handler(true)
	for _, tc := range []struct {
		remote string
		want   int
	}{
		{"127.0.0.1:4000", 200},
		{"[::1]:4000", 200},
		{"10.249.3.4:4000", 200},
		{"[::ffff:10.249.0.9]:4000", 200},
		{"203.0.113.5:4000", 403},
		{"10.250.0.1:4000", 403},
		{"[2001:db8::1]:4000", 403},
	} {
		for _, path := range []string{"/bot/v1/health", "/bot/v1/ip/192.0.2.1"} {
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = tc.remote
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("%s %s: %d, esperado %d", tc.remote, path, rec.Code, tc.want)
			}
			if tc.want == 403 && errorCode(t, rec.Body.Bytes()) != errForbiddenOrigin {
				t.Errorf("%s: %s", tc.remote, rec.Body)
			}
		}
	}
}

// TestInternalForeignAuthorization: na 9003 um Authorization do visitante (Basic, Bearer de outro sistema)
// repassado pelo forwardAuth não vira 401; uma chave fsk_ inválida, sim.
func TestInternalForeignAuthorization(t *testing.T) {
	f := newFixture(t)
	hdr := forkHeadersFor()
	hdr["Authorization"] = "Basic dXNlcjpwYXNz"
	if c, _, b := f.do(f.internal, "GET", "/bot/v1/auth", "", hdr, ""); c != 200 {
		t.Fatalf("Basic do visitante: %d %s", c, b)
	}
	hdr["Authorization"] = "Bearer eyJhbGciOi"
	if c, _, _ := f.do(f.internal, "GET", "/bot/v1/auth", "", hdr, ""); c != 200 {
		t.Fatalf("Bearer do visitante: %d", c)
	}
	hdr["Authorization"] = "Bearer fsk_" + strings.Repeat("b", 52)
	if c, _, _ := f.do(f.internal, "GET", "/bot/v1/auth", "", hdr, ""); c != 401 {
		t.Fatalf("fsk_ inválida: %d", c)
	}
}

// TestForwardAuth: 400 sem os X-Fs-*; com as duas visões, 200 com o veredito real, view.tcp e o conn_id do store;
// sem a visão do store, responde depois da espera com view.tcp=false.
func TestForwardAuth(t *testing.T) {
	f := newFixture(t)
	c, _, b := f.do(f.internal, "GET", "/bot/v1/auth", "", map[string]string{"X-Fs-Src-Ip": "1.2.3.4"}, "")
	if c != 400 || errorCode(t, b) != errMissingForkHeaders {
		t.Fatalf("sem X-Fs-*: %d %s", c, b)
	}
	hdr := forkHeadersFor()
	hdr["X-Fs-Proto"] = "spdy"
	if c, _, b := f.do(f.internal, "GET", "/bot/v1/auth", "", hdr, ""); c != 400 || errorCode(t, b) != errBadRequest {
		t.Fatalf("proto inválido: %d %s", c, b)
	}

	start := time.Now()
	c, _, b = f.do(f.internal, "GET", "/bot/v1/auth", "", forkHeadersFor(), "")
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Errorf("não esperou a visão (FS_BOT_VIEW_WAIT)")
	}
	var v Verdict
	_ = json.Unmarshal(b, &v)
	if v.View.TCP || v.View.TLS || v.Subject.ConnID != nil {
		t.Errorf("sem visões: %+v", v)
	}

	f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, validBatch())
	f.putStore()
	// Veredito real (rules v1.4): o UA do cliente Go do teste é de biblioteca; o JA4H do lote não está na base.
	c, h, b := f.do(f.internal, "GET", "/bot/v1/auth", "", forkHeadersFor(), "")
	if c != 200 || h.Get("X-Fs-Verdict") != ClassSuspect || h.Get("X-Fs-Score") != "50" || h.Get("X-Fs-Signals") != "library_client" {
		t.Fatalf("%d %v %s", c, h, b)
	}
	v = Verdict{}
	_ = json.Unmarshal(b, &v)
	if v.RulesVersion != "v1.4" || v.ListsVersion == "" || v.ListsVersion == "none" {
		t.Errorf("versões: %q %q", v.RulesVersion, v.ListsVersion)
	}
	if !v.View.TCP || !v.View.TLS || !v.View.HTTP || !v.View.H2 || v.Subject.ConnID == nil || *v.Subject.ConnID != testStoreConnID {
		t.Errorf("com as duas visões: %+v", v)
	}
	if v.Subject.Path == nil || *v.Subject.Path != "/index.html" || v.Subject.Site == nil || *v.Subject.Site != "www.example.com" {
		t.Errorf("subject: %+v", v.Subject)
	}

	// Com chave, o site precisa estar nos domínios dela.
	_, key := f.createKey(KeyOptions{Name: "k", Domains: []string{"example.net"}})
	if c, _, _ := f.do(f.internal, "GET", "/bot/v1/auth", key, forkHeadersFor(), ""); c != 400 {
		t.Errorf("site fora da chave: %d", c)
	}
}

// TestStreamLimit: acima de 64 clientes do feed, 503; um cliente recebe só os vereditos dos domínios da chave.
func TestStreamLimit(t *testing.T) {
	h := NewHub()
	h.max = 1
	if err := h.add(&streamClient{}); err != nil {
		t.Fatal(err)
	}
	if err := h.add(&streamClient{}); err == nil {
		t.Fatal("teto de clientes não respeitado")
	}
	c := &streamClient{domains: []string{"example.com"}, queue: make(chan *Verdict, 1)}
	h.clients = map[*streamClient]struct{}{c: {}}
	h.Publish(&Verdict{Class: ClassBot, Subject: Subject{Site: ptr("other.com")}})
	h.Publish(&Verdict{Class: ClassBot, Subject: Subject{Site: ptr("example.com")}})
	h.Publish(&Verdict{Class: ClassBot, Subject: Subject{Site: ptr("example.com")}})
	if len(c.queue) != 1 || c.dropped != 1 {
		t.Fatalf("fila %d, descartes %d", len(c.queue), c.dropped)
	}
}

// TestStreamSSE: o feed responde text/event-stream e entrega o evento publicado.
func TestStreamSSE(t *testing.T) {
	f := newFixture(t)
	req, _ := http.NewRequestWithContext(t.Context(), "GET", f.internal.URL+"/bot/v1/stream?class=bot", nil)
	resp, err := f.internal.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	for f.srv.hub.Clients() == 0 {
		time.Sleep(time.Millisecond)
	}
	f.srv.hub.Publish(&Verdict{Class: ClassHuman, Ts: "t"})
	f.srv.hub.Publish(&Verdict{Class: ClassBot, Ts: "2026-11-16T12:00:00.000000000Z"})
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	got := string(buf[:n])
	if !strings.HasPrefix(got, "event: verdict\ndata: ") || !strings.Contains(got, `"class":"bot"`) {
		t.Fatalf("evento: %q", got)
	}
}
