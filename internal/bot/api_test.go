package bot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/rules"
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
	// Veredito real (rules v1.5): o UA do cliente Go do teste é de biblioteca; o JA4H do lote não está na base.
	c, h, b := f.do(f.internal, "GET", "/bot/v1/auth", "", forkHeadersFor(), "")
	if c != 200 || h.Get("X-Fs-Verdict") != ClassSuspect || h.Get("X-Fs-Score") != "50" || h.Get("X-Fs-Signals") != "library_client" {
		t.Fatalf("%d %v %s", c, h, b)
	}
	v = Verdict{}
	_ = json.Unmarshal(b, &v)
	if v.RulesVersion != rules.RulesVersion || v.ListsVersion == "" || v.ListsVersion == "none" {
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

// openFeed abre o feed na 9002 com a chave e espera o cliente entrar no Hub (want clientes ao todo).
func (f *fixture) openFeed(key string, want int) *http.Response {
	f.t.Helper()
	req, _ := http.NewRequestWithContext(f.t.Context(), "GET", f.public.URL+"/bot/v1/stream", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := f.public.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != 200 {
		f.t.Fatalf("feed: %d", resp.StatusCode)
	}
	for f.srv.hub.Clients() < want {
		time.Sleep(time.Millisecond)
	}
	return resp
}

// TestStreamEndsOnRevokeAndRotate: task 368 — o feed aberto com uma chave termina (EOF) na recarga das chaves
// seguinte à revogação ou à rotação dela e não recebe o veredito publicado depois; o feed de outra chave ativa segue.
func TestStreamEndsOnRevokeAndRotate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel func(f *fixture, k Key)
	}{
		{"revoke", func(f *fixture, k Key) {
			if _, err := RevokeKey(t.Context(), f.db, k.ID, f.clock.Now()); err != nil {
				t.Fatal(err)
			}
		}},
		{"rotate", func(f *fixture, k Key) {
			if _, _, err := RotateKey(t.Context(), f.db, k.ID); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			k, key := f.createKey(KeyOptions{Name: "x", Domains: []string{"example.com"}})
			_, other := f.createKey(KeyOptions{Name: "y", Domains: []string{"example.com"}})
			resp := f.openFeed(key, 1)
			f.openFeed(other, 2)
			f.srv.hub.Publish(&Verdict{Class: ClassBot, Subject: Subject{Site: ptr("example.com")}, Ts: "antes"})
			buf := make([]byte, 4096)
			if n, _ := resp.Body.Read(buf); !strings.Contains(string(buf[:n]), `"ts":"antes"`) {
				t.Fatalf("veredito antes da revogação: %q", buf[:n])
			}

			tc.cancel(f, k)
			f.srv.reloadKeys(t.Context())
			if n := f.srv.hub.Clients(); n != 1 {
				t.Errorf("clientes depois da recarga: %d, quer 1 (o da outra chave)", n)
			}
			f.srv.hub.Publish(&Verdict{Class: ClassBot, Subject: Subject{Site: ptr("example.com"), Src: &endpoint{IP: "192.0.2.9", Port: 1}}, Ts: "depois"})
			done := make(chan []byte, 1)
			go func() {
				b, _ := io.ReadAll(resp.Body)
				done <- b
			}()
			select {
			case b := <-done:
				if strings.Contains(string(b), "depois") {
					t.Errorf("veredito publicado depois da recarga chegou ao feed: %q", b)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("feed da chave cancelada não terminou")
			}
			if c, _, _ := f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", key, nil, ""); c != 401 {
				t.Errorf("requisição nova com a chave antiga: %d", c)
			}
		})
	}
}

// TestInternalKeyWithoutLimits: na 9003 a chave só escolhe domínios e modo (task 408, ADR 0073 item 4): com balde
// de 1, 50 forwardAuth seguidos dão 200 e o uso é gravado; na 9002 a mesma chave dá 429, e o 429 de uma chave em
// modo block deixa o health degraded com "block key limited" por 60 s.
func TestInternalKeyWithoutLimits(t *testing.T) {
	f := newFixture(t)
	k, key := f.createKey(KeyOptions{Name: "s", Domains: []string{"www.example.com"}, RatePerS: 1, Burst: 1, DailyQuota: 10})
	if c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", key, nil, validBatch()); c != 202 {
		t.Fatalf("ingest: %d %s", c, b)
	}
	f.putStore()
	for i := range 50 {
		if c, _, b := f.do(f.internal, "GET", "/bot/v1/auth", key, forkHeadersFor(), ""); c != 200 {
			t.Fatalf("forwardAuth %d na 9003: %d %s", i, c, b)
		}
	}
	if f.metrics.Get(metricRateLimited) != 0 {
		t.Fatalf("429 na 9003: %v", f.metrics.Get(metricRateLimited))
	}
	if err := f.srv.limiter.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := f.db.QueryRow(`SELECT requests FROM key_usage_daily WHERE key_id = ?`, k.ID).Scan(&n); err != nil || n != 51 {
		t.Fatalf("uso gravado: %d %v", n, err)
	}
	// na 9002 o balde vale; chave em observe não marca o health
	f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", key, nil, "")
	if c, _, _ := f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", key, nil, ""); c != 429 {
		t.Fatalf("9002: %d", c)
	}
	if _, reasons := f.srv.Status(); slices.Contains(reasons, "block key limited") {
		t.Fatalf("observe marcou o health: %v", reasons)
	}
	_, blk := f.createKey(KeyOptions{Name: "b", Domains: []string{"www.example.com"}, Mode: ModeBlock, RatePerS: 1, Burst: 1})
	f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", blk, nil, "")
	if c, _, _ := f.do(f.public, "GET", "/bot/v1/ip/192.0.2.1", blk, nil, ""); c != 429 {
		t.Fatalf("9002 block: %d", c)
	}
	if st, reasons := f.srv.Status(); st != "degraded" || !slices.Contains(reasons, "block key limited") {
		t.Fatalf("health: %s %v", st, reasons)
	}
	f.clock.Advance(61 * time.Second)
	if _, reasons := f.srv.Status(); slices.Contains(reasons, "block key limited") {
		t.Fatalf("ainda marcado: %v", reasons)
	}
}

// TestInternalUsageOutsideQuota: o uso da chave na 9003 (Count) fica gravado, mas não conta na cota diária da
// 9002, nem em memória nem depois de um reinício que relê key_usage_daily (task 413, ADR 0073 item 4).
func TestInternalUsageOutsideQuota(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	clock := newFakeClock(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	k := &Key{ID: "k1", RatePerS: 1000, Burst: 1000, DailyQuota: 3}
	l := NewLimiter(db, clock.Now)
	// 9003 antes da primeira chamada pela 9002 no dia: o pendente da 9003 não entra na cota em memória
	for range 5 {
		l.Count(k)
	}
	for i := range 2 {
		if ok, _ := l.Allow(ctx, k); !ok {
			t.Fatalf("9002 %d: recusada pelo uso da 9003 em memória", i+1)
		}
	}
	for range 5 {
		l.Count(k)
	}
	if err := l.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	var req, internal int
	if err := db.QueryRow("SELECT requests, internal_requests FROM key_usage_daily WHERE key_id = 'k1'").Scan(&req, &internal); err != nil ||
		req != 12 || internal != 10 {
		t.Fatalf("uso gravado: requests %d internal %d %v", req, internal, err)
	}
	// "reinício": limitador novo relê o dia; a cota restante da 9002 continua 1
	l = NewLimiter(db, clock.Now)
	l.Count(k)
	if ok, _ := l.Allow(ctx, k); !ok {
		t.Fatal("terceira pela 9002 recusada depois do reinício")
	}
	if ok, _ := l.Allow(ctx, k); ok {
		t.Fatal("quarta pela 9002 aceita acima da cota")
	}
}

// connBatch é um lote só de registros de conexão de www.example.com, com fs_conn_id e porta de origem distintos a
// partir de first.
func connBatch(first, n int) string {
	var b strings.Builder
	b.WriteString(`{"sender":"t","records":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"type":"connection","fs_conn_id":"01JC0X3K8V2T7Q9N4M6P%06d","ts":"2026-11-16T12:00:00.000000000Z",`+
			`"src":{"ip":"198.51.100.%d","port":%d},"dst":{"ip":"10.249.0.2","port":443},"entry_point":"websecure",`+
			`"sni":"www.example.com","alpn":"h2","tls_version":"1.3"}`, first+i, 1+(first+i)%200, 10000+first+i)
	}
	b.WriteString(`]}`)
	return b.String()
}

// TestIngestKeyRecords: na 9002 uma chave não passa do balde de registros (task 371, ADR 0073 item 3.1): o lote
// tira len(records) fichas de uma vez; sem fichas para o lote inteiro, 429 com Retry-After e nenhum registro
// aplicado; os registros aceitos vão a key_usage_daily.records; na 9003 a mesma chave não tem esse limite.
func TestIngestKeyRecords(t *testing.T) {
	f := newFixture(t)
	k, key := f.createKey(KeyOptions{Name: "r", Domains: []string{"www.example.com"}, Burst: 100, IngestRate: 10, IngestBurst: 20})
	if c, _, b := f.do(f.public, "POST", "/bot/v1/ingest/traefik", key, nil, connBatch(0, 20)); c != 202 ||
		string(b) != `{"accepted":20,"rejected":0}`+"\n" {
		t.Fatalf("primeiro lote: %d %s", c, b)
	}
	c, h, b := f.do(f.public, "POST", "/bot/v1/ingest/traefik", key, nil, connBatch(100, 5))
	if c != 429 || errorCode(t, b) != errRateLimited || h.Get("Retry-After") != "1" {
		t.Fatalf("sem fichas: %d %v %s", c, h, b)
	}
	if _, ok := f.srv.Index().Fork("01JC0X3K8V2T7Q9N4M6P000100", f.clock.Now()); ok {
		t.Fatal("registro aplicado no lote recusado")
	}
	f.clock.Advance(time.Second) // 10 fichas
	if c, h, _ := f.do(f.public, "POST", "/bot/v1/ingest/traefik", key, nil, connBatch(200, 15)); c != 429 || h.Get("Retry-After") != "1" {
		t.Fatalf("15 com 10 fichas: %d %v", c, h)
	}
	if c, _, b := f.do(f.public, "POST", "/bot/v1/ingest/traefik", key, nil, connBatch(300, 10)); c != 202 {
		t.Fatalf("10 com 10 fichas: %d %s", c, b)
	}
	if got := f.metrics.Get(ingestRefusedMetric(refusedKeyRecords)); got != 2 {
		t.Errorf("key_records %v", got)
	}
	// 9003: sem balde de registros
	if c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", key, nil, connBatch(400, 50)); c != 202 {
		t.Fatalf("9003: %d %s", c, b)
	}
	if err := f.srv.limiter.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	var records, limited int64
	if err := f.db.QueryRow(`SELECT records, limited FROM key_usage_daily WHERE key_id = ?`, k.ID).Scan(&records, &limited); err != nil ||
		records != 80 || limited != 2 {
		t.Fatalf("uso: records %d limited %d %v", records, limited, err)
	}
}

// TestIngestKeyShare: as conexões da 9003 (sem chave) não são despejadas por um ingest de chave que passa da parte
// dela no índice (10% de FS_BOT_MAX_CONNS): a chave despeja as próprias mais antigas (reason=key) (task 371, ADR
// 0073 item 3.2).
func TestIngestKeyShare(t *testing.T) {
	f := newFixture(t) // MaxConns 1000: parte da chave 100
	if c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, connBatch(0, 50)); c != 202 {
		t.Fatalf("9003: %d %s", c, b)
	}
	_, key := f.createKey(KeyOptions{Name: "s", Domains: []string{"www.example.com"}, Burst: 100, IngestBurst: 10_000, IngestRate: 10_000})
	for i := range 3 {
		if c, _, b := f.do(f.public, "POST", "/bot/v1/ingest/traefik", key, nil, connBatch(1000+i*1000, 1000)); c != 202 {
			t.Fatalf("lote %d da chave: %d %s", i, c, b)
		}
	}
	for i := range 50 {
		if _, ok := f.srv.Index().Fork(fmt.Sprintf("01JC0X3K8V2T7Q9N4M6P%06d", i), f.clock.Now()); !ok {
			t.Fatalf("conexão %d da 9003 despejada", i)
		}
	}
	if _, fork := f.srv.Index().Len(); fork != 150 {
		t.Fatalf("fork %d, quer 50 + 100 da chave", fork)
	}
	// as que ficaram da chave são as mais novas
	if _, ok := f.srv.Index().Fork("01JC0X3K8V2T7Q9N4M6P003999", f.clock.Now()); !ok {
		t.Fatal("a mais nova da chave saiu")
	}
	if got := f.metrics.Get(evictedMetric(evictKey)); got != 2900 {
		t.Errorf("evicted key %v", got)
	}
	if f.metrics.Get(evictedMetric(evictCount)) != 0 {
		t.Errorf("despejo global: %v", f.metrics.Get(evictedMetric(evictCount)))
	}
}

// TestStreamKeyShare: dos 64 clientes do feed, a 9002 usa até 48 e cada chave da 9002 até 4 (429 com Retry-After
// 15); a 9003 tem os 16 restantes (task 371, ADR 0073 item 3.3).
func TestStreamKeyShare(t *testing.T) {
	h := NewHub()
	for range MaxStreamClientsPerKey {
		if err := h.add(&streamClient{public: true, owner: "k1"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.add(&streamClient{public: true, owner: "k1"}); !errors.Is(err, errStreamKey) {
		t.Fatalf("quinto da chave: %v", err)
	}
	for i := MaxStreamClientsPerKey; i < MaxStreamClientsPublic; i++ {
		if err := h.add(&streamClient{public: true, owner: fmt.Sprintf("k%d", 2+i/MaxStreamClientsPerKey)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.add(&streamClient{public: true, owner: "outra"}); !errors.Is(err, errStreamFull) {
		t.Fatalf("49º da 9002: %v", err)
	}
	for range MaxStreamClients - MaxStreamClientsPublic {
		if err := h.add(&streamClient{}); err != nil {
			t.Fatalf("9003: %v", err)
		}
	}
	if err := h.add(&streamClient{}); !errors.Is(err, errStreamFull) {
		t.Fatalf("65º: %v", err)
	}

	// pela API: a quinta conexão da chave na 9002 recebe 429 com Retry-After 15
	f := newFixture(t)
	k, key := f.createKey(KeyOptions{Name: "feed", Domains: []string{"www.example.com"}, Burst: 100})
	for range MaxStreamClientsPerKey {
		if err := f.srv.hub.add(&streamClient{public: true, owner: k.ID}); err != nil {
			t.Fatal(err)
		}
	}
	c, hdr, b := f.do(f.public, "GET", "/bot/v1/stream", key, nil, "")
	if c != 429 || errorCode(t, b) != errRateLimited || hdr.Get("Retry-After") != "15" {
		t.Fatalf("feed acima da chave: %d %v %s", c, hdr, b)
	}
}

// checkMinimal403 confere o 403 do modo block (ADR 0074): corpo {"error":"forbidden"} sem detail, X-Traefix-Deny: 1
// e nenhum cabeçalho de veredito (X-Traefix-* nem X-Fs-*).
func checkMinimal403(t *testing.T, what string, code int, h http.Header, b []byte) {
	t.Helper()
	if code != http.StatusForbidden || string(b) != `{"error":"forbidden"}`+"\n" || h.Get("X-Traefix-Deny") != "1" {
		t.Fatalf("%s: %d %v %s", what, code, h, b)
	}
	for _, k := range verdictHeaders {
		if _, ok := h[k]; ok {
			t.Errorf("%s: 403 com %s: %v", what, k, h)
		}
	}
}

// TestBlockMinimal403: em modo block o 403 de um `bot` é mínimo e só ele leva X-Traefix-Deny; o 200 do observe e o
// 200 do block para quem não é bot ficam com os cabeçalhos e o Verdict; o veredito do 403 segue no feed e na
// consulta (task 367, ADR 0074).
func TestBlockMinimal403(t *testing.T) {
	f := newFixture(t)
	_, obs := f.createKey(KeyOptions{Name: "o", Domains: []string{"www.example.com"}})
	_, blk := f.createKey(KeyOptions{Name: "b", Domains: []string{"www.example.com"}, Mode: ModeBlock})
	c := &streamClient{queue: make(chan *Verdict, 8)}
	if err := f.srv.hub.add(c); err != nil {
		t.Fatal(err)
	}
	curl := curlAuthHeaders()
	curl["X-Fs-Ja4h"] = ja4hCurl
	code, h, b := f.do(f.internal, "GET", "/bot/v1/auth", obs, curl, "")
	var v Verdict
	if err := json.Unmarshal(b, &v); code != 200 || err != nil || v.Class != ClassBot || h.Get("X-Traefix-Verdict") != ClassBot ||
		h.Get("X-Fs-Score") != strconv.Itoa(v.Score) || h.Get("X-Traefix-Signals") != signalIDs(v.Signals) {
		t.Fatalf("observe: %d %v %s", code, h, b)
	}
	if _, ok := h["X-Traefix-Deny"]; ok {
		t.Fatalf("200 com X-Traefix-Deny: %v", h)
	}
	hdr := curlAuthHeaders()
	hdr["X-Fs-Ja4h"] = ja4hCurl
	hdr["X-Fs-Conn-Id"], hdr["X-Fs-Src-Port"] = "01JC0X3K8V2T7Q9N4M6P1R5S77", "51277"
	code, h, b = f.do(f.internal, "GET", "/bot/v1/auth", blk, hdr, "")
	checkMinimal403(t, "block", code, h, b)
	if errorCode(t, b) != errForbidden {
		t.Fatalf("código %s", b)
	}
	// o veredito do 403 vai ao feed e à consulta
	var got *Verdict
	for len(c.queue) > 0 {
		got = <-c.queue
	}
	if got == nil || got.Class != ClassBot || got.Subject.FsConnID == nil || *got.Subject.FsConnID != hdr["X-Fs-Conn-Id"] {
		t.Fatalf("feed: %+v", got)
	}
	_, _, b = f.do(f.internal, "GET", "/bot/v1/verdict/conn/"+hdr["X-Fs-Conn-Id"], blk, nil, "")
	if err := json.Unmarshal(b, &v); err != nil || v.Class != ClassBot {
		t.Fatalf("consulta: %s", b)
	}
	// erro do forwardAuth em block não leva o marcador
	code, h, _ = f.do(f.internal, "GET", "/bot/v1/auth", blk, map[string]string{"X-Fs-Src-Ip": "1"}, "")
	if _, ok := h["X-Traefix-Deny"]; code != 400 || ok {
		t.Fatalf("400 com X-Traefix-Deny: %d %v", code, h)
	}
}

// openapiPathBlocks separa o texto do openapi do bot por rota (linhas "  /bot/v1/...:" até a próxima rota ou o
// fim de paths), sem parser de YAML (nenhuma dependência nova, ADR 0009).
func openapiPathBlocks(t *testing.T) map[string]string {
	t.Helper()
	spec := string(openapiBytes(t))
	start := strings.Index(spec, "\npaths:\n")
	end := strings.Index(spec, "\nwebhooks:\n")
	if start < 0 || end < start {
		t.Fatal("openapi sem paths/webhooks")
	}
	blocks := map[string]string{}
	cur := ""
	for _, line := range strings.Split(spec[start+len("\npaths:\n"):end], "\n") {
		if strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":") {
			cur = strings.TrimSuffix(strings.TrimSpace(line), ":")
			continue
		}
		if cur != "" {
			blocks[cur] += line + "\n"
		}
	}
	return blocks
}

// TestOpenAPIDeclaresHandlerErrors: task 409 — o contrato declara o 403 forbidden_origin que o originGuard da 9003
// dá em toda rota, o 500 internal de /ip e /fingerprints e o 404 do filtro site do feed (spec 020 RF-03).
func TestOpenAPIDeclaresHandlerErrors(t *testing.T) {
	f := newFixture(t)
	blocks := openapiPathBlocks(t)
	if len(blocks) < 9 {
		t.Fatalf("só %d rotas no openapi: %v", len(blocks), blocks)
	}
	h := f.srv.Handler(true)
	for path, block := range blocks {
		declared := strings.Contains(block, `"403": { $ref: "#/components/responses/ForbiddenOrigin" }`) ||
			strings.Contains(block, `"403":`) && strings.Contains(block, "`forbidden_origin`")
		if !declared {
			t.Errorf("%s: sem o 403 forbidden_origin da 9003", path)
		}
		method := "GET"
		if strings.Contains(block, "\n    post:\n") || strings.HasPrefix(block, "    post:\n") {
			method = "POST"
		}
		// origem fora das redes da 9003: o guarda responde antes do mux, em qualquer rota
		req := httptest.NewRequest(method, strings.NewReplacer("{", "", "}", "").Replace(path), nil)
		req.RemoteAddr = "203.0.113.5:4000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || errorCode(t, rec.Body.Bytes()) != errForbiddenOrigin {
			t.Errorf("%s %s de fora: %d %s", method, path, rec.Code, rec.Body)
		}
	}
	for _, path := range []string{"/bot/v1/ip/{ip}", "/bot/v1/fingerprints/{kind}/{value}"} {
		if !strings.Contains(blocks[path], `"500": { $ref: "#/components/responses/Internal" }`) {
			t.Errorf("%s: sem o 500 internal", path)
		}
	}
	if !strings.Contains(blocks["/bot/v1/stream"], `"404":`) {
		t.Error("/bot/v1/stream: sem o 404 do site fora da chave")
	}

	// 500 internal de fato, com o banco fechado
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/bot/v1/ip/192.0.2.1", "/bot/v1/fingerprints/ja4/t13d1516h2_8daaf6152771_02713d6af862"} {
		if c, _, b := f.do(f.internal, "GET", path, "", nil, ""); c != http.StatusInternalServerError ||
			errorCode(t, b) != errInternal {
			t.Errorf("%s com o banco fechado: %d %s", path, c, b)
		}
	}
}
