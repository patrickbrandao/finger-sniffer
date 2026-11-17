package bot

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ja4hCurl é o JA4H completo de um curl h2 (partes a e b medidas na base própria, sem cookies).
const ja4hCurl = "ge20nn020000_5594a17e7e7e_000000000000_000000000000"

// curlAuthHeaders são os X-Fs-* de uma primeira requisição de curl sem visão do fork nem do store.
func curlAuthHeaders() map[string]string {
	h := forkHeadersFor()
	h["User-Agent"] = "curl/8.7.1"
	return h
}

// TestAuthJA4HHeader: ADR 0058 item 1 (task 292) — na primeira requisição de uma conexão, sem o ingest, o JA4H
// vem de X-Fs-Ja4h: curl sai `bot` 70 com ja4h_library e o modo block responde 403 com os X-Fs-*. Sem o cabeçalho,
// o comportamento anterior (`suspect` 50); malformado é ignorado e cai no ingest ou em nenhum.
func TestAuthJA4HHeader(t *testing.T) {
	f := newFixture(t)
	_, block := f.createKey(KeyOptions{Name: "b", Domains: []string{"*.example.com"}, Mode: ModeBlock, RatePerS: 1000, Burst: 1000})
	metric := func(src string) float64 { return f.metrics.Get(authJA4HMetric(src)) }

	hdr := curlAuthHeaders()
	hdr["X-Fs-Ja4h"] = ja4hCurl
	c, h, b := f.do(f.internal, "GET", "/bot/v1/auth", "", hdr, "")
	if c != 200 || h.Get("X-Fs-Verdict") != ClassBot || h.Get("X-Fs-Score") != "70" ||
		h.Get("X-Fs-Signals") != "ja4h_library,library_client" {
		t.Fatalf("com X-Fs-Ja4h: %d %v %s", c, h, b)
	}
	var v Verdict
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Fingerprints == nil || v.Fingerprints.JA4H == nil || *v.Fingerprints.JA4H != ja4hCurl || v.RulesVersion != "v1.3" {
		t.Errorf("fingerprints/versão: %+v %q", v.Fingerprints, v.RulesVersion)
	}
	if metric(ja4hFromHeader) != 1 || metric(ja4hFromIngest) != 0 || metric(ja4hNone) != 0 {
		t.Errorf("bot_auth_ja4h_total: header %v ingest %v none %v", metric(ja4hFromHeader), metric(ja4hFromIngest), metric(ja4hNone))
	}
	// modo block: 403 com o veredito nos cabeçalhos
	c, h, b = f.do(f.internal, "GET", "/bot/v1/auth", block, hdr, "")
	if c != 403 || h.Get("X-Fs-Verdict") != ClassBot || h.Get("X-Fs-Score") != "70" ||
		h.Get("X-Fs-Signals") != "ja4h_library,library_client" {
		t.Fatalf("block com X-Fs-Ja4h: %d %v %s", c, h, b)
	}

	// sem o cabeçalho e sem ingest: como antes, só library_client (suspect 50), passa no block
	c, h, b = f.do(f.internal, "GET", "/bot/v1/auth", block, curlAuthHeaders(), "")
	if c != 200 || h.Get("X-Fs-Verdict") != ClassSuspect || h.Get("X-Fs-Score") != "50" || h.Get("X-Fs-Signals") != "library_client" {
		t.Fatalf("sem X-Fs-Ja4h: %d %v %s", c, h, b)
	}
	if metric(ja4hNone) != 1 {
		t.Errorf("none = %v", metric(ja4hNone))
	}
	// malformados: ignorados (none sem ingest)
	for _, bad := range []string{
		strings.ToUpper(ja4hCurl), "ge20nn020000_5594a17e7e7e", ja4hCurl + "_000000000000",
		"ge20nn020000_5594a17e7e7g_000000000000_000000000000", "x" + ja4hCurl,
	} {
		hdr["X-Fs-Ja4h"] = bad
		if c, h, _ := f.do(f.internal, "GET", "/bot/v1/auth", "", hdr, ""); c != 200 || h.Get("X-Fs-Verdict") != ClassSuspect {
			t.Errorf("malformado %q: %d %v", bad, c, h)
		}
	}
	if metric(ja4hNone) != 6 || metric(ja4hFromHeader) != 2 {
		t.Errorf("none %v header %v", metric(ja4hNone), metric(ja4hFromHeader))
	}

	// com o ingest da conexão: malformado cai no JA4H do ingest; bem formado prevalece sobre ele
	f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, validBatch())
	hdr["X-Fs-Ja4h"] = "nope"
	c, _, b = f.do(f.internal, "GET", "/bot/v1/auth", "", hdr, "")
	if c != 200 {
		t.Fatalf("ingest: %d %s", c, b)
	}
	v = Verdict{}
	_ = json.Unmarshal(b, &v)
	if v.Fingerprints == nil || v.Fingerprints.JA4H == nil || *v.Fingerprints.JA4H != "ge20nn030000_x_y_z" {
		t.Errorf("JA4H do ingest: %+v", v.Fingerprints)
	}
	if metric(ja4hFromIngest) != 1 {
		t.Errorf("ingest = %v", metric(ja4hFromIngest))
	}
	hdr["X-Fs-Ja4h"] = ja4hCurl
	c, h, b = f.do(f.internal, "GET", "/bot/v1/auth", "", hdr, "")
	if c != 200 || !strings.Contains(h.Get("X-Fs-Signals"), "ja4h_library") {
		t.Fatalf("cabeçalho sobre o ingest: %d %v %s", c, h, b)
	}
	if metric(ja4hFromHeader) != 3 || metric(ja4hFromIngest) != 1 {
		t.Errorf("header %v ingest %v", metric(ja4hFromHeader), metric(ja4hFromIngest))
	}
}

// TestAuthErrorsWithoutVerdict: ADR 0058 item 3 (task 292) — nenhuma resposta de erro da auth traz X-Fs-Verdict
// (400, 401, 403 forbidden_origin, 429), nem os X-Fs-* postos antes do erro.
func TestAuthErrorsWithoutVerdict(t *testing.T) {
	f := newFixture(t)
	_, limited := f.createKey(KeyOptions{Name: "l", Domains: []string{"*.example.com"}, Mode: ModeBlock, RatePerS: 1, Burst: 1})
	_, other := f.createKey(KeyOptions{Name: "o", Domains: []string{"example.net"}, Mode: ModeBlock})
	hdr := curlAuthHeaders()
	hdr["X-Fs-Ja4h"] = ja4hCurl
	noVerdict := func(name string, c, want int, h http.Header, b []byte) {
		t.Helper()
		if c != want {
			t.Fatalf("%s: %d, quer %d: %s", name, c, want, b)
		}
		for _, k := range []string{"X-Fs-Verdict", "X-Fs-Score", "X-Fs-Signals"} {
			if _, ok := h[k]; ok {
				t.Errorf("%s com %s: %v", name, k, h)
			}
		}
		errorCode(t, b)
	}
	// 400 missing_fork_headers e 400 bad_request (site fora da chave)
	c, h, b := f.do(f.internal, "GET", "/bot/v1/auth", "", map[string]string{"X-Fs-Src-Ip": "1.2.3.4"}, "")
	noVerdict("400 missing_fork_headers", c, 400, h, b)
	c, h, b = f.do(f.internal, "GET", "/bot/v1/auth", other, hdr, "")
	noVerdict("400 site fora", c, 400, h, b)
	// 401 invalid_key
	c, h, b = f.do(f.internal, "GET", "/bot/v1/auth", "fsk_"+strings.Repeat("c", 52), hdr, "")
	noVerdict("401", c, 401, h, b)
	// 429: o balde de 1 gasto na primeira (que é o 403 do block, com veredito)
	c, h, _ = f.do(f.internal, "GET", "/bot/v1/auth", limited, hdr, "")
	if c != 403 || h.Get("X-Fs-Verdict") != ClassBot {
		t.Fatalf("block: %d %v", c, h)
	}
	c, h, b = f.do(f.internal, "GET", "/bot/v1/auth", limited, hdr, "")
	noVerdict("429", c, 429, h, b)
	// 403 forbidden_origin na 9003
	req := httptest.NewRequest("GET", "/bot/v1/auth", nil)
	req.RemoteAddr = "203.0.113.5:4000"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.srv.Handler(true).ServeHTTP(rec, req)
	noVerdict("403 forbidden_origin", rec.Code, 403, rec.Result().Header, rec.Body.Bytes())
	if errorCode(t, rec.Body.Bytes()) != errForbiddenOrigin {
		t.Errorf("403: %s", rec.Body)
	}

	// cabeçalhos do veredito postos antes de um erro não saem com ele
	rec = httptest.NewRecorder()
	rec.Header().Set("X-Fs-Verdict", ClassBot)
	rec.Header().Set("X-Fs-Score", "70")
	rec.Header().Set("X-Fs-Signals", "ja4h_library")
	writeError(rec, http.StatusInternalServerError, "internal", "x")
	noVerdict("500", rec.Code, 500, rec.Result().Header, rec.Body.Bytes())
}
