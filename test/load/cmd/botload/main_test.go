//go:build load

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ja4hPattern é o formato aceito no X-Traefix-Ja4h (ADR 0058 item 1; openapi do bot 0.4.0).
var ja4hPattern = regexp.MustCompile(`^[a-z0-9]{12}_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$`)

// schemaPath é a cópia do esquema publicado pelo traefix (ADR 0063 item 3), contrato dos lotes gerados aqui.
const schemaPath = "../../../../cmd/finger-sniffer-bot/traefix-fingerprint-v1.schema.json"

// TestAuthHeaders: os X-Traefix-* da spec 019 RF-05 (origem, JA4, JA3, Akamai, ALPN e JA4H bem formados), nenhum
// X-Fs-* e a chave do middleware (ADR 0063 item 1).
func TestAuthHeaders(t *testing.T) {
	tpls, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	ja4 := regexp.MustCompile(`^[tq][0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
	md5 := regexp.MustCompile(`^[0-9a-f]{32}$`)
	for _, tpl := range tpls {
		c := &simConn{id: "01JC0X3K8V2T7Q9F4M6P1R5S13", srcIP: "203.0.113.7", srcPort: 40000, dstPort: 8443, tpl: tpl}
		h := authHeaders(c, "fs-load.example", "/load/x/1", "fsk_test")
		for _, n := range []string{
			"X-Traefix-Src-Ip", "X-Traefix-Src-Port", "X-Traefix-Dst-Port", "X-Traefix-Conn-Id", "X-Traefix-Proto",
			"X-Traefix-H2", "X-Traefix-Alpn", "X-Forwarded-Host", "User-Agent",
		} {
			if h.Get(n) == "" {
				t.Errorf("%s: sem %s", tpl.name, n)
			}
		}
		for n := range h {
			if strings.HasPrefix(n, "X-Fs-") {
				t.Errorf("%s: %s no forwardAuth (só X-Traefix-*, ADR 0063 item 1)", tpl.name, n)
			}
		}
		if !ja4hPattern.MatchString(h.Get("X-Traefix-Ja4h")) {
			t.Errorf("%s: X-Traefix-Ja4h %q fora do formato", tpl.name, h.Get("X-Traefix-Ja4h"))
		}
		if !ja4.MatchString(h.Get("X-Traefix-Ja4")) || !md5.MatchString(h.Get("X-Traefix-Ja3")) {
			t.Errorf("%s: X-Traefix-Ja4 %q X-Traefix-Ja3 %q fora do formato", tpl.name, h.Get("X-Traefix-Ja4"), h.Get("X-Traefix-Ja3"))
		}
		if h.Get("X-Traefix-Alpn") != "h2,http/1.1" || h.Get("X-Traefix-Proto") != "h2" {
			t.Errorf("%s: X-Traefix-Alpn %q X-Traefix-Proto %q", tpl.name, h.Get("X-Traefix-Alpn"), h.Get("X-Traefix-Proto"))
		}
		if h.Get("Authorization") != "Bearer fsk_test" || h.Get("Cookie") != "" {
			t.Errorf("%s: Authorization %q Cookie %q", tpl.name, h.Get("Authorization"), h.Get("Cookie"))
		}
	}
	if got := alpnHeader([]string{"h2", "a,b", "50%", "\x01é"}); got != "h2,a%2Cb,50%25,%01%C3%A9" {
		t.Errorf("alpnHeader = %q", got)
	}
}

// TestTemplatesV1: o modelo do Chrome convertido tem as fingerprints prontas iguais às do lote de exemplo do
// traefix com o mesmo ClientHello e o mesmo prefixo h2 (internal/bot/testdata/ingest/h2-tcp.json, conferido com a
// FoxIO pelo traefix), e os dois modelos levam os bytes crus (rawBytes).
func TestTemplatesV1(t *testing.T) {
	tpls, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../../../internal/bot/testdata/ingest/h2-tcp.json")
	if err != nil {
		t.Fatal(err)
	}
	var ex struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(b, &ex); err != nil {
		t.Fatal(err)
	}
	exTLS, _ := ex.Records[0]["tls"].(map[string]any)
	exH2, _ := ex.Records[0]["http2"].(map[string]any)
	for _, tpl := range tpls {
		tls, _ := tpl.conn["tls"].(map[string]any)
		h2, _ := tpl.conn["http2"].(map[string]any)
		if tls["clientHello"] == "" || h2["prefix"] == "" || tpl.conn["type"] != "connection" || tpl.req["type"] != "request" {
			t.Errorf("%s: modelo sem os bytes crus ou fora do v1: %v", tpl.name, tpl.conn)
		}
		if tpl.name != "chrome" {
			continue
		}
		if tls["clientHello"] != exTLS["clientHello"] {
			t.Fatal("o ClientHello do modelo chrome deixou de ser o do lote de exemplo h2-tcp.json")
		}
		for _, k := range []string{"ja3", "ja3String", "ja3n", "ja3nString", "ja4", "ja4r", "ja4o"} {
			if tls[k] != exTLS[k] {
				t.Errorf("chrome: tls.%s %q, exemplo do traefix %q", k, tls[k], exTLS[k])
			}
		}
		if h2["akamai"] != exH2["akamai"] {
			t.Errorf("chrome: http2.akamai %q, exemplo do traefix %q", h2["akamai"], exH2["akamai"])
		}
	}
}

// TestBatchesMatchSchema: os lotes do auth (conexão e requisição) e o lote hostil padrão validam contra a cópia do
// esquema do traefix (ADR 0063 item 3; spec 017 RF-14).
func TestBatchesMatchSchema(t *testing.T) {
	sch := loadSchema(t)
	tpls, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 18, 6, 0, 0, 0, time.UTC)
	var auth []map[string]any
	for _, tpl := range tpls {
		c, tls := withTLS(tpl.conn)
		c["connId"], c["time"] = "01JC0X3K8V2T7Q9F4M6P1R5S13", ts(now)
		tls["sni"] = "fs-load.example"
		rq := clone(tpl.req)
		rq["connId"], rq["start"], rq["end"], rq["path"] = "01JC0X3K8V2T7Q9F4M6P1R5S13", ts(now), ts(now.Add(time.Millisecond)), "/load/x/1"
		auth = append(auth, c, rq)
	}
	rng := rand.New(rand.NewPCG(1, 2))
	hostile := hostileConn(rng, tpls[0], "hostile.fs-load.example", now)
	for name, recs := range map[string][]map[string]any{"auth": auth, "hostile": hostile} {
		body, err := batchBody(recs)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatal(err)
		}
		if errs := sch.validate(sch.root, doc, "$"); len(errs) > 0 {
			t.Errorf("lote %s fora do esquema do traefix:\n%s", name, strings.Join(errs, "\n"))
		}
	}
	// o validador reprova o que o esquema reprova (o teste não passa vazio)
	bad := map[string]any{
		"schema": "traefix.fingerprint/v2", "sender": "botload", "entryPoint": "e", "sentAt": ts(now),
		"records": []any{map[string]any{"type": "connection", "connId": "bad"}},
	}
	if errs := sch.validate(sch.root, roundTrip(t, bad), "$"); len(errs) < 3 {
		t.Errorf("lote inválido com %d erros, esperado schema, sender e o registro: %v", len(errs), errs)
	}
}

// TestHostileBatch: o lote hostil padrão (40 conexões × 17 registros) cabe no contrato do ingest (1024 registros,
// 4 MiB, caminho ≤ 256 bytes, campos ≤ 512 caracteres e da lista permitida, JA4H no formato) e tem valores únicos
// entre conexões.
func TestHostileBatch(t *testing.T) {
	tpls, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(1, 2))
	var recs []map[string]any
	now := time.Date(2026, 11, 17, 6, 0, 0, 0, time.UTC)
	for range 40 {
		recs = append(recs, hostileConn(rng, tpls[0], "hostile.fs-load.example", now)...)
	}
	body, err := batchBody(recs)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) > maxBatchRecords || len(body) > maxBatchBytes {
		t.Fatalf("lote com %d registros e %d bytes", len(recs), len(body))
	}
	t.Logf("lote hostil: %d registros, %d bytes", len(recs), len(body))
	var b struct {
		Schema  string `json:"schema"`
		Records []struct {
			Type   string `json:"type"`
			Path   string `json:"path"`
			JA4H   string `json:"ja4h"`
			Fields []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"fields"`
			TCP *struct {
				JA4T string `json:"ja4t"`
			} `json:"tcp"`
		} `json:"records"`
	}
	if err := json.Unmarshal(body, &b); err != nil || b.Schema != schemaV1 || len(b.Records) != len(recs) {
		t.Fatalf("lote: %v schema %q (%d registros)", err, b.Schema, len(b.Records))
	}
	uas, ja4ts := map[string]bool{}, map[string]bool{}
	for _, r := range b.Records {
		if r.Type == "connection" {
			if r.TCP == nil || r.TCP.JA4T == "" {
				t.Errorf("conexão hostil sem a visão TCP")
			} else {
				ja4ts[r.TCP.JA4T] = true
			}
			continue
		}
		if len(r.Path) > maxPathBytes {
			t.Errorf("caminho de %d bytes", len(r.Path))
		}
		for _, f := range r.Fields {
			if utf8.RuneCountInString(f.Value) > maxFieldValue {
				t.Errorf("campo %s com %d caracteres", f.Name, utf8.RuneCountInString(f.Value))
			}
			// só a lista permitida chega com valor ao bot (spec 019 RF-06): fora dela o campo não pesaria no índice
			if !allowedField(f.Name) {
				t.Errorf("campo %s fora da lista permitida", f.Name)
			}
		}
		if !ja4hPattern.MatchString(r.JA4H) {
			t.Errorf("JA4H %q fora do formato", r.JA4H)
		}
		ua := r.Fields[0].Value
		if r.Fields[0].Name != "user-agent" || len(ua) != hostileUALen {
			t.Errorf("UA de %d bytes, esperado %d", len(ua), hostileUALen)
		}
		uas[ua] = true
	}
	if want := 40 * hostileReqs; len(uas) != want {
		t.Errorf("%d UAs distintos, esperado %d", len(uas), want)
	}
	if len(ja4ts) < 39 {
		t.Errorf("%d JA4T distintos em 40 conexões", len(ja4ts))
	}
}

// allowedField é a lista padrão de fields do traefix e a lista permitida do bot (spec 019 RF-06, spec 018).
func allowedField(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "user-agent", "accept", "accept-language", "accept-encoding":
		return true
	}
	return strings.HasPrefix(n, "sec-ch-ua") || strings.HasPrefix(n, "sec-fetch-")
}

func roundTrip(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// ---------------------------------------------------------------- validador do esquema

// jsonSchema é um validador mínimo de JSON Schema 2020-12 com só as palavras que a cópia do esquema do traefix usa
// (type, required, properties, items, maxItems, anyOf, not, const, enum, pattern, maxLength, minimum, maximum,
// contentEncoding base64 e $ref local); palavra desconhecida faz o teste falhar, para o validador não ficar para
// trás quando o architect atualizar a cópia.
type jsonSchema struct {
	root map[string]any
	defs map[string]any
}

var knownKeywords = map[string]bool{
	"$schema": true, "$id": true, "$defs": true, "$ref": true, "title": true, "description": true, "format": true,
	"type": true, "required": true, "properties": true, "items": true, "maxItems": true, "anyOf": true, "not": true,
	"const": true, "enum": true, "pattern": true, "maxLength": true, "minimum": true, "maximum": true,
	"contentEncoding": true,
}

func loadSchema(t *testing.T) *jsonSchema {
	t.Helper()
	b, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	s := &jsonSchema{root: root}
	s.defs, _ = root["$defs"].(map[string]any)
	var walk func(v any, inProps bool)
	walk = func(v any, inProps bool) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				if !inProps && !knownKeywords[k] {
					t.Fatalf("esquema do traefix com a palavra %q, que o validador do botload não conhece", k)
				}
				walk(vv, !inProps && (k == "properties" || k == "$defs"))
			}
		case []any:
			for _, vv := range x {
				walk(vv, false)
			}
		}
	}
	walk(root, false)
	return s
}

func (s *jsonSchema) validate(sch map[string]any, v any, at string) []string {
	var errs []string
	fail := func(f string, a ...any) { errs = append(errs, at+": "+fmt.Sprintf(f, a...)) }
	if ref, ok := sch["$ref"].(string); ok {
		d, _ := s.defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
		if d == nil {
			fail("$ref %s desconhecido", ref)
		} else {
			errs = append(errs, s.validate(d, v, at)...)
		}
	}
	if typ, ok := sch["type"].(string); ok && !jsonType(typ, v) {
		fail("tipo %T, esperado %s", v, typ)
		return errs
	}
	if c, ok := sch["const"]; ok && c != v {
		fail("%v, esperado %v", v, c)
	}
	if e, ok := sch["enum"].([]any); ok && !slices.Contains(e, v) {
		fail("%v fora de %v", v, e)
	}
	if str, ok := v.(string); ok {
		if p, ok := sch["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(str) {
			fail("%q fora de %s", str, p)
		}
		if m, ok := sch["maxLength"].(float64); ok && float64(utf8.RuneCountInString(str)) > m {
			fail("%d caracteres, máximo %v", utf8.RuneCountInString(str), m)
		}
		if sch["contentEncoding"] == "base64" {
			if _, err := base64.StdEncoding.DecodeString(str); err != nil {
				fail("base64 inválido: %v", err)
			}
		}
	}
	if n, ok := v.(float64); ok {
		if m, ok := sch["minimum"].(float64); ok && n < m {
			fail("%v < %v", n, m)
		}
		if m, ok := sch["maximum"].(float64); ok && n > m {
			fail("%v > %v", n, m)
		}
	}
	if obj, ok := v.(map[string]any); ok {
		if req, ok := sch["required"].([]any); ok {
			for _, r := range req {
				if _, ok := obj[r.(string)]; !ok {
					fail("sem %s", r)
				}
			}
		}
		props, _ := sch["properties"].(map[string]any)
		for k, pv := range props {
			if x, ok := obj[k]; ok {
				errs = append(errs, s.validate(pv.(map[string]any), x, at+"."+k)...)
			}
		}
	}
	if arr, ok := v.([]any); ok {
		if m, ok := sch["maxItems"].(float64); ok && float64(len(arr)) > m {
			fail("%d itens, máximo %v", len(arr), m)
		}
		if it, ok := sch["items"].(map[string]any); ok {
			for i, x := range arr {
				errs = append(errs, s.validate(it, x, fmt.Sprintf("%s[%d]", at, i))...)
			}
		}
	}
	if alts, ok := sch["anyOf"].([]any); ok {
		var all []string
		match := false
		for i, alt := range alts {
			e := s.validate(alt.(map[string]any), v, fmt.Sprintf("%s(anyOf %d)", at, i))
			if len(e) == 0 {
				match = true
				break
			}
			all = append(all, e...)
		}
		if !match {
			errs = append(errs, all...)
		}
	}
	if not, ok := sch["not"].(map[string]any); ok && len(s.validate(not, v, at)) == 0 {
		fail("casa com o not")
	}
	return errs
}

func jsonType(typ string, v any) bool {
	switch typ {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "integer":
		n, ok := v.(float64)
		return ok && n == float64(int64(n))
	case "number":
		_, ok := v.(float64)
		return ok
	}
	return false
}

// TestReportWindow: a janela corta as amostras pelo início e o resumo separa erro, view.tcp e feed > 1 s.
func TestReportWindow(t *testing.T) {
	csv := samplesHeader + "\n" +
		"1000,auth,2000,200,1\n" +
		"2000,auth,4000,200,0\n" +
		"3000,auth,9000,500,0\n" +
		"4000,feed,1500000,200,1\n" +
		"5000,auth,1000,200,1\n"
	ss, err := parseSamples(strings.NewReader(csv), 1000, 5000)
	if err != nil {
		t.Fatal(err)
	}
	a := summarize(ss, "auth", nil)
	if a.N != 3 || a.Errors != 1 || a.Flag != 1 || a.Lat.N != 2 || a.Lat.Max != 4 {
		t.Fatalf("auth = %+v", a)
	}
	if f := summarize(ss, "feed", nil); f.N != 1 || f.Over != 1 {
		t.Fatalf("feed = %+v", f)
	}
	// última linha cortada (arquivo copiado em gravação) é ignorada; cortada no meio é erro
	if ss, err := parseSamples(strings.NewReader(csv+"17948954667872004"), 0, 0); err != nil || len(ss) != 5 {
		t.Fatalf("última linha cortada: %d amostras, %v", len(ss), err)
	}
	if _, err := parseSamples(strings.NewReader(samplesHeader+"\n1,auth\n2,auth,1,200,1\n"), 0, 0); err == nil {
		t.Fatal("linha cortada no meio do arquivo passou")
	}
}

// TestDiffBot: contas do heartbeat entre duas coletas, com o +Inf vindo do _count (ADR 0057 item 3).
func TestDiffBot(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, m map[string]float64) string {
		b, _ := json.Marshal(map[string]any{"services": map[string]any{"bot": map[string]any{"metrics": m}}})
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	before := write("a.json", map[string]float64{
		`bot_auth_seconds_bucket{le="0.01"}`: 10, `bot_auth_seconds_bucket{le="0.05"}`: 10, "bot_auth_seconds_count": 10,
		`bot_auth_ja4h_total{source="header"}`: 10, `bot_conns_evicted_total{reason="bytes"}`: 0,
	})
	after := write("b.json", map[string]float64{
		`bot_auth_seconds_bucket{le="0.01"}`: 105, `bot_auth_seconds_bucket{le="0.05"}`: 109, "bot_auth_seconds_count": 110,
		`bot_auth_ja4h_total{source="header"}`: 110, `bot_conns_evicted_total{reason="bytes"}`: 7, "bot_index_bytes": 1234,
		`bot_auth_fingerprint_total{kind="tls",source="ingest"}`: 60, `bot_auth_fingerprint_total{kind="tls",source="header"}`: 40,
		`bot_ingest_fingerprint_mismatch_total{kind="ja4t"}`: 2,
	})
	b, err := botMetrics(before)
	if err != nil {
		t.Fatal(err)
	}
	a, err := botMetrics(after)
	if err != nil {
		t.Fatal(err)
	}
	d := diffBot(b, a)
	if d.Auth != 100 || d.JA4H["header"] != 100 || d.Evicted["bytes"] != 7 || d.IndexBytes != 1234 {
		t.Fatalf("diffBot = %+v", d)
	}
	if d.FP["tls/ingest"] != 60 || d.FP["tls/header"] != 40 || d.FP["tcp/store"] != 0 || d.Mismatch["ja4t"] != 2 || d.Mismatch["ja4"] != 0 {
		t.Fatalf("fingerprints %v, divergências %v", d.FP, d.Mismatch)
	}
	if d.AuthLE10 != 0.95 || d.AuthLE50 != 0.99 {
		t.Fatalf("frações ≤ 10 ms %v e ≤ 50 ms %v, esperado 0,95 e 0,99", d.AuthLE10, d.AuthLE50)
	}
}

// TestFeedSample: atraso ts → chegada; connection.updated do raw marcado (flag 1); stream.dropped contado.
func TestFeedSample(t *testing.T) {
	now := time.Date(2026, 11, 17, 6, 0, 1, 0, time.UTC)
	s, ok := feedSample([]byte(`{"kind":"connection.opened","ts":"2026-11-17T06:00:00.75Z","data":{"proto":"tcp"}}`), now)
	if !ok || s.kind != "store_feed" || s.latUS != 250000 || s.flag != 0 {
		t.Fatalf("opened: %+v %v", s, ok)
	}
	if s, ok := feedSample([]byte(`{"kind":"connection.updated","ts":"2026-11-17T06:00:00Z","data":{"proto":"raw"}}`), now); !ok || s.flag != 1 {
		t.Fatalf("updated raw: %+v %v", s, ok)
	}
	if s, ok := feedSample([]byte(`{"kind":"stream.dropped","ts":"2026-11-17T06:00:00Z","dropped":7}`), now); !ok || s.kind != "store_feed_dropped" || s.flag != 7 {
		t.Fatalf("dropped: %+v %v", s, ok)
	}
	if _, ok := feedSample([]byte(`: ping`), now); ok {
		t.Fatal("linha que não é JSON virou amostra")
	}
}
