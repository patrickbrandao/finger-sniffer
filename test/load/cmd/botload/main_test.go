//go:build load

package main

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/patrickbrandao/finger-sniffer/internal/bot"
)

// ja4hPattern é o formato aceito no X-Fs-Ja4h (ADR 0058 item 1; openapi do bot 0.2.0).
var ja4hPattern = regexp.MustCompile(`^[a-z0-9]{12}_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$`)

// TestReadKey: só a primeira linha, com o prefixo fsk_; o erro não ecoa o que foi lido.
func TestReadKey(t *testing.T) {
	k, err := readKey(strings.NewReader("fsk_abc\nresto\n"))
	if err != nil || k != "fsk_abc" {
		t.Fatalf("readKey = %q, %v", k, err)
	}
	if _, err := readKey(strings.NewReader("segredo-errado\n")); err == nil || strings.Contains(err.Error(), "segredo") {
		t.Fatalf("readKey sem fsk_: %v", err)
	}
}

// TestAuthHeaders: os X-Fs-* da RF-06 com o X-Fs-Ja4h bem formado e a chave do middleware (ADR 0058).
func TestAuthHeaders(t *testing.T) {
	tpls, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range tpls {
		c := &simConn{id: "01JC0X3K8V2T7Q9F4M6P1R5S13", srcIP: "203.0.113.7", srcPort: 40000, dstPort: 8443, tpl: tpl}
		h := authHeaders(c, "fs-load.example", "/load/x/1", "fsk_test")
		for _, n := range []string{"X-Fs-Src-Ip", "X-Fs-Src-Port", "X-Fs-Dst-Port", "X-Fs-Conn-Id", "X-Fs-Proto", "X-Forwarded-Host", "User-Agent"} {
			if h.Get(n) == "" {
				t.Errorf("%s: sem %s", tpl.name, n)
			}
		}
		if !ja4hPattern.MatchString(h.Get("X-Fs-Ja4h")) {
			t.Errorf("%s: X-Fs-Ja4h %q fora do formato", tpl.name, h.Get("X-Fs-Ja4h"))
		}
		if h.Get("Authorization") != "Bearer fsk_test" || h.Get("Cookie") != "" {
			t.Errorf("%s: Authorization %q Cookie %q", tpl.name, h.Get("Authorization"), h.Get("Cookie"))
		}
	}
}

// TestHostileBatch: o lote hostil padrão (40 conexões × 17 registros) cabe no contrato do ingest (1024 registros,
// 4 MiB, caminho ≤ 256 bytes, campos ≤ 512 caracteres, JA4H no formato) e tem valores únicos entre conexões.
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
	b, err := bot.DecodeIngestBatch(body)
	if err != nil || len(b.Records) != len(recs) {
		t.Fatalf("DecodeIngestBatch: %v (%d registros)", err, len(b.Records))
	}
	uas := map[string]bool{}
	for _, raw := range b.Records {
		var r bot.TraefikRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		if r.Type != "request" {
			continue
		}
		if len(r.Path) > maxPathBytes {
			t.Errorf("caminho de %d bytes", len(r.Path))
		}
		for k, v := range r.Fields {
			if utf8.RuneCountInString(v) > maxFieldValue {
				t.Errorf("campo %s com %d caracteres", k, utf8.RuneCountInString(v))
			}
		}
		if r.JA4H == nil || !ja4hPattern.MatchString(*r.JA4H) {
			t.Errorf("JA4H %v fora do formato", r.JA4H)
		}
		ua := r.Fields["user-agent"]
		if len(ua) != hostileUALen {
			t.Errorf("UA de %d bytes, esperado %d", len(ua), hostileUALen)
		}
		uas[ua] = true
	}
	if want := 40 * hostileReqs; len(uas) != want {
		t.Errorf("%d UAs distintos, esperado %d", len(uas), want)
	}
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
