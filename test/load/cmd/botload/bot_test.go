//go:build load

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// botUnderTest é o serviço bot da árvore rodando em processo (banco temporário e a porta interna em httptest), para
// o gerador conversar com o bot de verdade sem o finger-01.
type botUnderTest struct {
	base    string
	key     string
	metrics *service.Metrics
	client  *http.Client
}

func newBotUnderTest(t *testing.T) *botUnderTest {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bot.db")
	db, err := bot.OpenDB(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	m := service.NewMetrics()
	cfg := bot.Config{
		PublicPort: 9002, InternalPort: 9003, DBPath: path, MaxBytes: 2 << 30, FlushInterval: time.Second,
		AggRetention: bot.MaxAggRetention, ConnTTL: 10 * time.Minute, MaxConns: 100000, ViewWait: 20 * time.Millisecond,
		RateHigh: 120, InternalAllow: []netip.Prefix{netip.MustParsePrefix("10.249.0.0/16")},
	}
	srv := bot.New(cfg, bot.Deps{DB: db, Metrics: m, Version: "test"})
	_, secret, _, err := bot.CreateKey(ctx, db, bot.KeyOptions{
		Name: "botload-test", Domains: []string{"fs-load.example", "*.hostile.fs-load.example"}, Mode: bot.ModeObserve,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Keys().Reload(ctx); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler(true))
	t.Cleanup(hs.Close)
	return &botUnderTest{base: hs.URL + "/bot/v1", key: secret, metrics: m, client: newClient(8)}
}

func (b *botUnderTest) ingest(t *testing.T, recs []map[string]any) {
	t.Helper()
	body, err := batchBody(recs)
	if err != nil {
		t.Fatal(err)
	}
	status, acc, rej, err := postIngest(context.Background(), b.client, b.base, b.key, body)
	if err != nil || status != http.StatusAccepted || acc != len(recs) || rej != 0 {
		t.Fatalf("ingest: status %d aceitos %d recusados %d (de %d) erro %v", status, acc, rej, len(recs), err)
	}
}

func (b *botUnderTest) auth(t *testing.T, h http.Header) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, b.base+"/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = h
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	var v struct {
		Class string `json:"class"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&v)
	return resp.StatusCode, resp.Header, v.Class
}

// TestGeneratorAgainstBot: os lotes traefix.fingerprint/v1 e os X-Traefix-* do gerador entram no bot desta árvore
// sem recusa nem divergência entre o calculado e o pronto (ADR 0062 item 3), o forwardAuth responde com a classe do
// golden de cada modelo nos dois conjuntos de cabeçalhos (ADR 0063 item 1), tanto com a visão do ingest quanto só
// com a dos cabeçalhos (primeira requisição), e o lote hostil padrão é aceito inteiro.
func TestGeneratorAgainstBot(t *testing.T) {
	b := newBotUnderTest(t)
	tpls, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, n := range []string{"chrome", "curl"} {
		raw, err := templatesFS.ReadFile("testdata/" + n + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var g struct {
			Verdict struct {
				Class string `json:"class"`
			} `json:"verdict"`
		}
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatal(err)
		}
		want[n] = g.Verdict.Class
	}
	const site = "fs-load.example"
	now := time.Now()
	for i, tpl := range tpls {
		for _, ingestFirst := range []bool{true, false} {
			c := &simConn{
				id:    fmt.Sprintf("01JC0X3K8V2T7Q9F4M6P1R5S%d%d", i, map[bool]int{true: 1, false: 2}[ingestFirst]),
				srcIP: fmt.Sprintf("203.0.113.%d", 10+i), srcPort: 40000 + i, dstIP: "10.249.0.2", dstPort: 443, tpl: tpl,
			}
			if ingestFirst {
				b.ingest(t, []map[string]any{connRecord(c, site, now)})
			}
			path := "/load/" + c.id + "/1"
			status, h, class := b.auth(t, authHeaders(c, site, path, b.key))
			if status != http.StatusOK || class != want[tpl.name] {
				t.Errorf("%s (ingest antes: %v): auth %d classe %q, esperado 200 %q", tpl.name, ingestFirst, status, class, want[tpl.name])
			}
			if h.Get("X-Traefix-Verdict") != class || h.Get("X-Fs-Verdict") != class {
				t.Errorf("%s: X-Traefix-Verdict %q X-Fs-Verdict %q, corpo %q", tpl.name, h.Get("X-Traefix-Verdict"), h.Get("X-Fs-Verdict"), class)
			}
			b.ingest(t, []map[string]any{requestRecord(c, site, path, now, now.Add(time.Millisecond))})
			if !ingestFirst {
				// o traefix manda o registro de conexão na primeira requisição, depois do forwardAuth
				b.ingest(t, []map[string]any{connRecord(c, site, now)})
			}
		}
	}
	rng := rand.New(rand.NewPCG(3, 4))
	var hostile []map[string]any
	for range 40 {
		hostile = append(hostile, hostileConn(rng, tpls[0], "hostile.fs-load.example", now)...)
	}
	b.ingest(t, hostile)

	m := b.metrics.Snapshot()
	t.Logf("métricas do bot: %v", m)
	for k, v := range m {
		if v != 0 && (strings.HasPrefix(k, "bot_ingest_fingerprint_mismatch_total") || strings.HasPrefix(k, "bot_ingest_parse_errors_total") ||
			strings.HasPrefix(k, "bot_ingest_ignored_total")) {
			t.Errorf("%s = %v, esperado 0", k, v)
		}
	}
	for _, k := range []string{
		`bot_auth_fingerprint_total{kind="tls",source="ingest"}`, `bot_auth_fingerprint_total{kind="tls",source="header"}`,
		`bot_auth_fingerprint_total{kind="h2",source="header"}`,
	} {
		if m[k] < float64(len(tpls)) {
			t.Errorf("%s = %v, esperado ≥ %d", k, m[k], len(tpls))
		}
	}
	if got, wantRecs := m["bot_ingest_records_total"], float64(len(hostile)+4*len(tpls)); got < wantRecs {
		t.Errorf("bot_ingest_records_total = %v, esperado ≥ %v", got, wantRecs)
	}
}
