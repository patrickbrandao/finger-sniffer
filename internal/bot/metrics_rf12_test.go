package bot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/webhook"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Formato das chaves do heartbeat (ADR 0056 item 4): nome, rótulos [a-z_]+ e valores [A-Za-z0-9_.:/-]{1,64}.
var (
	metricKeyRe   = regexp.MustCompile(`^([a-z_][a-z0-9_]*)(?:\{(.*)\})?$`)
	metricLabelRe = regexp.MustCompile(`^([a-z_]+)="([A-Za-z0-9_.:/-]{1,64})"$`)
)

// parseMetricKey separa nome e rótulos de uma chave do heartbeat; ok=false fora do formato da ADR 0056 item 4.
func parseMetricKey(key string) (name string, labels map[string]string, ok bool) {
	m := metricKeyRe.FindStringSubmatch(key)
	if m == nil {
		return "", nil, false
	}
	labels = map[string]string{}
	if m[2] != "" {
		for _, l := range strings.Split(m[2], ",") {
			lm := metricLabelRe.FindStringSubmatch(l)
			if lm == nil {
				return "", nil, false
			}
			labels[lm[1]] = lm[2]
		}
	}
	return m[1], labels, true
}

// TestHeartbeatMetricsRF12: conferência final da spec 018 RF-12 (task 283) — o heartbeat do bot traz todas as
// métricas da spec, com os rótulos da ADR 0056 item 4 (e os valores fixos de cada rótulo enumerado), os
// histogramas como _bucket{le}/_sum/_count sem o bucket +Inf (ADR 0057 item 3) e toda chave no formato.
func TestHeartbeatMetricsRF12(t *testing.T) {
	db, path := testDB(t)
	cfg := testConfig(path)
	cfg.ListsDir = t.TempDir() // listas baixadas ativas: bot_list_age_seconds{list}
	clock := newFakeClock(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	m := service.NewMetrics()
	s := New(cfg, Deps{DB: db, Now: clock.Now, Metrics: m, OpenAPI: openapiBytes(t), Version: "test"})
	ctx, cancel := context.WithCancel(context.Background())

	// Um envio de webhook (bot_webhook_sent_total{code}).
	rcv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer rcv.Close()
	s.hooks = webhook.New(webhook.Options{Client: rcv.Client(), Now: clock.Now, Count: m.Add})
	defer func() { cancel(); s.hooks.Wait() }()
	if _, _, _, err := CreateKey(ctx, db, KeyOptions{Name: "x", Domains: []string{"example.com"}, WebhookURL: rcv.URL + "/h"}, clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.keys.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	s.syncWebhooks(ctx)
	site := "example.com"
	s.hub.Publish(&Verdict{Class: ClassBot, Signals: []Signal{}, Subject: Subject{Kind: "request", Site: &site}, Ts: "2026-11-16T12:00:00.000000000Z"})
	for deadline := time.Now().Add(5 * time.Second); m.Get(`bot_webhook_sent_total{code="204"}`) == 0; {
		if time.Now().After(deadline) {
			t.Fatal("webhook não enviado")
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.purge(ctx)
	s.updateMetrics()

	snap := m.Snapshot()
	series := map[string][]map[string]string{}
	for key := range snap {
		name, labels, ok := parseMetricKey(key)
		if !ok {
			t.Errorf("chave fora do formato da ADR 0056 item 4: %q", key)
			continue
		}
		if labels["le"] == "+Inf" {
			t.Errorf("bucket +Inf enviado: %q", key)
		}
		series[name] = append(series[name], labels)
	}
	classes := []string{ClassHuman, ClassGoodBot, ClassBot, ClassSuspect, ClassUnknown}
	// labels: rótulos exigidos; values: valores que cada rótulo enumerado precisa ter (nil = qualquer).
	type want struct {
		labels []string
		values map[string][]string
	}
	required := map[string]want{
		"bot_verdicts_total":            {[]string{"class", "source"}, map[string][]string{"class": classes, "source": {SourceAuth, SourceQuery, SourceProbe}}},
		"bot_auth_seconds_bucket":       {[]string{"le"}, nil},
		"bot_auth_seconds_sum":          {},
		"bot_auth_seconds_count":        {},
		"bot_view_wait_total":           {[]string{"missing"}, map[string][]string{"missing": {"tcp", "fork"}}},
		"bot_ingest_records_total":      {},
		"bot_ingest_dropped_total":      {},
		"bot_conns_evicted_total":       {[]string{"reason"}, map[string][]string{"reason": {evictCount, evictBytes}}},
		"bot_index_bytes":               {},
		"bot_store_feed_messages_total": {},
		"bot_list_age_seconds":          {[]string{"list"}, map[string][]string{"list": {"googlebot", "aws"}}},
		"bot_list_entries":              {[]string{"list"}, map[string][]string{"list": {"known_clients", "googlebot", "aws"}}},
		"bot_webhook_sent_total":        {[]string{"code"}, nil},
		"bot_webhook_dropped_total":     {},
		"bot_keys_active":               {},
		"bot_rate_limited_total":        {},
		"bot_purged_total":              {[]string{"reason"}, map[string][]string{"reason": {"age", "size"}}},
		"bot_db_bytes":                  {},
		"bot_auth_wait_seconds_bucket":  {[]string{"le"}, nil},
		"bot_auth_wait_seconds_sum":     {},
		"bot_auth_wait_seconds_count":   {},
		"bot_ingest_parse_errors_total": {[]string{"part"}, map[string][]string{"part": {"client_hello", "h2_prefix"}}},
		"bot_agg_dropped_total":         {},
		"bot_auth_ja4h_total":           {[]string{"source"}, map[string][]string{"source": {ja4hFromHeader, ja4hFromIngest, ja4hNone}}},
	}
	for name, w := range required {
		got, ok := series[name]
		if !ok {
			t.Errorf("métrica da RF-12 ausente: %s", name)
			continue
		}
		for _, labels := range got {
			for _, l := range w.labels {
				if labels[l] == "" {
					t.Errorf("%s sem o rótulo %s: %v", name, l, labels)
				}
			}
			if len(labels) != len(w.labels) {
				t.Errorf("%s com rótulos %v, quer %v", name, labels, w.labels)
			}
		}
		for l, values := range w.values {
			for _, v := range values {
				if !slices.ContainsFunc(got, func(x map[string]string) bool { return x[l] == v }) {
					t.Errorf("%s sem a série %s=%q", name, l, v)
				}
			}
		}
	}
	for _, h := range []string{"bot_auth_seconds", "bot_auth_wait_seconds"} {
		if n := len(series[h+"_bucket"]); n != len(authBuckets) {
			t.Errorf("%s com %d buckets, quer %d", h, n, len(authBuckets))
		}
	}
}
