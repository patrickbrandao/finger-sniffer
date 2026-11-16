package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// heartbeatNames são os nomes reais das métricas publicadas no heartbeat pelos serviços (pkg/service e
// internal/*), para o lint cobrir o que o servidor expõe.
var heartbeatNames = map[string][]string{
	event.ServiceWeb: {
		"buffered_bytes", "buffered_events", "dropped_events_total", "published_events_total", "web_acme_failures_total",
		"web_acme_issued_total", "web_connections_active", "web_connections_total", "web_events_marshal_errors_total",
		"web_events_oversize_total", "web_http1_requests_total", "web_websocket_connections_total", "web_websocket_frames_total",
	},
	event.ServiceDNS: {"dns_dropped_total", "dns_formerr_total", "dns_queries_tcp_total", "dns_queries_udp_total", "dns_rate_limited_total"},
	event.ServiceRaw: {"raw_active_sessions", "raw_sessions_total"},
	event.ServiceStore: {
		"store_app_events_total", "store_bad_batches_total", "store_bad_events_total", "store_conn_id_invalid_total",
		"store_conn_id_requests_total", "store_connections_open", "store_connections_total", "store_db_bytes", "store_dns_queries_total",
		"store_event_only_connections_total", "store_expunged_total", "store_ingest_lag_ms", "store_packets_total",
		"store_pending_events_total", "store_raw_stream_bytes_total", "store_stray_total", "store_degraded_connections_total",
		"store_ingest_errors_total", "store_finalize_retries_total", "store_batch_count_mismatch_total",
		"store_db_full_dropped_total", "store_late_packets_total", "store_late_dropped_total", "store_packet_spills_total",
	},
	event.ServiceCapture: {"published_events_total"},
}

func metricsHealth(context.Context) Health {
	h := Health{Services: map[string]ServiceHealth{}, Host: &HostHealth{SyncookiesSent: 3, Store: &DBHealth{DBBytes: 4096, Connections: 2}}}
	for svc, names := range heartbeatNames {
		m := map[string]float64{}
		for i, n := range names {
			m[n] = float64(i + 1)
		}
		status := event.StatusOK
		if svc == event.ServiceRaw {
			status = event.StatusDown
		}
		h.Services[svc] = ServiceHealth{Status: status, Version: "0.1.0", Metrics: m}
	}
	return h
}

// TestMetrics: registro próprio com as métricas da spec 004 "Métricas", tipos certos, buckets pedidos, lint do
// promlint limpo, route = padrão do mux, /metrics só na 9001.
func TestMetrics(t *testing.T) {
	in, _, _ := liveAPI(t, 64, 4)
	in.now = func() time.Time { return time.Unix(0, base+6e9) }
	m := newStoreMetrics(metricsHealth, in.flows.open, in.live)
	m.registerStream(&in.stream)
	m.registerSpace(newDBSpace(newFakeSpace(4<<30, 3<<30)))
	in.SetMetrics(m)
	r := NewRetention(in.db, time.Minute, 1<<30)
	r.OnPurge = m.purge

	// Tráfego: conexão TCP com h1, DNS, avulso e um purge.
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, probeID, http1Payload(0, "HTTP/1.1")),
		appMsg(t, event.SubjectDNSQuery, "udp", resolver, dnsSrv, 0, probeID, dnsPayload("udp")),
		batch(netip.MustParseAddrPort("192.0.2.77:4000"), mirror, protoTCP, []pkt{{6000, true, tcpRST, 0}}))
	if _, err := r.RunOnce(context.Background(), time.Unix(0, base).Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	in.live.OnSend(LiveHTTPRequest, 20*time.Millisecond)

	api := &API{
		OpenAPI: []byte("x"), Health: func(context.Context, time.Time) Health { return Health{} }, Now: time.Now,
		Q: NewQueries(in.db, in.flows.live, 65535), W: in.db, Live: in.live, Prom: m,
	}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	f := &apiFixture{srv: srv}
	id := ""
	_ = in.db.QueryRow("SELECT conn_id FROM connections").Scan(&id)
	for _, p := range []string{"/api/v1/connections/01JC0X3K8V2T7Q9N4M6P1R5S8W", "/api/v1/connections", "/nope", "/api/v1/stream?kind=x"} {
		f.get(t, p)
	}

	problems, err := testutil.GatherAndLint(m.reg)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("lint %s: %s", p.Metric, p.Text)
	}
	mfs, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]dto.MetricType{}
	byName := map[string]*dto.MetricFamily{}
	for _, mf := range mfs {
		types[mf.GetName()] = mf.GetType()
		byName[mf.GetName()] = mf
	}
	counter, gauge, hist := dto.MetricType_COUNTER, dto.MetricType_GAUGE, dto.MetricType_HISTOGRAM
	want := map[string]dto.MetricType{
		"fs_service_up": gauge, "fs_service_info": gauge, "fs_web_connections_active": gauge, "fs_dns_queries_udp_total": counter,
		"fs_store_events_ingested_total": counter, "fs_store_ingest_lag_seconds": hist, "fs_store_connections_open": gauge,
		"fs_store_connections_total": counter, "fs_store_connections_degraded_total": counter, "fs_store_stray_packets_total": counter,
		"fs_store_dns_queries_total": counter, "fs_store_purged_total": counter, "fs_store_db_bytes": gauge,
		"fs_store_record_ready_seconds": hist, "fs_store_live_clients": gauge, "fs_store_live_events_total": counter,
		"fs_store_live_dropped_total": counter, "fs_store_live_delay_seconds": hist, "fs_store_api_requests_total": counter,
		"fs_store_api_request_duration_seconds": hist,
		"fs_store_stream_lost_total":            counter, "fs_store_ingest_backlog_seconds": gauge, "fs_store_ingest_pending_messages": gauge,
		// banco no tmpfs (ADR 0045 item 5)
		"fs_store_db_fs_bytes": gauge, "fs_store_db_full_total": counter, "fs_store_db_full_dropped_total": counter,
		// nomes antigos preservados
		"fs_store_connections": gauge, "fs_host_syncookies_sent": gauge, "fs_store_app_events_total": counter,
	}
	for name, typ := range want {
		got, ok := types[name]
		if !ok {
			t.Errorf("missing %s", name)
		} else if got != typ {
			t.Errorf("%s: type %v want %v", name, got, typ)
		}
	}
	for _, gone := range []string{"fs_store_ingest_lag_ms", "fs_store_stray_total"} {
		if _, ok := types[gone]; ok {
			t.Errorf("%s must be replaced by the native metric", gone)
		}
	}
	fsBytes := map[string]float64{}
	for _, mt := range byName["fs_store_db_fs_bytes"].GetMetric() {
		fsBytes[mt.GetLabel()[0].GetValue()] = mt.GetGauge().GetValue()
	}
	if fsBytes["size"] != 4<<30 || fsBytes["free"] != 3<<30 {
		t.Errorf("fs_store_db_fs_bytes %v", fsBytes)
	}
	if _, err := m.purged.GetMetricWithLabelValues("space"); err != nil || len(byName["fs_store_purged_total"].GetMetric()) != 3 {
		t.Errorf("fs_store_purged_total must be pre-created with age, size and space")
	}
	// Buckets: API 1 ms–1 s; lag/atraso 10 ms–10 s.
	bounds := func(name string) (float64, float64) {
		b := byName[name].GetMetric()[0].GetHistogram().GetBucket()
		return b[0].GetUpperBound(), b[len(b)-1].GetUpperBound()
	}
	for name, w := range map[string][2]float64{
		"fs_store_api_request_duration_seconds": {0.001, 1}, "fs_store_ingest_lag_seconds": {0.01, 10},
		"fs_store_record_ready_seconds": {0.01, 10}, "fs_store_live_delay_seconds": {0.01, 10},
	} {
		lo, hi := bounds(name)
		if lo < w[0]*0.999 || lo > w[0]*1.001 || hi < w[1]*0.999 || hi > w[1]*1.001 {
			t.Errorf("%s buckets %g..%g", name, lo, hi)
		}
	}

	// Contagens do tráfego acima.
	if v := testutil.ToFloat64(m.connsTotal.WithLabelValues("tcp", "http1.1")); v != 1 {
		t.Errorf("connections_total{tcp,http1.1}=%v", v)
	}
	if v := testutil.ToFloat64(m.dnsQueries); v != 1 {
		t.Errorf("dns=%v", v)
	}
	if v := testutil.ToFloat64(m.stray); v != 1 {
		t.Errorf("stray=%v", v)
	}
	if v := testutil.ToFloat64(m.purged.WithLabelValues("age")); v != 1 {
		t.Errorf("purged age=%v", v)
	}
	if v := testutil.ToFloat64(m.ingested.WithLabelValues(event.SubjectWebHTTP1Request)); v != 1 {
		t.Errorf("ingested=%v", v)
	}

	// route é o padrão do mux, nunca o caminho com IDs.
	code, body := f.get(t, "/metrics")
	if code != 200 {
		t.Fatalf("/metrics %d", code)
	}
	for _, w := range []string{
		`fs_store_api_requests_total{code="404",route="GET /api/v1/connections/{conn_id}"} 1`,
		`fs_store_api_requests_total{code="200",route="GET /api/v1/connections"} 1`,
		`fs_store_api_requests_total{code="404",route="other"} 1`,
		`fs_store_api_requests_total{code="400",route="GET /api/v1/stream"} 1`,
		`fs_service_up{service="raw"} 0`, `fs_service_info{service="web",version="0.1.0"} 1`,
		`fs_store_live_clients{transport="sse"} 0`, `fs_store_db_bytes 4096`,
	} {
		if !strings.Contains(body, w) {
			t.Errorf("/metrics missing %q", w)
		}
	}
	if strings.Contains(body, "01JC0X3K8V2T7Q9N4M6P1R5S8W") {
		t.Error("route label with an ID")
	}
	https := httptest.NewServer(api.HTTPSHandler())
	defer https.Close()
	resp, err := http.Get(https.URL + "/metrics") //nolint:noctx,gosec // teste
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/metrics on 9000: %d", resp.StatusCode)
	}
}

// TestMetricsKeepsStreaming: o instrumento da API não quebra SSE (Flush) nem WebSocket (Hijack) e conta o 101.
func TestMetricsKeepsStreaming(t *testing.T) {
	in, h, _ := liveAPI(t, 64, 4)
	m := newStoreMetrics(metricsHealth, in.flows.open, h)
	api := &API{
		OpenAPI: []byte("x"), Health: func(context.Context, time.Time) Health { return Health{} }, Now: time.Now,
		Q: NewQueries(in.db, in.flows.live, 65535), W: in.db, Live: h, Prom: m,
	}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	sse, resp := sseClient(t, ctx, srv.URL+"/api/v1/stream")
	ws := wsClient(t, ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/api/v1/ws", "https://other.example")
	eventually(t, 2*time.Second, func() bool { s := h.Stats(); return s.Clients["sse"] == 1 && s.Clients["ws"] == 1 }, "clients")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	h.Publish(liveTestMsg(LiveHTTPRequest, "A", 443))
	for name, ch := range map[string]<-chan liveRecv{"sse": sse, "ws": ws} {
		if got := collect(ch, 2*time.Second, func(e []liveRecv) bool { return len(e) == 1 }); len(got) != 1 {
			t.Fatalf("%s: %d events", name, len(got))
		}
	}
	eventually(t, 2*time.Second, func() bool {
		var d dto.Metric
		_ = m.liveDelay.Write(&d)
		return d.GetHistogram().GetSampleCount() == 2
	}, "live delay not observed for both clients")
	cancel()
	eventually(t, 2*time.Second, func() bool {
		return testutil.ToFloat64(m.apiRequests.WithLabelValues("GET /api/v1/ws", "101")) == 1 &&
			testutil.ToFloat64(m.apiRequests.WithLabelValues("GET /api/v1/stream", "200")) == 1
	}, "streaming requests not counted")
}

// TestMetricsHeartbeatNativeCollision: depois de um lote descartado no modo banco cheio, o heartbeat do store traz
// store_db_full_dropped_total e o contador nativo fs_store_db_full_dropped_total também existe; o /metrics continua
// 200 e o lint limpo (task 259). Nenhum nome do heartbeat do store pode virar fs_<nome> de uma métrica nativa sem
// estar em replacedHeartbeat.
func TestMetricsHeartbeatNativeCollision(t *testing.T) {
	h := Health{Services: map[string]ServiceHealth{event.ServiceStore: {
		Status: event.StatusOK, Metrics: map[string]float64{"store_db_full_dropped_total": 3},
	}}}
	m := newStoreMetrics(func(context.Context) Health { return h }, func() int { return 0 }, nil)
	m.dbFullDropped(3)
	if _, err := m.reg.Gather(); err != nil {
		t.Fatalf("Gather: %v", err)
	}
	rec := httptest.NewRecorder()
	m.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "fs_store_db_full_dropped_total 3") {
		t.Errorf("contador nativo ausente:\n%s", rec.Body.String())
	}
	if probs, err := testutil.GatherAndLint(m.reg); err != nil || len(probs) > 0 {
		t.Errorf("lint: %v %v", err, probs)
	}

	// Nomes nativos (sem heartbeat) contra todos os nomes do heartbeat do store.
	bare := newStoreMetrics(func(context.Context) Health { return Health{} }, func() int { return 0 }, nil)
	fams, err := bare.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	native := map[string]bool{}
	for _, f := range fams {
		native[f.GetName()] = true
	}
	for _, k := range heartbeatNames[event.ServiceStore] {
		if native["fs_"+sanitize(k)] && !replacedHeartbeat[k] {
			t.Errorf("heartbeat %q colide com a métrica nativa fs_%s e não está em replacedHeartbeat", k, sanitize(k))
		}
	}
}

const invalidHeader = `# HELP fs_store_heartbeat_metrics_invalid_total Heartbeat metric keys ignored: malformed, conflicting label sets for the same name, or beyond 512 keys per heartbeat.
# TYPE fs_store_heartbeat_metrics_invalid_total counter
`

// TestMetricsHeartbeatLabels: chaves com rótulos do heartbeat do bot (ADR 0056 item 4) viram fs_<nome>{service,
// <rótulos>}; _bucket/_sum/_count viram um histograma; chave malformada ou com conjunto de rótulos conflitante é
// ignorada e contada uma vez por heartbeat em fs_store_heartbeat_metrics_invalid_total; o lint fica limpo.
func TestMetricsHeartbeatLabels(t *testing.T) {
	at1, at2 := "2026-11-16T10:00:00Z", "2026-11-16T10:00:05Z"
	bot := map[string]float64{
		`bot_verdicts_total{class="bot",source="auth"}`:      5,
		`bot_verdicts_total{source="traefix",class="human"}`: 2,
		`bot_auth_seconds_bucket{le="0.01"}`:                 3,
		`bot_auth_seconds_bucket{le="0.1"}`:                  4,
		"bot_auth_seconds_sum":                               0.25,
		"bot_auth_seconds_count":                             5,
		`bot_list_entries{list="tor"}`:                       100,
		"bot_keys_active":                                    7,
		// inválidas
		`bot_auth_seconds_bucket{le="+Inf"}`:                 5, // "+" fora de [A-Za-z0-9_.:/-]; o +Inf vem de _count
		`bot_verdicts_total{class="bot"}`:                    1, // outro conjunto de rótulos para o mesmo nome
		`bot_bad_total{class=bot}`:                           1, // valor sem aspas
		`bot_bad_total{Class="x"}`:                           1, // nome de rótulo fora de [a-z_]
		`bot_bad_total{class="a b"}`:                         1, // valor fora do conjunto
		`bot_bad_total{service="x"}`:                         1, // rótulo reservado
		`bot_bad_total{a="1",a="2"}`:                         1, // rótulo repetido
		`bot_bad_total{}`:                                    1,
		`bot_bad_total{a="1"`:                                1,
		`bot-bad_total{a="1"}`:                               1, // nome inválido
		`bot_bad_total{a="` + strings.Repeat("x", 65) + `"}`: 1, // valor longo demais
	}
	dns := map[string]float64{
		"dns_queries_udp_total":  9,
		"bot_list_entries":       1, // nome já publicado com {service,list} pelo bot
		"bot_auth_seconds_count": 1, // reservado pelo histograma do bot
	}
	h := Health{Services: map[string]ServiceHealth{
		event.ServiceBot: {Status: event.StatusOK, LastHeartbeat: &at1, Metrics: bot},
		event.ServiceDNS: {Status: event.StatusOK, LastHeartbeat: &at1, Metrics: dns},
	}}
	m := newStoreMetrics(func(context.Context) Health { return h }, func() int { return 0 }, nil)
	want := `# HELP fs_bot_auth_seconds Histogram from the service heartbeat (bot_auth_seconds).
# TYPE fs_bot_auth_seconds histogram
fs_bot_auth_seconds_bucket{service="bot",le="0.01"} 3
fs_bot_auth_seconds_bucket{service="bot",le="0.1"} 4
fs_bot_auth_seconds_bucket{service="bot",le="+Inf"} 5
fs_bot_auth_seconds_sum{service="bot"} 0.25
fs_bot_auth_seconds_count{service="bot"} 5
# HELP fs_bot_keys_active Value from the service heartbeat (bot_keys_active).
# TYPE fs_bot_keys_active gauge
fs_bot_keys_active{service="bot"} 7
# HELP fs_bot_list_entries Value from the service heartbeat (bot_list_entries).
# TYPE fs_bot_list_entries gauge
fs_bot_list_entries{list="tor",service="bot"} 100
# HELP fs_bot_verdicts_total Value from the service heartbeat (bot_verdicts_total).
# TYPE fs_bot_verdicts_total counter
fs_bot_verdicts_total{class="bot",service="bot",source="auth"} 5
fs_bot_verdicts_total{class="human",service="bot",source="traefix"} 2
# HELP fs_dns_queries_udp_total Value from the service heartbeat (dns_queries_udp_total).
# TYPE fs_dns_queries_udp_total counter
fs_dns_queries_udp_total{service="dns"} 9
` + invalidHeader + `fs_store_heartbeat_metrics_invalid_total{service="bot"} 11
fs_store_heartbeat_metrics_invalid_total{service="dns"} 2
`
	names := []string{
		"fs_bot_auth_seconds", "fs_bot_keys_active", "fs_bot_list_entries", "fs_bot_verdicts_total",
		"fs_dns_queries_udp_total", "fs_store_heartbeat_metrics_invalid_total",
	}
	// Duas coletas do mesmo heartbeat: os inválidos são contados uma vez só.
	for range 2 {
		if err := testutil.GatherAndCompare(m.reg, strings.NewReader(want), names...); err != nil {
			t.Fatal(err)
		}
	}
	if probs, err := testutil.GatherAndLint(m.reg); err != nil || len(probs) > 0 {
		t.Errorf("lint: %v %v", err, probs)
	}
	mfs, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if n := mf.GetName(); strings.HasPrefix(n, "fs_bot_bad") || strings.HasPrefix(n, "fs_bot_auth_seconds_") {
			t.Errorf("família inesperada %s", n)
		}
	}

	// Heartbeat novo do bot: os inválidos dele somam de novo; o do dns, que não mudou, fica.
	s := h.Services[event.ServiceBot]
	s.LastHeartbeat = &at2
	h.Services[event.ServiceBot] = s
	if err := testutil.GatherAndCompare(m.reg, strings.NewReader(invalidHeader+`fs_store_heartbeat_metrics_invalid_total{service="bot"} 22
fs_store_heartbeat_metrics_invalid_total{service="dns"} 2
`), "fs_store_heartbeat_metrics_invalid_total"); err != nil {
		t.Fatal(err)
	}
}

// TestMetricsHeartbeatIncompleteHistogram: _bucket sem _sum/_count não vira histograma; fica como contador solto.
func TestMetricsHeartbeatIncompleteHistogram(t *testing.T) {
	h := Health{Services: map[string]ServiceHealth{event.ServiceBot: {Status: event.StatusOK, Metrics: map[string]float64{
		`bot_wait_seconds_bucket{le="1"}`: 2,
	}}}}
	m := newStoreMetrics(func(context.Context) Health { return h }, func() int { return 0 }, nil)
	if err := testutil.GatherAndCompare(m.reg, strings.NewReader(`# HELP fs_bot_wait_seconds_bucket Value from the service heartbeat (bot_wait_seconds_bucket).
# TYPE fs_bot_wait_seconds_bucket counter
fs_bot_wait_seconds_bucket{le="1",service="bot"} 2
`), "fs_bot_wait_seconds_bucket"); err != nil {
		t.Fatal(err)
	}
}

// TestMetricsHeartbeatKeyLimit: acima de 512 chaves num heartbeat, o resto (em ordem alfabética) é ignorado e contado.
func TestMetricsHeartbeatKeyLimit(t *testing.T) {
	keys := map[string]float64{}
	for i := range 600 {
		keys[fmt.Sprintf("bot_k%03d", i)] = float64(i)
	}
	h := Health{Services: map[string]ServiceHealth{event.ServiceBot: {Status: event.StatusOK, Metrics: keys}}}
	m := newStoreMetrics(func(context.Context) Health { return h }, func() int { return 0 }, nil)
	mfs, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, mf := range mfs {
		got[mf.GetName()] = true
	}
	if !got["fs_bot_k511"] || got["fs_bot_k512"] || got["fs_bot_k599"] {
		t.Errorf("corte em 512 errado: k511=%v k512=%v", got["fs_bot_k511"], got["fs_bot_k512"])
	}
	if err := testutil.GatherAndCompare(m.reg, strings.NewReader(invalidHeader+`fs_store_heartbeat_metrics_invalid_total{service="bot"} 88
`), "fs_store_heartbeat_metrics_invalid_total"); err != nil {
		t.Fatal(err)
	}
}
