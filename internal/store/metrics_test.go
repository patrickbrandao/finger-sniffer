package store

import (
	"context"
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
// internal/*), para o lint cobrir o que a vps602 expõe.
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
