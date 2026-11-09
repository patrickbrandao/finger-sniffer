package store

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Buckets dos histogramas (task 054): API de 1 ms a 1 s; lag e atrasos de 10 ms a 10 s.
var (
	apiBuckets   = prometheus.ExponentialBucketsRange(0.001, 1, 11)
	delayBuckets = prometheus.ExponentialBucketsRange(0.01, 10, 11)
)

// replacedHeartbeat são métricas do heartbeat do próprio store que viraram métricas nativas (outro nome ou tipo):
// não são repetidas como fs_<nome>{service="store"}, para não haver dois tipos com o mesmo nome.
var replacedHeartbeat = map[string]bool{
	"store_connections_open":           true, // fs_store_connections_open
	"store_connections_total":          true, // fs_store_connections_total{l4,proto}
	"store_db_bytes":                   true, // fs_store_db_bytes
	"store_dns_queries_total":          true, // fs_store_dns_queries_total
	"store_ingest_lag_ms":              true, // fs_store_ingest_lag_seconds (histograma)
	"store_stray_total":                true, // fs_store_stray_packets_total
	"store_degraded_connections_total": true, // fs_store_connections_degraded_total
	"store_expunged_total":             true, // fs_store_purged_total{reason}
}

// storeMetrics são as métricas do /metrics (spec 004 RF-10), num registro próprio (sem o global).
type storeMetrics struct {
	reg         *prometheus.Registry
	handler     http.Handler
	ingested    *prometheus.CounterVec
	ingestLag   prometheus.Histogram
	connsTotal  *prometheus.CounterVec
	degraded    prometheus.Counter
	stray       prometheus.Counter
	dnsQueries  prometheus.Counter
	purged      *prometheus.CounterVec
	recordReady *prometheus.HistogramVec
	liveDelay   prometheus.Histogram
	apiRequests *prometheus.CounterVec
	apiDuration *prometheus.HistogramVec
}

// newStoreMetrics registra as métricas. health monta o estado agregado (heartbeats, host, banco); open conta as
// conexões abertas; live é o hub do tempo real (pode ser nil).
func newStoreMetrics(health func(context.Context) Health, open func() int, live *Hub) *storeMetrics {
	reg := prometheus.NewRegistry()
	m := &storeMetrics{
		reg: reg,
		ingested: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fs_store_events_ingested_total", Help: "Messages consumed from the FS_EVENTS stream, by subject.",
		}, []string{"subject"}),
		ingestLag: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "fs_store_ingest_lag_seconds", Help: "Delay from the event timestamp to the commit of its batch.", Buckets: delayBuckets,
		}),
		connsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fs_store_connections_total", Help: "Finished connections recorded, by L4 and protocol stack.",
		}, []string{"l4", "proto"}),
		degraded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fs_store_connections_degraded_total", Help: "Connections created in degraded mode (no pcap or raw bytes).",
		}),
		stray: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fs_store_stray_packets_total", Help: "Packets recorded without a connection.",
		}),
		dnsQueries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fs_store_dns_queries_total", Help: "DNS queries recorded.",
		}),
		purged: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fs_store_purged_total", Help: "Connections purged by retention, by reason (age or size).",
		}, []string{"reason"}),
		recordReady: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "fs_store_record_ready_seconds", Help: "Delay from the end of a connection to its final record being written, by reason (close, quic_close or idle).", Buckets: delayBuckets,
		}, []string{"reason"}),
		liveDelay: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "fs_store_live_delay_seconds", Help: "Delay from the source event to its delivery to a live client.", Buckets: delayBuckets,
		}),
		apiRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fs_store_api_requests_total", Help: "API requests, by mux pattern and status code.",
		}, []string{"route", "code"}),
		apiDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "fs_store_api_request_duration_seconds", Help: "API request duration, by mux pattern.", Buckets: apiBuckets,
		}, []string{"route"}),
	}
	reg.MustRegister(m.ingested, m.ingestLag, m.connsTotal, m.degraded, m.stray, m.dnsQueries, m.purged, m.recordReady,
		m.liveDelay, m.apiRequests, m.apiDuration)
	for _, r := range []string{"age", "size"} {
		m.purged.WithLabelValues(r)
	}
	for _, r := range []string{"close", "quic_close", "idle"} {
		m.recordReady.WithLabelValues(r)
	}
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "fs_store_connections_open", Help: "Connections currently open in the ingest.",
	}, func() float64 { return float64(open()) }))
	reg.MustRegister(&healthCollector{health: health})
	if live != nil {
		reg.MustRegister(&liveCollector{hub: live})
		live.OnSend = func(_ string, d time.Duration) { m.liveDelay.Observe(d.Seconds()) }
	}
	m.handler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})
	return m
}

// Os métodos abaixo aceitam receptor nil (ingest sem métricas, nos testes).

func (m *storeMetrics) event(subject string) {
	if m != nil {
		m.ingested.WithLabelValues(subject).Inc()
	}
}

func (m *storeMetrics) lag(d time.Duration) {
	if m != nil {
		m.ingestLag.Observe(d.Seconds())
	}
}

func (m *storeMetrics) connection(l4, proto string) {
	if m != nil {
		m.connsTotal.WithLabelValues(l4, proto).Inc()
	}
}

func (m *storeMetrics) degradedConn() {
	if m != nil {
		m.degraded.Inc()
	}
}

func (m *storeMetrics) strayPackets(n int) {
	if m != nil {
		m.stray.Add(float64(n))
	}
}

func (m *storeMetrics) dnsQuery() {
	if m != nil {
		m.dnsQueries.Inc()
	}
}

func (m *storeMetrics) purge(reason string, n int64) {
	if m != nil && n > 0 {
		m.purged.WithLabelValues(reason).Add(float64(n))
	}
}

// ready registra o atraso fim → registro. reason separa o fechamento (close, quic_close) da ociosidade (idle),
// que por definição só fecha depois do tempo ocioso e não entra na meta de 500 ms.
func (m *storeMetrics) ready(d time.Duration, reason string) {
	if m != nil {
		m.recordReady.WithLabelValues(reason).Observe(d.Seconds())
	}
}

// healthCollector expõe os heartbeats (fs_service_up, fs_service_info, fs_<métrica>{service}) e o estado do
// host e do banco, lidos a cada coleta. Coletor sem descrição fixa (os nomes vêm dos heartbeats).
type healthCollector struct {
	health func(context.Context) Health
}

func (c *healthCollector) Describe(chan<- *prometheus.Desc) {}

func (c *healthCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h := c.health(ctx)
	up := prometheus.NewDesc("fs_service_up", "1 while the service sends heartbeats (down after FS_HEALTH_DOWN_AFTER).", []string{"service"}, nil)
	info := prometheus.NewDesc("fs_service_info", "Version reported in the last heartbeat of each service.", []string{"service", "version"}, nil)
	names := make([]string, 0, len(h.Services))
	for n := range h.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	descs := map[string]*prometheus.Desc{}
	for _, svc := range names {
		s := h.Services[svc]
		v := 0.0
		if s.Status != event.StatusDown {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(up, prometheus.GaugeValue, v, svc)
		if s.Version != "" {
			ch <- prometheus.MustNewConstMetric(info, prometheus.GaugeValue, 1, svc, s.Version)
		}
		for k, val := range s.Metrics {
			if svc == event.ServiceStore && replacedHeartbeat[k] {
				continue
			}
			name := "fs_" + sanitize(k)
			d := descs[name]
			if d == nil {
				d = prometheus.NewDesc(name, "Value from the service heartbeat ("+k+").", []string{"service"}, nil)
				descs[name] = d
			}
			// Contadores acumulados no heartbeat terminam em _total; o resto é medida.
			typ := prometheus.GaugeValue
			if strings.HasSuffix(k, "_total") {
				typ = prometheus.CounterValue
			}
			ch <- prometheus.MustNewConstMetric(d, typ, val, svc)
		}
	}
	if h.Host != nil {
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("fs_host_syncookies_sent", "TcpExt SyncookiesSent of the host.", nil, nil),
			prometheus.GaugeValue, float64(h.Host.SyncookiesSent))
		if st := h.Host.Store; st != nil {
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("fs_store_db_bytes", "Size of the SQLite database in bytes.", nil, nil),
				prometheus.GaugeValue, float64(st.DBBytes))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("fs_store_connections", "Connections kept in the database.", nil, nil),
				prometheus.GaugeValue, float64(st.Connections))
		}
	}
}

// liveCollector expõe os contadores do hub do tempo real.
type liveCollector struct{ hub *Hub }

var (
	liveClientsDesc = prometheus.NewDesc("fs_store_live_clients", "Live clients connected, by transport.", []string{"transport"}, nil)
	liveEventsDesc  = prometheus.NewDesc("fs_store_live_events_total", "Live events emitted, by kind.", []string{"kind"}, nil)
	liveDropDesc    = prometheus.NewDesc("fs_store_live_dropped_total", "Live events dropped for slow clients.", nil, nil)
)

func (c *liveCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- liveClientsDesc
	ch <- liveEventsDesc
	ch <- liveDropDesc
}

func (c *liveCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.hub.Stats()
	for _, tr := range []string{"sse", "ws"} {
		ch <- prometheus.MustNewConstMetric(liveClientsDesc, prometheus.GaugeValue, float64(s.Clients[tr]), tr)
	}
	for _, k := range LiveKinds {
		ch <- prometheus.MustNewConstMetric(liveEventsDesc, prometheus.CounterValue, float64(s.Events[k]), k)
	}
	ch <- prometheus.MustNewConstMetric(liveDropDesc, prometheus.CounterValue, float64(s.Dropped))
}

// instrument mede cada requisição pelo padrão do mux (r.Pattern, nunca o caminho com IDs).
func (m *storeMetrics) instrument(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		route := r.Pattern
		if route == "" || route == "/" {
			route = "other"
		}
		m.apiRequests.WithLabelValues(route, itoa(sw.code)).Inc()
		m.apiDuration.WithLabelValues(route).Observe(time.Since(start).Seconds())
	})
}

func itoa(n int) string {
	if n < 100 || n > 999 {
		return "000"
	}
	return string([]byte{byte('0' + n/100), byte('0' + n/10%10), byte('0' + n%10)})
}

// statusWriter guarda o código da resposta; mantém Flush (SSE) e Hijack (WebSocket).
type statusWriter struct {
	http.ResponseWriter
	code  int
	wrote bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.code, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack not supported")
	}
	w.code, w.wrote = http.StatusSwitchingProtocols, true
	return hj.Hijack()
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
