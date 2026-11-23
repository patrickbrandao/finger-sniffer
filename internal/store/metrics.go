package store

import (
	"bufio"
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Buckets dos histogramas (task 054): API de 1 ms a 1 s; lag e atrasos de 10 ms a 10 s.
var (
	apiBuckets   = prometheus.ExponentialBucketsRange(0.001, 1, 11)
	delayBuckets = prometheus.ExponentialBucketsRange(0.01, 10, 11)
	// writerBuckets: comandos do escritor SQLite, de 0,5 ms a 10 s (task 248).
	writerBuckets = prometheus.ExponentialBucketsRange(0.0005, 10, 16)
)

// writerOps são os valores de op em fs_store_writer_seconds (task 248).
var writerOps = []string{opIngestTx, opIngestCommit, opFinalizeTx, opPurgeDelete, opPurgeVacuum, opCheckpoint, opWALRestart}

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
	"store_db_full_dropped_total":      true, // fs_store_db_full_dropped_total (mesmo nome, sem o rótulo service)
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
	midflow     prometheus.Counter
	dnsQueries  prometheus.Counter
	purged      *prometheus.CounterVec
	recordReady *prometheus.HistogramVec
	flowsDrop   *prometheus.CounterVec
	liveDelay   prometheus.Histogram
	apiRequests *prometheus.CounterVec
	apiDuration *prometheus.HistogramVec
	apiReject   *prometheus.CounterVec
	writer      *prometheus.HistogramVec
	walFrames   prometheus.Gauge
	dbFullErrs  prometheus.Counter
	dbFullDrop  prometheus.Counter
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
		midflow: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fs_store_stray_midflow_total", Help: "Stray TCP packets (not RST) of flows whose start (SYN or SYN-ACK) the store never saw.",
		}),
		dnsQueries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fs_store_dns_queries_total", Help: "DNS queries recorded.",
		}),
		purged: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fs_store_purged_total", Help: "Connections purged by retention, by reason (age, size, or space: free space of the database filesystem).",
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
	m.apiReject = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fs_store_api_rejected_total",
		Help: "API requests refused with 503, by mux pattern and reason (busy: JSON response budget exhausted; shutting_down).",
	}, []string{"route", "reason"})
	m.writer = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "fs_store_writer_seconds",
		Help:    "Duration of SQLite writer operations, by op (ingest_tx, ingest_commit, finalize_tx, purge_delete, purge_vacuum, wal_checkpoint, wal_restart).",
		Buckets: writerBuckets,
	}, []string{"op"})
	m.walFrames = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "fs_store_wal_frames", Help: "Frames (4 KiB pages) in the SQLite WAL at the last checkpoint.",
	})
	m.dbFullErrs = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fs_store_db_full_total", Help: "SQLITE_FULL errors (database filesystem full) in store writes.",
	})
	m.dbFullDrop = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fs_store_db_full_dropped_total", Help: "FS_EVENTS messages acknowledged and dropped because even the batch without blobs did not fit the database.",
	})
	m.flowsDrop = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fs_store_flows_dropped_total",
		Help: "Flow table cap (8192 entries): unestablished entries evicted, and packets of new 5-tuples refused with no entry to evict.",
	}, []string{"reason"})
	reg.MustRegister(m.ingested, m.ingestLag, m.connsTotal, m.degraded, m.stray, m.midflow, m.dnsQueries, m.purged, m.recordReady,
		m.liveDelay, m.apiRequests, m.apiDuration, m.apiReject, m.flowsDrop, m.writer, m.walFrames, m.dbFullErrs, m.dbFullDrop)
	for _, op := range writerOps {
		m.writer.WithLabelValues(op)
	}
	for _, r := range []string{dropEvicted, dropTableFull} {
		m.flowsDrop.WithLabelValues(r)
	}
	for _, r := range []string{"age", "size", "space"} {
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

// registerStream expõe a posição do consumidor no FS_EVENTS (ADR 0041 item 3): mensagens que nunca chegaram
// (saltos de sequência), backlog em segundos e mensagens pendentes.
func (m *storeMetrics) registerStream(st *streamStats) {
	m.reg.MustRegister(
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "fs_store_stream_lost_total", Help: "FS_EVENTS messages that never reached the store (stream sequence gaps: expired by max_age or max_bytes).",
		}, func() float64 { l, _, _ := st.snapshot(); return float64(l) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fs_store_ingest_backlog_seconds", Help: "Wall clock (at scrape) minus the stream timestamp of the last message processed (0 once the consumer catches up).",
		}, func() float64 { _, b, _ := st.snapshot(); return b }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fs_store_ingest_pending_messages", Help: "Messages still pending for the store consumer (NumPending of the last message processed).",
		}, func() float64 { _, _, p := st.snapshot(); return float64(p) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "fs_store_stream_recreated_total", Help: "Times the store recreated FS_EVENTS and its consumer after they were gone (NATS restart with the in-memory stream); messages lost meanwhile are not counted in fs_store_stream_lost_total.",
		}, func() float64 { return float64(st.recreatedTotal()) }),
	)
}

// dbFSBytesDesc é fs_store_db_fs_bytes{kind}: tamanho e livre do sistema de arquivos do banco (ADR 0045).
var dbFSBytesDesc = prometheus.NewDesc("fs_store_db_fs_bytes", "Size and free space of the filesystem holding the database (statfs), by kind (size or free).", []string{"kind"}, nil)

// spaceCollector lê o statfs do banco a cada coleta.
type spaceCollector struct{ sp *dbSpace }

func (c spaceCollector) Describe(ch chan<- *prometheus.Desc) { ch <- dbFSBytesDesc }

func (c spaceCollector) Collect(ch chan<- prometheus.Metric) {
	size, free, _ := c.sp.read() // sem statfs: 0
	ch <- prometheus.MustNewConstMetric(dbFSBytesDesc, prometheus.GaugeValue, float64(size), "size")
	ch <- prometheus.MustNewConstMetric(dbFSBytesDesc, prometheus.GaugeValue, float64(free), "free")
}

// registerSpace expõe o espaço do sistema de arquivos do banco (ADR 0045 item 5).
// registerAPIBudget expõe os bytes reservados pelas respostas JSON em andamento (ADR 0066 item 4).
func (m *storeMetrics) registerAPIBudget(b *jsonBudget) {
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "fs_store_api_json_bytes_in_flight", Help: "Bytes of finite JSON API responses built and not yet written (budget of 256 MiB).",
	}, func() float64 { return float64(b.used.Load()) }))
}

// apiRejected conta um 503 do orçamento ou do desligamento (ADR 0066 item 4).
func (m *storeMetrics) apiRejected(route, reason string) {
	if m == nil {
		return
	}
	m.apiReject.WithLabelValues(route, reason).Inc()
}

func (m *storeMetrics) registerSpace(sp *dbSpace) { m.reg.MustRegister(spaceCollector{sp: sp}) }

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

func (m *storeMetrics) strayMidflow(n int) {
	if m != nil && n > 0 {
		m.midflow.Add(float64(n))
	}
}

func (m *storeMetrics) dnsQuery() {
	if m != nil {
		m.dnsQueries.Inc()
	}
}

func (m *storeMetrics) flowDropped(reason string) {
	if m != nil {
		m.flowsDrop.WithLabelValues(reason).Inc()
	}
}

// writerOp registra a duração de uma operação do escritor (task 248).
func (m *storeMetrics) writerOp(op string, d time.Duration) {
	if m != nil {
		m.writer.WithLabelValues(op).Observe(d.Seconds())
	}
}

func (m *storeMetrics) dbFull() {
	if m != nil {
		m.dbFullErrs.Inc()
	}
}

func (m *storeMetrics) dbFullDropped(n int) {
	if m != nil {
		m.dbFullDrop.Add(float64(n))
	}
}

func (m *storeMetrics) wal(frames int64) {
	if m != nil {
		m.walFrames.Set(float64(frames))
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

// healthCollector expõe os heartbeats (fs_service_up, fs_service_info, fs_<métrica>{service,<rótulos>}) e o estado
// do host e do banco, lidos a cada coleta. Coletor sem descrição fixa (os nomes vêm dos heartbeats).
type healthCollector struct {
	health func(context.Context) Health

	// mu protege seen e invalid: fs_store_heartbeat_metrics_invalid_total soma as chaves rejeitadas uma vez por
	// heartbeat (identificado por last_heartbeat), não a cada coleta.
	mu      sync.Mutex
	seen    map[string]string
	invalid map[string]float64
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen, c.invalid = map[string]string{}, map[string]float64{}
	}
	fams := heartbeatFamilies{}
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
		inv := fams.emit(ch, svc, s.Metrics)
		id := ""
		if s.LastHeartbeat != nil {
			id = *s.LastHeartbeat
		}
		if last, ok := c.seen[svc]; !ok || last != id {
			c.seen[svc] = id
			c.invalid[svc] += float64(inv)
		}
		ch <- prometheus.MustNewConstMetric(heartbeatInvalidDesc, prometheus.CounterValue, c.invalid[svc], svc)
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

// maxHeartbeatMetrics é o limite de chaves por heartbeat de um serviço (ADR 0056 item 4): em ordem alfabética, o
// que passar disso é ignorado e contado como inválido.
const maxHeartbeatMetrics = 512

var (
	heartbeatInvalidDesc = prometheus.NewDesc("fs_store_heartbeat_metrics_invalid_total",
		"Heartbeat metric keys ignored: malformed, conflicting label sets for the same name, or beyond 512 keys per heartbeat.",
		[]string{"service"}, nil)
	hbNameRe       = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	hbLabelNameRe  = regexp.MustCompile(`^[a-z_]+$`)
	hbLabelValueRe = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,64}$`)
)

// hbLabel é um rótulo de uma chave do heartbeat.
type hbLabel struct{ name, value string }

// hbSeries é uma chave do heartbeat já separada em nome e rótulos (ordenados pelo nome).
type hbSeries struct {
	key     string
	name    string // sem o prefixo fs_
	labels  []hbLabel
	labeled bool
	value   float64
	used    bool // absorvida num histograma
}

// canon é a forma canônica dos rótulos (para casar _bucket, _sum e _count da mesma série).
func canon(ls []hbLabel) string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.name)
		b.WriteByte('=')
		b.WriteString(l.value)
		b.WriteByte(',')
	}
	return b.String()
}

// parseHeartbeatKey separa nome{rotulo="valor",...}. Chave sem chaves segue como antes (nome com sanitize).
func parseHeartbeatKey(k string) (hbSeries, bool) {
	i := strings.IndexByte(k, '{')
	if i < 0 {
		return hbSeries{key: k, name: sanitize(k)}, true
	}
	name := k[:i]
	if !hbNameRe.MatchString(name) || !strings.HasSuffix(k, "}") || len(k) < i+3 {
		return hbSeries{}, false
	}
	parts := strings.Split(k[i+1:len(k)-1], ",")
	ls := make([]hbLabel, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		n, v, ok := strings.Cut(p, "=")
		// service é o rótulo que o store acrescenta; repeti-lo quebraria a série.
		if !ok || !hbLabelNameRe.MatchString(n) || n == "service" || seen[n] {
			return hbSeries{}, false
		}
		if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' || !hbLabelValueRe.MatchString(v[1:len(v)-1]) {
			return hbSeries{}, false
		}
		seen[n] = true
		ls = append(ls, hbLabel{n, v[1 : len(v)-1]})
	}
	sort.Slice(ls, func(a, b int) bool { return ls[a].name < ls[b].name })
	return hbSeries{key: k, name: name, labels: ls, labeled: true}, true
}

// famKind é o tipo de uma família publicada a partir dos heartbeats.
type famKind int

const (
	famGauge famKind = iota
	famCounter
	famHistogram
	famHistogramPart // nome_bucket, nome_sum e nome_count reservados por um histograma
)

var histogramSuffixes = []string{"_bucket", "_sum", "_count"}

type heartbeatFamily struct {
	kind famKind
	sig  string // nomes dos rótulos
	desc *prometheus.Desc
}

// heartbeatFamilies garante uma descrição por nome: o primeiro conjunto de rótulos (e tipo) de um nome vence; série
// com outro conjunto é inválida (o Gather falharia com dimensões diferentes na mesma família).
type heartbeatFamilies map[string]*heartbeatFamily

// claim devolve a descrição de name com o tipo e os rótulos pedidos, ou nil em conflito. Um histograma reserva
// nome_bucket, nome_sum e nome_count (o registro recusa outra família com esses nomes).
func (f heartbeatFamilies) claim(name string, kind famKind, labels []string, help string) *prometheus.Desc {
	sig := strings.Join(labels, ",")
	if fam := f[name]; fam != nil {
		if fam.kind != kind || fam.sig != sig {
			return nil
		}
		return fam.desc
	}
	for _, suf := range histogramSuffixes {
		if kind == famHistogram && f[name+suf] != nil {
			return nil
		}
		if base, ok := strings.CutSuffix(name, suf); ok && kind != famHistogram && f[base] != nil && f[base].kind == famHistogram {
			return nil
		}
	}
	fam := &heartbeatFamily{kind: kind, sig: sig, desc: prometheus.NewDesc(name, help, labels, nil)}
	f[name] = fam
	if kind == famHistogram {
		for _, suf := range histogramSuffixes {
			f[name+suf] = &heartbeatFamily{kind: famHistogramPart}
		}
	}
	return fam.desc
}

// emit republica as métricas do heartbeat de svc e devolve quantas chaves foram ignoradas.
func (f heartbeatFamilies) emit(ch chan<- prometheus.Metric, svc string, metrics map[string]float64) int {
	keys := make([]string, 0, len(metrics))
	for k := range metrics {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	invalid := 0
	if len(keys) > maxHeartbeatMetrics {
		invalid += len(keys) - maxHeartbeatMetrics
		keys = keys[:maxHeartbeatMetrics]
	}
	series := make([]*hbSeries, 0, len(keys))
	byName := map[string]*hbSeries{}
	for _, k := range keys {
		if svc == event.ServiceStore && replacedHeartbeat[k] {
			continue
		}
		s, ok := parseHeartbeatKey(k)
		if !ok {
			invalid++
			continue
		}
		s.value = metrics[k]
		series = append(series, &s)
		if id := s.name + "|" + canon(s.labels); byName[id] == nil {
			byName[id] = &s
		}
	}
	invalid += f.emitHistograms(ch, svc, series, byName)
	for _, s := range series {
		if s.used {
			continue
		}
		labels, values := []string{"service"}, []string{svc}
		typ, kind := prometheus.GaugeValue, famGauge
		help := "Value from the service heartbeat (" + s.key + ")."
		if s.labeled {
			for _, l := range s.labels {
				labels = append(labels, l.name)
				values = append(values, l.value)
			}
			help = "Value from the service heartbeat (" + s.name + ")."
			if strings.HasSuffix(s.name, "_total") || hasAnySuffix(s.name, histogramSuffixes) {
				typ, kind = prometheus.CounterValue, famCounter
			}
		} else if strings.HasSuffix(s.key, "_total") {
			// Contadores acumulados no heartbeat terminam em _total; o resto é medida (como antes da ADR 0056).
			typ, kind = prometheus.CounterValue, famCounter
		}
		d := f.claim("fs_"+s.name, kind, labels, help)
		if d == nil {
			invalid++
			continue
		}
		m, err := prometheus.NewConstMetric(d, typ, s.value, values...)
		if err != nil {
			invalid++
			continue
		}
		ch <- m
	}
	return invalid
}

// emitHistograms junta nome_bucket{le}, nome_sum e nome_count (com os mesmos demais rótulos) num histograma
// fs_nome, que no texto do /metrics sai como as mesmas séries cumulativas (e passa no lint). Grupo incompleto (sem
// _sum ou _count, le repetido, valor negativo) fica como séries soltas (contadores). Devolve as séries ignoradas.
func (f heartbeatFamilies) emitHistograms(ch chan<- prometheus.Metric, svc string, series []*hbSeries, byName map[string]*hbSeries) int {
	type group struct {
		base    string
		others  []hbLabel
		buckets []*hbSeries
		bounds  []float64
	}
	groups := map[string]*group{}
	var order []string
	for _, s := range series {
		base, ok := strings.CutSuffix(s.name, "_bucket")
		if !ok || !s.labeled {
			continue
		}
		le := ""
		others := make([]hbLabel, 0, len(s.labels))
		for _, l := range s.labels {
			if l.name == "le" {
				le = l.value
			} else {
				others = append(others, l)
			}
		}
		bound, err := strconv.ParseFloat(le, 64)
		if le == "" || err != nil || math.IsNaN(bound) {
			continue
		}
		gk := base + "|" + canon(others)
		g := groups[gk]
		if g == nil {
			g = &group{base: base, others: others}
			groups[gk] = g
			order = append(order, gk)
		}
		g.buckets = append(g.buckets, s)
		g.bounds = append(g.bounds, bound)
	}
	invalid := 0
	for _, gk := range order {
		g := groups[gk]
		sum, count := byName[g.base+"_sum|"+canon(g.others)], byName[g.base+"_count|"+canon(g.others)]
		if sum == nil || count == nil || !(count.value >= 0) {
			continue
		}
		buckets := make(map[float64]uint64, len(g.buckets))
		ok := true
		for i, b := range g.buckets {
			if _, dup := buckets[g.bounds[i]]; dup || !(b.value >= 0) {
				ok = false
				break
			}
			buckets[g.bounds[i]] = uint64(b.value)
		}
		if !ok {
			continue
		}
		// le="+Inf" é o total, que o histograma tira de _count.
		delete(buckets, math.Inf(+1))
		labels, values := []string{"service"}, []string{svc}
		for _, l := range g.others {
			labels = append(labels, l.name)
			values = append(values, l.value)
		}
		parts := append([]*hbSeries{sum, count}, g.buckets...)
		for _, p := range parts {
			p.used = true
		}
		d := f.claim("fs_"+g.base, famHistogram, labels, "Histogram from the service heartbeat ("+g.base+").")
		if d == nil {
			invalid += len(parts)
			continue
		}
		m, err := prometheus.NewConstHistogram(d, uint64(count.value), sum.value, buckets, values...)
		if err != nil {
			invalid += len(parts)
			continue
		}
		ch <- m
	}
	return invalid
}

func hasAnySuffix(s string, sufs []string) bool {
	for _, suf := range sufs {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
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
