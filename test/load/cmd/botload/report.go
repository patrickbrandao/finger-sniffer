//go:build load

package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/test/load/loadstat"
)

// readSamples lê um samples.csv (ou .csv.gz) e devolve as amostras com início em [from, to).
func readSamples(path string, from, to int64) ([]sample, error) {
	f, err := os.Open(path) //nolint:gosec // pasta do operador
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // leitura
	var rd io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close() //nolint:errcheck // leitura
		rd = gz
	}
	return parseSamples(rd, from, to)
}

// parseSample lê uma linha do samples.csv.
func parseSample(line string) (sample, error) {
	var s sample
	p := strings.Split(line, ",")
	if len(p) != 5 {
		return s, fmt.Errorf("%q", line)
	}
	var errs [4]error
	s.t, errs[0] = strconv.ParseInt(p[0], 10, 64)
	s.kind = p[1]
	s.latUS, errs[1] = strconv.ParseInt(p[2], 10, 64)
	s.status, errs[2] = strconv.Atoi(p[3])
	s.flag, errs[3] = strconv.Atoi(p[4])
	for _, e := range errs {
		if e != nil {
			return s, e
		}
	}
	return s, nil
}

func parseSamples(rd io.Reader, from, to int64) ([]sample, error) {
	var out []sample
	// a última linha pode estar cortada (cópia de um arquivo ainda em gravação): só ela é ignorada
	var bad error
	sc := bufio.NewScanner(rd)
	for n := 0; sc.Scan(); n++ {
		if bad != nil {
			return nil, bad
		}
		line := sc.Text()
		if n == 0 && line == samplesHeader {
			continue
		}
		s, err := parseSample(line)
		if err != nil {
			bad = fmt.Errorf("linha %d: %w", n+1, err)
			continue
		}
		if (from == 0 || s.t >= from) && (to == 0 || s.t < to) {
			out = append(out, s)
		}
	}
	return out, sc.Err()
}

// kindStats é o resumo de um tipo de amostra numa janela.
type kindStats struct {
	N      int              `json:"n"`
	Errors int              `json:"errors"` // status diferente do esperado
	Flag   int              `json:"flag"`   // soma do campo flag (view.tcp no auth, registros no ingest)
	Over   int              `json:"over"`   // acima do limite do tipo (feed > 1 s)
	Lat    loadstat.Summary `json:"lat_ms"`
}

var okStatus = map[string]int{"auth": 200, "query": 200, "feed": 200, "store_feed": 200, "ingest": 202, "hostile_ingest": 202}

func summarize(ss []sample, kind string, keep func(sample) bool) kindStats {
	var st kindStats
	var lat []float64
	for _, s := range ss {
		if s.kind != kind || (keep != nil && !keep(s)) {
			continue
		}
		st.N++
		st.Flag += s.flag
		if want, ok := okStatus[kind]; ok && s.status != want {
			st.Errors++
			continue
		}
		ms := float64(s.latUS) / 1000
		if (kind == "feed" || kind == "store_feed") && ms > 1000 {
			st.Over++
		}
		lat = append(lat, ms)
	}
	st.Lat = loadstat.Summarize(lat)
	return st
}

// ---------------------------------------------------------------- health do store (heartbeat do bot)

// botMetrics lê o services.bot.metrics de um GET /api/v1/health salvo.
func botMetrics(path string) ([]loadstat.Sample, error) {
	b, err := os.ReadFile(path) //nolint:gosec // pasta do operador
	if err != nil {
		return nil, err
	}
	var h struct {
		Services map[string]struct {
			Metrics map[string]float64 `json:"metrics"`
		} `json:"services"`
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m := h.Services["bot"].Metrics
	if m == nil {
		return nil, fmt.Errorf("%s: sem services.bot.metrics", path)
	}
	var sb strings.Builder
	for k, v := range m {
		_, _ = fmt.Fprintf(&sb, "%s %v\n", k, v)
	}
	return loadstat.ParseProm(sb.String())
}

// histWithInf junta os buckets finitos do heartbeat com o +Inf (= _count; o bot não envia o +Inf, ADR 0057 item 3).
func histWithInf(ss []loadstat.Sample, base string) []loadstat.Bucket {
	b := loadstat.Histogram(ss, base, nil)
	return append(b, loadstat.Bucket{LE: math.Inf(1), Count: loadstat.Sum(ss, base+"_count", nil)})
}

// botDelta são as contas das métricas do bot entre duas coletas.
type botDelta struct {
	Auth          float64            `json:"auth"`
	JA4H          map[string]float64 `json:"auth_ja4h"`
	AuthP95       float64            `json:"auth_p95_ms"`
	AuthP99       float64            `json:"auth_p99_ms"`
	AuthLE10      float64            `json:"auth_le_10ms"`
	AuthLE50      float64            `json:"auth_le_50ms"`
	WaitP95       float64            `json:"wait_p95_ms"`
	WaitP99       float64            `json:"wait_p99_ms"`
	WaitSumMS     float64            `json:"wait_sum_ms"`
	AuthSumMS     float64            `json:"auth_sum_ms"`
	ViewWait      map[string]float64 `json:"view_wait"`
	Evicted       map[string]float64 `json:"evicted"`
	IndexBytes    float64            `json:"index_bytes_after"`
	IngestRecords float64            `json:"ingest_records"`
	IngestDropped float64            `json:"ingest_dropped"`
	RateLimited   float64            `json:"rate_limited"`
	AggDropped    float64            `json:"agg_dropped"`
	StoreFeed     float64            `json:"store_feed_messages"`
}

func diffBot(before, after []loadstat.Sample) botDelta {
	d := func(name string, labels map[string]string) float64 {
		return loadstat.Sum(after, name, labels) - loadstat.Sum(before, name, labels)
	}
	auth := loadstat.DiffBuckets(histWithInf(before, "bot_auth_seconds"), histWithInf(after, "bot_auth_seconds"))
	wait := loadstat.DiffBuckets(histWithInf(before, "bot_auth_wait_seconds"), histWithInf(after, "bot_auth_wait_seconds"))
	out := botDelta{
		Auth: d("bot_auth_seconds_count", nil), JA4H: map[string]float64{}, ViewWait: map[string]float64{}, Evicted: map[string]float64{},
		AuthP95: loadstat.Quantile(auth, 0.95) * 1000, AuthP99: loadstat.Quantile(auth, 0.99) * 1000,
		AuthLE10: loadstat.FractionBelow(auth, 0.01), AuthLE50: loadstat.FractionBelow(auth, 0.05),
		WaitP95: loadstat.Quantile(wait, 0.95) * 1000, WaitP99: loadstat.Quantile(wait, 0.99) * 1000,
		WaitSumMS: d("bot_auth_wait_seconds_sum", nil) * 1000, AuthSumMS: d("bot_auth_seconds_sum", nil) * 1000,
		IndexBytes:    loadstat.Sum(after, "bot_index_bytes", nil),
		IngestRecords: d("bot_ingest_records_total", nil), IngestDropped: d("bot_ingest_dropped_total", nil),
		RateLimited: d("bot_rate_limited_total", nil), AggDropped: d("bot_agg_dropped_total", nil),
		StoreFeed: d("bot_store_feed_messages_total", nil),
	}
	for _, s := range []string{"header", "ingest", "none"} {
		out.JA4H[s] = d("bot_auth_ja4h_total", map[string]string{"source": s})
	}
	for _, s := range []string{"fork", "tcp"} {
		out.ViewWait[s] = d("bot_view_wait_total", map[string]string{"missing": s})
	}
	for _, s := range []string{"bytes", "count"} {
		out.Evicted[s] = d("bot_conns_evicted_total", map[string]string{"reason": s})
	}
	return out
}

// ---------------------------------------------------------------- relatório

func parseWhen(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0, err
	}
	return t.UnixNano(), nil
}

func fmtLat(s loadstat.Summary) string {
	if s.N == 0 {
		return "—"
	}
	return fmt.Sprintf("%.2f / %.2f / %.2f / %.1f", s.P50, s.P95, s.P99, s.Max)
}

func reportCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	dir := fs.String("dir", ".", "pasta com samples.csv, hostile_samples.csv e feed_samples.csv (ou .gz)")
	fromS := fs.String("from", "", "início da janela (RFC 3339; vazio = tudo)")
	toS := fs.String("to", "", "fim da janela (RFC 3339; vazio = tudo)")
	hb := fs.String("health-before", "", "GET /api/v1/health do store no início da janela")
	ha := fs.String("health-after", "", "GET /api/v1/health do store no fim da janela")
	minutes := fs.Bool("minutes", true, "tabela por minuto do forwardAuth")
	if err := fs.Parse(args); err != nil {
		return err
	}
	from, err := parseWhen(*fromS)
	if err != nil {
		return err
	}
	to, err := parseWhen(*toS)
	if err != nil {
		return err
	}
	var ss []sample
	for _, n := range []string{"samples.csv", "hostile_samples.csv", "feed_samples.csv"} {
		for _, p := range []string{n, n + ".gz"} {
			got, err := readSamples(filepath.Join(*dir, p), from, to)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			ss = append(ss, got...)
		}
	}
	_, _ = fmt.Fprintf(w, "Janela %s → %s, %d amostras.\n\n", orAll(*fromS), orAll(*toS), len(ss))
	_, _ = fmt.Fprintln(w, "| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |")
	_, _ = fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- |")
	rows := []struct {
		name, kind string
		keep       func(sample) bool
	}{
		{"forwardAuth (flag = view.tcp)", "auth", nil},
		{"consulta GET /verdict", "query", nil},
		{"feed (todas as requisições)", "feed", nil},
		{"feed (primeira requisição da conexão)", "feed", func(s sample) bool { return s.flag == 1 }},
		{"ingest (flag = registros)", "ingest", nil},
		{"ingest hostil (flag = aceitos)", "hostile_ingest", nil},
		{"feed global do store no finger-01", "store_feed", nil},
		{"feed global do store, sem o connection.updated do raw", "store_feed", func(s sample) bool { return s.flag == 0 }},
	}
	for _, r := range rows {
		st := summarize(ss, r.kind, r.keep)
		_, _ = fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %s |\n", r.name, st.N, st.Errors, st.Flag, st.Over, fmtLat(st.Lat))
	}
	counts := map[string]int{}
	dropped, storeDropped := 0, 0
	for _, s := range ss {
		counts[s.kind]++
		switch s.kind {
		case "feed_dropped":
			dropped += s.flag
		case "store_feed_dropped":
			storeDropped += s.flag
		}
	}
	_, _ = fmt.Fprintf(w, "\nSem veredito no feed: %d; stream.dropped: %d eventos (%d perdidos); puladas sem conexão: %d; puladas em voo: %d.\n",
		counts["feed_missing"], counts["feed_dropped"], dropped, counts["skip"], counts["busy"])
	_, _ = fmt.Fprintf(w, "Feed global do store no finger-01: stream.dropped %d avisos, %d eventos perdidos.\n", counts["store_feed_dropped"], storeDropped)
	if *minutes {
		printMinutes(w, ss)
	}
	if *hb != "" && *ha != "" {
		before, err := botMetrics(*hb)
		if err != nil {
			return err
		}
		after, err := botMetrics(*ha)
		if err != nil {
			return err
		}
		d := diffBot(before, after)
		b, _ := json.MarshalIndent(d, "", "  ")
		_, _ = fmt.Fprintf(w, "\nMétricas do bot (heartbeat, %s → %s):\n\n```json\n%s\n```\n", *hb, *ha, b)
		_, _ = fmt.Fprintf(w, "\nbot_auth_ja4h_total{source=\"header\"} Δ %.0f contra %d forwardAuth 200 do cliente na janela das amostras.\n",
			d.JA4H["header"], summarize(ss, "auth", nil).Lat.N)
	}
	return nil
}

func orAll(s string) string {
	if s == "" {
		return "(tudo)"
	}
	return s
}

// printMinutes escreve n, erros, view.tcp e p95/p99 do forwardAuth por minuto (relógio do finger-01, UTC).
func printMinutes(w io.Writer, ss []sample) {
	byMin := map[int64][]sample{}
	for _, s := range ss {
		if s.kind == "auth" {
			m := s.t / int64(time.Minute)
			byMin[m] = append(byMin[m], s)
		}
	}
	if len(byMin) == 0 {
		return
	}
	keys := make([]int64, 0, len(byMin))
	for k := range byMin {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	_, _ = fmt.Fprintln(w, "\n| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |")
	_, _ = fmt.Fprintln(w, "| --- | --- | --- | --- | --- |")
	for _, k := range keys {
		st := summarize(byMin[k], "auth", nil)
		_, _ = fmt.Fprintf(w, "| %s | %d | %d | %d | %.2f / %.2f / %.1f |\n", time.Unix(0, k*int64(time.Minute)).UTC().Format("15:04"),
			st.N, st.Errors, st.Flag, st.Lat.P95, st.Lat.P99, st.Lat.Max)
	}
}
