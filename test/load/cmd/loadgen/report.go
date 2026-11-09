//go:build load

package main

// Modo report: junta gen.json (gerador), cgroup.csv (vps602) e as coletas do /metrics, aplica as metas da
// ADR 0022/0024 e escreve summary.json, summary.md e cpu_mem_by_second.csv.

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/test/load/loadstat"
)

// memoryMax das units (deploy/systemd/*.service).
var memoryMax = map[string]float64{
	"capture": 96 << 20, "web": 96 << 20, "raw": 96 << 20, "dns": 96 << 20, "store": 384 << 20, "nats": 192 << 20,
}

type check struct {
	Goal   string `json:"goal"`
	Metric string `json:"metric"`
	Target string `json:"target"`
	Value  string `json:"value"`
	Pass   bool   `json:"pass"`
}

type unitUsage struct {
	CPUMean   float64 `json:"cpu_mean_pct"`
	CPUP95    float64 `json:"cpu_p95_pct"`
	CPUMax    float64 `json:"cpu_max_pct"`
	MemMaxMiB float64 `json:"mem_max_mib"`
	AnonMax   float64 `json:"anon_max_mib"`
	MemoryMax float64 `json:"memory_max_mib"`
}

type summaryDoc struct {
	Commit    string                `json:"commit"`
	Date      string                `json:"date"`
	Profile   string                `json:"profile"`
	Checks    []check               `json:"checks"`
	Usage     map[string]unitUsage  `json:"usage"`
	Decomp    map[string][3]float64 `json:"decomposition_ms"` // p50, p95, p99 (histogramas do store)
	Health    map[string]float64    `json:"health_deltas"`
	AllPass   bool                  `json:"all_pass"`
	Generator results               `json:"generator"`
}

func reportCmd(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	dir := fs.String("dir", "", "pasta do run")
	quicTarget := fs.Duration("quic-target", 3*time.Second, "meta p95 do registro QUIC (ADR 0024: 3 s; depois da task 090: 500 ms)")
	_ = fs.Parse(args)
	if *dir == "" {
		return fmt.Errorf("-dir é obrigatório")
	}
	b, err := os.ReadFile(filepath.Join(*dir, "gen.json"))
	if err != nil {
		return err
	}
	var g gen
	if err := json.Unmarshal(b, &g); err != nil {
		return err
	}
	off := time.Duration(g.OffsetStartNs)
	warmV, endV := g.WarmLocal+int64(off), g.LoadEndLocal+int64(off)
	sd := summaryDoc{
		Commit: g.Commit, Date: time.Unix(0, g.StartLocal).UTC().Format(time.RFC3339),
		Profile: fmt.Sprintf("%d novas/s, até %d simultâneas (máx. visto %d), vida %v, %d trocas, %v com %v de aquecimento descartado, mix %s, origem %s; %d abertas, %d puladas",
			g.Config.Rate, g.Config.MaxActive, g.MaxActive, g.Config.Life, g.Config.Reqs, g.Config.Duration, g.Config.Warmup, g.Config.Mix, g.Config.LabelOrigin, g.Launched, g.Skipped),
		Generator: g.Results, Decomp: map[string][3]float64{}, Health: map[string]float64{},
	}
	r := g.Results
	add := func(goal, metric, target, value string, pass bool) {
		sd.Checks = append(sd.Checks, check{goal, metric, target, value, pass})
	}

	// RNF-02: feed
	for _, f := range []string{"ws", "sse"} {
		s := r.FeedDelayMs[f]
		add("RNF-02", "atraso do feed /"+f+" (p99)", "< 1000 ms", fmt.Sprintf("p50 %.0f / p95 %.0f / p99 %.0f / máx %.0f ms (n=%d)", s.P50, s.P95, s.P99, s.Max, s.N), s.N > 0 && s.P99 < 1000)
		fa := r.FeedDelayMs[f+"/@fact"]
		add("RNF-02*", "atraso do feed /"+f+" sem o connection.updated do raw.session (ts = accept), p99", "< 1000 ms", fmt.Sprintf("p50 %.0f / p95 %.0f / p99 %.0f / máx %.0f ms (n=%d)", fa.P50, fa.P95, fa.P99, fa.Max, fa.N), fa.N > 0 && fa.P99 < 1000)
		d := r.FeedDropped[f]
		add("RNF-02", "stream.dropped /"+f, "0", fmt.Sprintf("%d avisos, %d eventos", d[0], d[1]), d[0] == 0)
	}
	// RNF-03: API (cliente, inclui a ida e volta pela internet)
	for _, route := range []string{"GET /connections/{id}", "GET /probes/{id}"} {
		s := r.APIMs[route]
		add("RNF-03", route+" no cliente (p95)", "< 100 ms", fmt.Sprintf("p50 %.1f / p95 %.1f / p99 %.1f / máx %.1f ms (n=%d)", s.P50, s.P95, s.P99, s.Max, s.N), s.N > 0 && s.P95 < 100)
	}
	nAPIErr := 0
	for _, n := range r.APIErrors {
		nAPIErr += n
	}
	add("RNF-03", "erros na amostragem da API", "0", strconv.Itoa(nAPIErr), nAPIErr == 0)
	// RNF-04: registro
	tcp, quic := r.RecordMs["tcp"], r.RecordMs["quic"]
	add("RNF-04", "TCP: fim no cliente → connection.closed (p95)", "≤ 500 ms", fmt.Sprintf("p50 %.0f / p95 %.0f / p99 %.0f / máx %.0f ms (n=%d)", tcp.P50, tcp.P95, tcp.P99, tcp.Max, tcp.N), tcp.N > 0 && tcp.P95 <= 500)
	qt := float64(quicTarget.Milliseconds())
	add("RNF-04", "QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95)", fmt.Sprintf("≤ %.0f ms", qt), fmt.Sprintf("p50 %.0f / p95 %.0f / p99 %.0f / máx %.0f ms (n=%d)", quic.P50, quic.P95, quic.P99, quic.Max, quic.N), quic.N > 0 && quic.P95 <= qt)

	// RNF-01: cobertura, degradado, perdas
	cv := r.Coverage
	add("RNF-01", "probes sem registro", "0", fmt.Sprintf("%d de %d (feed ws %d, sse %d, só API %d)", cv.Missing, cv.Probes, cv.SeenWS, cv.SeenSSE, cv.SeenAPIOnly), cv.Probes > 0 && cv.Missing == 0)
	add("RNF-01", "registros degraded da carga", "0", strconv.Itoa(cv.Degraded), cv.Degraded == 0)
	nErr, nLaunch := 0, 0
	for _, k := range r.Conns {
		nLaunch += k.Launched
		nErr += k.Launched - k.OK
	}
	add("RNF-01", "conexões com erro no cliente", "0", fmt.Sprintf("%d de %d", nErr, nLaunch), nErr == 0)
	add("RNF-01", "conexões puladas pelo teto do gerador", "0", strconv.Itoa(g.Skipped), g.Skipped == 0)

	hw, he := healthAt(g.Health, g.WarmLocal, false), healthAt(g.Health, g.LoadEndLocal, true)
	dropped := 0.0
	for svc, m := range he.Metrics {
		d := m["dropped_events_total"] - hw.Metrics[svc]["dropped_events_total"]
		sd.Health["dropped_events_total/"+svc] = d
		dropped += d
	}
	add("RNF-01", "dropped_events_total (todos os serviços, Δ)", "0", fmtF(dropped), dropped == 0)
	kd := he.Metrics["capture"]["capture_kernel_drops_total"] - hw.Metrics["capture"]["capture_kernel_drops_total"]
	sd.Health["capture_kernel_drops_total"] = kd
	add("RNF-01", "kernel_drops do capture (Δ)", "0", fmtF(kd), kd == 0)
	for _, k := range []string{"capture_queue_freezes_total", "capture_truncated_total", "capture_kernel_packets_total", "store_stray_total", "store_late_packets_total"} {
		sd.Health[k] = he.Metrics[firstPart(k)][k] - hw.Metrics[firstPart(k)][k]
	}
	notOK, versions := 0, map[string]bool{}
	for _, h := range g.Health {
		versions[h.Version] = true
		if !h.VersionsMatch {
			versions["versions_match=false"] = true
		}
		for _, st := range h.Status {
			if st != "ok" {
				notOK++
			}
		}
	}
	add("RNF-01", "health: serviços fora de ok (amostras)", "0", strconv.Itoa(notOK), notOK == 0)
	add("—", "versão estável durante a medição (versions_match)", "1 versão", strings.Join(keys(versions), ", "), len(versions) == 1)

	// CPU/RAM por unit
	usage, hostCPU, err := cgroupUsage(filepath.Join(*dir, "cgroup.csv"), filepath.Join(*dir, "cpu_mem_by_second.csv"), warmV, endV)
	if err != nil {
		return err
	}
	sd.Usage = usage
	memOK := true
	var memV []string
	for _, u := range []string{"capture", "web", "raw", "dns", "store", "nats"} {
		us := usage[u]
		// anon é a memória do processo; memory.current inclui o cache de página (recuperável) e pode encostar
		// no MemoryMax sem OOM
		if us.AnonMax >= us.MemoryMax {
			memOK = false
		}
		memV = append(memV, fmt.Sprintf("%s %.0f (%.0f)/%.0f", u, us.AnonMax, us.MemMaxMiB, us.MemoryMax))
	}
	add("RNF-01", "RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB", "anon < MemoryMax", strings.Join(memV, ", "), len(usage) > 0 && memOK)
	add("RNF-01", "CPU do host (média / p95 / máx, % de 1 vCPU)", "informativo", fmt.Sprintf("%.0f / %.0f / %.0f (steal médio %.1f)", hostCPU[0], hostCPU[1], hostCPU[2], hostCPU[3]), true)

	// RNF-05: retenção
	maxAge := 0.0
	for _, h := range g.Health {
		if h.Oldest == nil || h.T < g.WarmLocal || h.T > g.LoadEndLocal {
			continue
		}
		maxAge = math.Max(maxAge, time.Unix(0, h.T+int64(off)).Sub(*h.Oldest).Seconds())
	}
	ret := g.Config.Retention.Seconds()
	// informativo: o health dá o início do mais antigo e a retenção conta do fim (task 080); conexões longas
	// (ociosas de 30–180 s) passam de retenção + folga sem erro. A prova é o expurgo conferido abaixo.
	add("RNF-05", "idade (pelo início) do registro mais antigo durante a carga", "informativo", fmt.Sprintf("%.0f s (retenção %.0f s)", maxAge, ret), true)
	rc := r.Retention
	add("RNF-05", "expurgo depois da retenção", "20 primeiros 404; ~9 min ainda 200", fmt.Sprintf("antigos: %d sumiram, %d ficaram; ~9 min: %d presentes, %d sumiram", rc.OldGone, rc.OldStill, rc.RecentPresent, rc.RecentGone),
		rc.Done && rc.OldStill == 0 && rc.OldGone > 0 && rc.RecentGone == 0 && rc.RecentPresent > 0)

	// RNF-07: frames
	maxFrame, offl := 0.0, he.Metrics["capture"]["capture_offload_suspect_total"]-hw.Metrics["capture"]["capture_offload_suspect_total"]
	agg := false
	for _, h := range g.Health {
		maxFrame = math.Max(maxFrame, h.Metrics["capture"]["capture_max_frame_bytes"])
		agg = agg || h.Aggregating
	}
	add("RNF-07", "maior frame capturado (capture_max_frame_bytes)", "≤ 1514", fmtF(maxFrame), maxFrame > 0 && maxFrame <= 1514)
	add("RNF-07", "offload_suspect (Δ capture, registros amostrados)", "0", fmt.Sprintf("%s / %d de %d", fmtF(offl), r.APIChecks["offload_suspect"], r.APIChecks["connections_checked"]), offl == 0 && r.APIChecks["offload_suspect"] == 0 && !agg)

	// decomposição pelos histogramas do store (Δ aquecimento → fim)
	warmM, err1 := readProm(filepath.Join(*dir, "metrics_warm.prom"))
	endM, err2 := readProm(filepath.Join(*dir, "metrics_end.prom"))
	if err1 == nil && err2 == nil {
		hq := func(name string, labels map[string]string) [3]float64 {
			d := loadstat.DiffBuckets(loadstat.Histogram(warmM, name, labels), loadstat.Histogram(endM, name, labels))
			return [3]float64{1000 * loadstat.Quantile(d, 0.5), 1000 * loadstat.Quantile(d, 0.95), 1000 * loadstat.Quantile(d, 0.99)}
		}
		sd.Decomp["ingest_lag (ts → commit)"] = hq("fs_store_ingest_lag_seconds", nil)
		sd.Decomp["live_delay (ts → envio ao cliente)"] = hq("fs_store_live_delay_seconds", nil)
		for _, reason := range []string{"close", "quic_close", "idle"} {
			sd.Decomp["record_ready{"+reason+"} (fim → gravado)"] = hq("fs_store_record_ready_seconds", map[string]string{"reason": reason})
		}
		for _, route := range []string{"GET /api/v1/connections/{conn_id}", "GET /api/v1/probes/{id}"} {
			sd.Decomp["api "+route+" (servidor)"] = hq("fs_store_api_request_duration_seconds", map[string]string{"route": route})
		}
		deg := loadstat.Sum(endM, "fs_store_connections_degraded_total", nil) - loadstat.Sum(warmM, "fs_store_connections_degraded_total", nil)
		sd.Health["fs_store_connections_degraded_total"] = deg
		ld := loadstat.Sum(endM, "fs_store_live_dropped_total", nil) - loadstat.Sum(warmM, "fs_store_live_dropped_total", nil)
		sd.Health["fs_store_live_dropped_total"] = ld
	}
	cf := r.FeedDelayMs["ws"]
	sd.Decomp["cliente /ws (ts → chegada)"] = [3]float64{cf.P50, cf.P95, cf.P99}

	sd.AllPass = true
	for _, c := range sd.Checks {
		sd.AllPass = sd.AllPass && c.Pass
	}
	out, _ := json.MarshalIndent(sd, "", " ")
	writeFile(filepath.Join(*dir, "summary.json"), out)
	md := renderMD(sd, g)
	writeFile(filepath.Join(*dir, "summary.md"), []byte(md))
	fmt.Print(md)
	return nil
}

func firstPart(k string) string { return strings.SplitN(k, "_", 2)[0] }

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// healthAt devolve a amostra de health com métricas mais próxima de t: a primeira em/depois de t (after=false)
// ou a última em/antes de t + 60 s (after=true, para pegar o heartbeat depois do fim da carga).
func healthAt(hs []healthSample, t int64, after bool) healthSample {
	var best healthSample
	for _, h := range hs {
		if h.Metrics == nil {
			continue
		}
		if !after && h.T >= t {
			return h
		}
		if after && h.T <= t+int64(60*time.Second) {
			best = h
		}
	}
	if best.Metrics == nil && len(hs) > 0 {
		return hs[len(hs)-1]
	}
	return best
}

func readProm(p string) ([]loadstat.Sample, error) {
	b, err := os.ReadFile(p) //nolint:gosec // pasta do operador
	if err != nil {
		return nil, err
	}
	return loadstat.ParseProm(string(b))
}

// cgroupUsage calcula CPU (% de 1 vCPU por segundo) e memória por unit no intervalo [from, to] (ns da vps602),
// grava a série por segundo e devolve também a CPU do host: média, p95, máximo e steal médio.
func cgroupUsage(in, out string, from, to int64) (map[string]unitUsage, [4]float64, error) {
	var host [4]float64
	f, err := os.Open(in) //nolint:gosec // pasta do operador
	if err != nil {
		return nil, host, err
	}
	defer f.Close() //nolint:errcheck // leitura
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, host, err
	}
	type pt struct{ t, cpu, mem, anon int64 }
	series := map[string][]pt{}
	for _, row := range rows[1:] {
		if len(row) < 6 {
			continue
		}
		var v [5]int64
		for i, s := range []string{row[0], row[2], row[3], row[4], row[5]} {
			v[i], _ = strconv.ParseInt(s, 10, 64)
		}
		series[row[1]] = append(series[row[1]], pt{v[0], v[1], v[2], v[3]})
	}
	usage := map[string]unitUsage{}
	perSec := map[string][]float64{}
	for unit, s := range series {
		var cpus []float64
		var memMax, anonMax float64
		for i := 1; i < len(s); i++ {
			if s[i].t < from || s[i].t > to {
				continue
			}
			dt := (s[i].t - s[i-1].t) / 1000
			if unit == "host" {
				// busy/total em jiffies; steal na coluna anon
				dTotal := s[i].mem - s[i-1].mem
				if dTotal > 0 {
					cpus = append(cpus, 100*float64(s[i].cpu-s[i-1].cpu)/float64(dTotal))
					host[3] += 100 * float64(s[i].anon-s[i-1].anon) / float64(dTotal)
				}
				continue
			}
			cpus = append(cpus, loadstat.CPUPercent(s[i-1].cpu, s[i].cpu, dt))
			memMax = math.Max(memMax, float64(s[i].mem))
			anonMax = math.Max(anonMax, float64(s[i].anon))
		}
		perSec[unit] = cpus
		sm := loadstat.Summarize(cpus)
		if unit == "host" {
			host[0], host[1], host[2] = sm.Mean, sm.P95, sm.Max
			if len(cpus) > 0 {
				host[3] /= float64(len(cpus))
			}
			continue
		}
		usage[unit] = unitUsage{CPUMean: sm.Mean, CPUP95: sm.P95, CPUMax: sm.Max, MemMaxMiB: memMax / (1 << 20), AnonMax: anonMax / (1 << 20), MemoryMax: memoryMax[unit] / (1 << 20)}
	}
	// série por segundo (CPU % por unit)
	o, err := os.Create(out) //nolint:gosec // pasta do operador
	if err != nil {
		return usage, host, err
	}
	defer o.Close() //nolint:errcheck // gravação
	w := csv.NewWriter(o)
	units := []string{"host", "capture", "web", "raw", "dns", "store", "nats"}
	_ = w.Write(append([]string{"second"}, units...))
	n := 0
	for _, u := range units {
		n = max(n, len(perSec[u]))
	}
	for i := 0; i < n; i++ {
		row := []string{strconv.Itoa(i)}
		for _, u := range units {
			if i < len(perSec[u]) {
				row = append(row, f1(perSec[u][i]))
			} else {
				row = append(row, "")
			}
		}
		_ = w.Write(row)
	}
	w.Flush()
	return usage, host, w.Error()
}

func renderMD(sd summaryDoc, g gen) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Commit `%s`, início %s, %s.\n\n", sd.Commit, sd.Date, sd.Profile)
	b.WriteString("| Meta | Métrica | Alvo | Medido | Resultado |\n| --- | --- | --- | --- | --- |\n")
	for _, c := range sd.Checks {
		res := "passou"
		if !c.Pass {
			res = "**falhou**"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", c.Goal, c.Metric, c.Target, c.Value, res)
	}
	b.WriteString("\nCPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):\n\n")
	b.WriteString("| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |\n| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, u := range []string{"capture", "web", "raw", "dns", "store", "nats"} {
		us := sd.Usage[u]
		fmt.Fprintf(&b, "| %s | %.1f | %.1f | %.1f | %.0f | %.0f | %.0f |\n", u, us.CPUMean, us.CPUP95, us.CPUMax, us.MemMaxMiB, us.AnonMax, us.MemoryMax)
	}
	b.WriteString("\nDecomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):\n\n")
	b.WriteString("| Etapa | p50 | p95 | p99 |\n| --- | --- | --- | --- |\n")
	for _, k := range keys(sd.Decomp) {
		v := sd.Decomp[k]
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", k, f1(v[0]), f1(v[1]), f1(v[2]))
	}
	b.WriteString("\nAtraso do feed por tipo de evento (/ws, ms):\n\n| kind | n | p50 | p95 | p99 | máx |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, k := range keys(sd.Generator.FeedDelayMs) {
		if !strings.HasPrefix(k, "ws/") {
			continue
		}
		s := sd.Generator.FeedDelayMs[k]
		fmt.Fprintf(&b, "| %s | %d | %.0f | %.0f | %.0f | %.0f |\n", strings.TrimPrefix(k, "ws/"), s.N, s.P50, s.P95, s.P99, s.Max)
	}
	b.WriteString("\nRegistro a partir de `data.ended` (último pacote) → connection.closed (ms):\n\n| L4 | n | p50 | p95 | p99 | máx |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, k := range keys(sd.Generator.RecordEndMs) {
		s := sd.Generator.RecordEndMs[k]
		fmt.Fprintf(&b, "| %s | %d | %.0f | %.0f | %.0f | %.0f |\n", k, s.N, s.P50, s.P95, s.P99, s.Max)
	}
	b.WriteString("\nConexões por tipo:\n\n| tipo | abertas | ok | degraded | proto no registro | erros |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, k := range keys(sd.Generator.Conns) {
		ks := sd.Generator.Conns[k]
		var protos, errs []string
		for _, p := range keys(ks.Proto) {
			protos = append(protos, fmt.Sprintf("%s=%d", p, ks.Proto[p]))
		}
		for _, e := range keys(ks.Errors) {
			errs = append(errs, fmt.Sprintf("%d× %s", ks.Errors[e], e))
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %s | %s |\n", k, ks.Launched, ks.OK, ks.Degraded, strings.Join(protos, " "), strings.Join(errs, "; "))
	}
	b.WriteString("\nOutros contadores (Δ durante a medição):\n\n")
	for _, k := range keys(sd.Health) {
		fmt.Fprintf(&b, "- `%s`: %s\n", k, fmtF(sd.Health[k]))
	}
	fmt.Fprintf(&b, "\nRelógio: vps602 − local %v no início, %v no fim (ida e volta do ssh %v).\n",
		time.Duration(g.OffsetStartNs), time.Duration(g.OffsetEndNs), time.Duration(g.ClockRTTNs))
	if len(g.Clock) > 0 {
		var lo, hi time.Duration
		acc := 0
		for _, c := range g.Clock {
			if !c.Accepted {
				continue
			}
			o := time.Duration(c.OffsetNs)
			if acc == 0 || o < lo {
				lo = o
			}
			if acc == 0 || o > hi {
				hi = o
			}
			acc++
		}
		fmt.Fprintf(&b, "Deslocamento acompanhado a cada 15 s (%d de %d medições aceitas): %v a %v; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.\n",
			acc, len(g.Clock), lo, hi)
	}
	if sd.AllPass {
		b.WriteString("\n**Todas as metas passaram.**\n")
	} else {
		b.WriteString("\n**Há metas que falharam.**\n")
	}
	return b.String()
}
