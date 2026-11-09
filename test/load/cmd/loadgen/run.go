//go:build load

package main

// Modo run: pacer de conexões, feed, amostragem da API, health e /metrics, conferência de que todo probe tem
// registro e da retenção; grava os dados brutos e as contas por meta em gen.json.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/patrickbrandao/finger-sniffer/test/load/loadstat"
)

type config struct {
	Host        string        `json:"host"`
	IP          string        `json:"ip"`
	API         string        `json:"api"`
	MetricsURL  string        `json:"metrics_url"`
	Rate        int           `json:"rate"`
	MaxActive   int           `json:"max_active"`
	Life        time.Duration `json:"life_ns"`
	Reqs        int           `json:"reqs"`
	Duration    time.Duration `json:"duration_ns"`
	Warmup      time.Duration `json:"warmup_ns"`
	Mix         string        `json:"mix"`
	APIRate     float64       `json:"api_rate"`
	ClockCmd    string        `json:"clock_cmd"`
	Retention   time.Duration `json:"retention_ns"`
	RetCheck    bool          `json:"retention_check"`
	Out         string        `json:"-"`
	LabelOrigin string        `json:"origin"`
}

// mix converte "h1=15,h1tls=15,..." num ciclo determinístico de tipos (o mix sai exato a cada ciclo).
func parseMix(s string) ([]connSpec, error) {
	ports := map[string][]int{
		"h1": {80, 8080}, "h1tls": {443, 8443}, "h2": {443, 8443}, "h3": {443},
		"raw-echo": {7}, "raw-banner": {21, 25}, "raw-sink": {143},
	}
	var cycle []connSpec
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		n, err := strconv.Atoi(v)
		if !ok || err != nil || n < 0 || ports[k] == nil {
			return nil, fmt.Errorf("mix inválido: %q", part)
		}
		for i := 0; i < n; i++ {
			cycle = append(cycle, connSpec{Kind: k, Port: ports[k][i%len(ports[k])]})
		}
	}
	if len(cycle) == 0 {
		return nil, fmt.Errorf("mix vazio")
	}
	// intercala os tipos no ciclo (passo coprimo) para não abrir rajadas do mesmo tipo
	out := make([]connSpec, len(cycle))
	step := 7
	for gcd(step, len(cycle)) != 1 {
		step++
	}
	for i := range cycle {
		out[i] = cycle[(i*step)%len(cycle)]
	}
	return out, nil
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// measureClock mede o deslocamento do relógio da vps602 (remoto − local) pela menor ida e volta.
func measureClock(cmdline string) (offset, rtt time.Duration, err error) {
	cmd := exec.Command("sh", "-c", cmdline) //nolint:gosec // comando do operador
	in, _ := cmd.StdinPipe()
	outP, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return 0, 0, err
	}
	defer func() { _ = in.Close(); _ = cmd.Wait() }()
	br := bufio.NewReader(outP)
	best := time.Hour
	for range 25 {
		t0 := time.Now()
		if _, err := io.WriteString(in, "x\n"); err != nil {
			return 0, 0, err
		}
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, 0, fmt.Errorf("relógio: %w", err)
		}
		t1 := time.Now()
		ns, err := strconv.ParseInt(strings.TrimSpace(line), 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("relógio: %q", line)
		}
		if d := t1.Sub(t0); d < best {
			best, offset = d, time.Unix(0, ns).Sub(t0.Add(d/2))
		}
	}
	return offset, best, nil
}

// tlRow é uma linha da linha do tempo do gerador (por segundo).
type tlRow struct{ launched, skipped, errs int }

// apiSample é uma requisição de amostragem da API.
type apiSample struct {
	Route  string  `json:"route"`
	T      int64   `json:"t"` // início (local)
	Ms     float64 `json:"ms"`
	Status int     `json:"status"`
	// conferências do registro completo (GET /connections/{id})
	OffloadSuspect bool `json:"offload_suspect,omitempty"`
	PcapTruncated  bool `json:"pcap_truncated,omitempty"`
}

// healthSample guarda o essencial de um GET /health.
type healthSample struct {
	T             int64                         `json:"t"` // local
	OK            bool                          `json:"ok"`
	Version       string                        `json:"version"`
	VersionsMatch bool                          `json:"versions_match"`
	Status        map[string]string             `json:"status"`
	Metrics       map[string]map[string]float64 `json:"metrics"`
	Oldest        *time.Time                    `json:"oldest"`
	DBBytes       float64                       `json:"db_bytes"`
	Connections   float64                       `json:"connections"`
	Aggregating   bool                          `json:"aggregating_offload"`
	Err           string                        `json:"err,omitempty"`
}

type healthDoc struct {
	OK            bool   `json:"ok"`
	Version       string `json:"version"`
	VersionsMatch bool   `json:"versions_match"`
	Services      map[string]struct {
		Status  string             `json:"status"`
		Version string             `json:"version"`
		Metrics map[string]float64 `json:"metrics"`
	} `json:"services"`
	Host struct {
		AggregatingOffload bool `json:"aggregating_offload"`
		Store              struct {
			DBBytes     float64    `json:"db_bytes"`
			Connections float64    `json:"connections"`
			Oldest      *time.Time `json:"oldest"`
		} `json:"store"`
	} `json:"host"`
}

// gen é o gen.json: configuração, instantes e resultados brutos agregados.
type gen struct {
	Config        config         `json:"config"`
	Commit        string         `json:"commit"`
	StartLocal    int64          `json:"start_local"`
	WarmLocal     int64          `json:"warm_local"`
	LoadEndLocal  int64          `json:"load_end_local"`
	OffsetStartNs int64          `json:"offset_start_ns"`
	OffsetEndNs   int64          `json:"offset_end_ns"`
	ClockRTTNs    int64          `json:"clock_rtt_ns"`
	Launched      int            `json:"launched"`
	Skipped       int            `json:"skipped"`
	MaxActive     int            `json:"max_active_seen"`
	Health        []healthSample `json:"health"`
	Results       results        `json:"results"`
}

type results struct {
	Conns       map[string]kindStats        `json:"conns"`
	FeedDelayMs map[string]loadstat.Summary `json:"feed_delay_ms"` // por feed e por feed/kind
	FeedDropped map[string][2]int           `json:"feed_dropped"`  // feed → [stream.dropped, soma dropped]
	FeedErrors  map[string][]string         `json:"feed_errors"`
	RecordMs    map[string]loadstat.Summary `json:"record_ms"`     // tcp/quic: fim no cliente → connection.closed
	RecordEndMs map[string]loadstat.Summary `json:"record_end_ms"` // tcp/quic: data.ended → connection.closed
	APIMs       map[string]loadstat.Summary `json:"api_ms"`
	APIErrors   map[string]int              `json:"api_errors"`
	APIChecks   map[string]int              `json:"api_checks"`
	Coverage    coverage                    `json:"coverage"`
	Retention   retentionCheck              `json:"retention"`
}

type kindStats struct {
	Launched int            `json:"launched"`
	OK       int            `json:"ok"`
	Errors   map[string]int `json:"errors"`
	Degraded int            `json:"degraded"`
	Proto    map[string]int `json:"proto"`
}

// coverage: todo probe fechado no cliente tem registro (feed ou API).
type coverage struct {
	Probes      int      `json:"probes"`
	SeenWS      int      `json:"seen_ws"`
	SeenSSE     int      `json:"seen_sse"`
	SeenAPIOnly int      `json:"seen_api_only"`
	Missing     int      `json:"missing"`
	MissingIDs  []string `json:"missing_ids"`
	Degraded    int      `json:"degraded"`
}

type retentionCheck struct {
	Done          bool     `json:"done"`
	OldGone       int      `json:"old_gone"`       // probes fechados há > retenção + folga: 404
	OldStill      int      `json:"old_still"`      // ... ainda presentes (falha)
	RecentPresent int      `json:"recent_present"` // probes fechados há ~9 min: 200
	RecentGone    int      `json:"recent_gone"`    // ... já sumiram (falha: expurgo precoce)
	Notes         []string `json:"notes"`
}

func runCmd(args []string) error {
	var c config
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fs.StringVar(&c.Host, "host", "vps602.tmsoft.com.br", "servidor")
	fs.StringVar(&c.API, "api", "https://vps602.tmsoft.com.br:9000/api/v1", "base da API (feed e amostragem)")
	fs.StringVar(&c.MetricsURL, "metrics", "http://vps602.tmsoft.com.br:9001/metrics", "/metrics do store")
	fs.IntVar(&c.Rate, "rate", 50, "conexões novas por segundo")
	fs.IntVar(&c.MaxActive, "max-active", 200, "teto de conexões simultâneas do gerador")
	fs.DurationVar(&c.Life, "life", 3800*time.Millisecond, "duração de cada conexão")
	fs.IntVar(&c.Reqs, "reqs", 3, "trocas por conexão (requisições HTTP ou linhas no raw)")
	fs.DurationVar(&c.Duration, "duration", 10*time.Minute, "duração da carga (inclui o aquecimento)")
	fs.DurationVar(&c.Warmup, "warmup", time.Minute, "aquecimento descartado")
	fs.StringVar(&c.Mix, "mix", "h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8", "mix por tipo (pesos)")
	fs.Float64Var(&c.APIRate, "api-rate", 10, "requisições de amostragem da API por segundo (metade conexões, metade probes)")
	fs.StringVar(&c.ClockCmd, "clock-cmd", "ssh -p 48022 root@vps602.tmsoft.com.br /tmp/fs-load/loadmon clock", "comando que ecoa o relógio da vps602")
	fs.DurationVar(&c.Retention, "retention", 10*time.Minute, "FS_RETENTION do servidor")
	fs.BoolVar(&c.RetCheck, "retention-check", true, "depois da carga, espera e confere o expurgo dos primeiros probes")
	fs.StringVar(&c.LabelOrigin, "origin", "mac", "rótulo da origem da carga (relatório)")
	fs.StringVar(&c.Out, "out", "", "pasta de saída")
	commit := fs.String("commit", "", "commit esperado na vps602 (vazio = não confere)")
	_ = fs.Parse(args)
	if c.Out == "" {
		return fmt.Errorf("-out é obrigatório")
	}
	if err := os.MkdirAll(c.Out, 0o750); err != nil {
		return err
	}
	cycle, err := parseMix(c.Mix)
	if err != nil {
		return err
	}
	ips, err := net.LookupIP(c.Host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			c.IP = ip.String()
			break
		}
	}
	if c.IP == "" {
		return fmt.Errorf("%s sem IPv4", c.Host)
	}

	offset, rtt, err := measureClock(c.ClockCmd)
	if err != nil {
		return err
	}
	logf("relógio: vps602 − local = %v (ida e volta %v)", offset, rtt)

	g := &gen{Config: c, OffsetStartNs: int64(offset), ClockRTTNs: int64(rtt)}
	httpc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		MaxIdleConnsPerHost: 8, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}}
	h0 := getHealth(httpc, c.API)
	if h0.Err != "" || !h0.VersionsMatch {
		return fmt.Errorf("health antes da carga: versions_match=%v err=%s", h0.VersionsMatch, h0.Err)
	}
	if *commit != "" && h0.Version != *commit {
		return fmt.Errorf("vps602 com a versão %s, esperava %s", h0.Version, *commit)
	}
	g.Commit = h0.Version
	g.Health = append(g.Health, h0)
	logf("vps602 na versão %s (versions_match=true)", h0.Version)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	feedCtx, feedCancel := context.WithCancel(ctx)
	defer feedCancel()
	ws, sse := newFeed("ws", offset), newFeed("sse", offset)
	var feedWG sync.WaitGroup
	feedWG.Add(2)
	go func() { defer feedWG.Done(); runWS(feedCtx, c.API, ws) }()
	go func() { defer feedWG.Done(); runSSE(feedCtx, c.API, sse) }()
	time.Sleep(2 * time.Second) // feeds conectados antes da primeira conexão

	writeFile(filepath.Join(c.Out, "metrics_start.prom"), scrape(httpc, c.MetricsURL))

	start := time.Now()
	warm := start.Add(c.Warmup)
	loadEnd := start.Add(c.Duration)
	g.StartLocal, g.WarmLocal, g.LoadEndLocal = start.UnixNano(), warm.UnixNano(), loadEnd.UnixNano()

	// health a cada 5 s; /metrics no fim do aquecimento
	var hmu sync.Mutex
	samplerCtx, samplerCancel := context.WithCancel(ctx)
	var samplerWG sync.WaitGroup
	samplerWG.Add(1)
	go func() {
		defer samplerWG.Done()
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		warmDone := false
		for {
			select {
			case <-samplerCtx.Done():
				return
			case <-tick.C:
			}
			h := getHealth(httpc, c.API)
			hmu.Lock()
			g.Health = append(g.Health, h)
			hmu.Unlock()
			if !warmDone && time.Now().After(warm) {
				warmDone = true
				writeFile(filepath.Join(c.Out, "metrics_warm.prom"), scrape(httpc, c.MetricsURL))
			}
		}
	}()

	// amostragem da API
	var apiMu sync.Mutex
	var apiSamples []apiSample
	if c.APIRate > 0 {
		samplerWG.Add(1)
		go func() {
			defer samplerWG.Done()
			tick := time.NewTicker(time.Duration(float64(time.Second) / c.APIRate))
			defer tick.Stop()
			for i := 0; ; i++ {
				select {
				case <-samplerCtx.Done():
					return
				case <-tick.C:
				}
				rc, ok := ws.pickRecent(i / 2)
				if !ok {
					continue
				}
				var s apiSample
				if i%2 == 0 {
					s = getTimed(httpc, c.API+"/connections/"+rc.connID, "GET /connections/{id}")
				} else {
					s = getTimed(httpc, c.API+"/probes/"+rc.probe, "GET /probes/{id}")
				}
				apiMu.Lock()
				apiSamples = append(apiSamples, s)
				apiMu.Unlock()
			}
		}()
	}

	// pacer
	var active, maxActive atomic.Int64
	var resMu sync.Mutex
	var conns []connResult
	var connWG sync.WaitGroup
	timeline := make([]tlRow, int(c.Duration/time.Second)+30)
	interval := time.Second / time.Duration(c.Rate)
	logf("carga: %d novas/s, até %d simultâneas, vida %v, %v (aquecimento %v), mix %s, origem %s",
		c.Rate, c.MaxActive, c.Life, c.Duration, c.Warmup, c.Mix, c.LabelOrigin)
	loadCtx, loadCancel := context.WithCancel(ctx)
	defer loadCancel()
	progress := time.Now()
	for i := 0; ; i++ {
		next := start.Add(time.Duration(i) * interval)
		if !next.Before(loadEnd) || ctx.Err() != nil {
			break
		}
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
		sec := min(int(time.Since(start)/time.Second), len(timeline)-1)
		if active.Load() >= int64(c.MaxActive) {
			g.Skipped++
			timeline[sec].skipped++
			continue
		}
		n := active.Add(1)
		for {
			m := maxActive.Load()
			if n <= m || maxActive.CompareAndSwap(m, n) {
				break
			}
		}
		g.Launched++
		timeline[sec].launched++
		spec := cycle[i%len(cycle)]
		connWG.Add(1)
		go func() {
			defer connWG.Done()
			r := runConn(loadCtx, c.IP, spec, c.Reqs, c.Life)
			active.Add(-1)
			resMu.Lock()
			conns = append(conns, r)
			if r.Err != "" {
				s := int(r.Start.Sub(start) / time.Second)
				if s >= 0 && s < len(timeline) {
					timeline[s].errs++
				}
			}
			resMu.Unlock()
		}()
		if time.Since(progress) >= 30*time.Second {
			progress = time.Now()
			ws.mu.Lock()
			nev := len(ws.samples)
			ws.mu.Unlock()
			logf("t=%3.0fs abertas=%d simultâneas=%d (máx %d) eventos ws=%d", time.Since(start).Seconds(), g.Launched, active.Load(), maxActive.Load(), nev)
		}
	}
	logf("fim da geração: %d abertas, %d puladas (teto), esperando as conexões terminarem", g.Launched, g.Skipped)
	connWG.Wait()
	time.Sleep(10 * time.Second) // últimos connection.closed (QUIC até 3 s)
	samplerCancel()
	samplerWG.Wait()
	writeFile(filepath.Join(c.Out, "metrics_end.prom"), scrape(httpc, c.MetricsURL))
	g.Health = append(g.Health, getHealth(httpc, c.API))
	g.MaxActive = int(maxActive.Load())

	// cobertura: probes sem connection.closed em nenhum feed → API
	g.Results.Coverage = checkCoverage(httpc, c.API, conns, ws, sse)

	// retenção depois da carga (os feeds continuam abertos, sem tráfego da carga)
	if c.RetCheck && ctx.Err() == nil {
		g.Results.Retention = checkRetention(ctx, httpc, c, conns, offset)
	}
	feedCancel()
	feedWG.Wait()

	if off2, _, err := measureClock(c.ClockCmd); err == nil {
		g.OffsetEndNs = int64(off2)
		logf("relógio no fim: %v (deriva %v)", off2, off2-offset)
	}
	g.Health = append(g.Health, getHealth(httpc, c.API))

	computeResults(g, conns, ws, sse, apiSamples, warm, loadEnd, offset)
	if err := writeTimeline(filepath.Join(c.Out, "timeline.csv"), start, timeline, g.Health); err != nil {
		return err
	}
	if err := writeFeedSeries(filepath.Join(c.Out, "feed_delay_by_second.csv"), ws, start, offset); err != nil {
		return err
	}
	if err := writeConns(filepath.Join(c.Out, "conns.csv"), conns, ws, sse, start, offset); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(g, "", " ")
	writeFile(filepath.Join(c.Out, "gen.json"), b)
	logf("dados em %s", c.Out)
	return nil
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
}

func writeFile(p string, b []byte) {
	if err := os.WriteFile(p, b, 0o600); err != nil {
		logf("gravar %s: %v", p, err)
	}
}

func scrape(c *http.Client, url string) []byte {
	resp, err := c.Get(url) //nolint:gosec // URL do operador
	if err != nil {
		return []byte("# erro: " + err.Error() + "\n")
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	b, _ := io.ReadAll(resp.Body)
	return b
}

func getHealth(c *http.Client, api string) healthSample {
	h := healthSample{T: time.Now().UnixNano()}
	resp, err := c.Get(api + "/health") //nolint:gosec // URL do operador
	if err != nil {
		h.Err = err.Error()
		return h
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	var d healthDoc
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		h.Err = err.Error()
		return h
	}
	h.OK, h.Version, h.VersionsMatch = d.OK, d.Version, d.VersionsMatch
	h.Status, h.Metrics = map[string]string{}, map[string]map[string]float64{}
	for name, s := range d.Services {
		h.Status[name] = s.Status
		h.Metrics[name] = s.Metrics
	}
	h.Oldest, h.DBBytes, h.Connections, h.Aggregating = d.Host.Store.Oldest, d.Host.Store.DBBytes, d.Host.Store.Connections, d.Host.AggregatingOffload
	return h
}

func getTimed(c *http.Client, url, route string) apiSample {
	s := apiSample{Route: route, T: time.Now().UnixNano()}
	t0 := time.Now()
	resp, err := c.Get(url) //nolint:gosec // URL do operador
	if err != nil {
		s.Ms = float64(time.Since(t0).Microseconds()) / 1000
		return s
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	s.Ms = float64(time.Since(t0).Microseconds()) / 1000
	s.Status = resp.StatusCode
	if route == "GET /connections/{id}" && resp.StatusCode == http.StatusOK {
		var r struct {
			OffloadSuspect bool `json:"offload_suspect"`
			PcapTruncated  bool `json:"pcap_truncated"`
		}
		_ = json.Unmarshal(b, &r)
		s.OffloadSuspect, s.PcapTruncated = r.OffloadSuspect, r.PcapTruncated
	}
	return s
}

func checkCoverage(c *http.Client, api string, conns []connResult, ws, sse *feed) coverage {
	var cv coverage
	for _, r := range conns {
		if !r.Closed {
			continue
		}
		cv.Probes++
		w, okW := ws.closedOf(r.Probe)
		s, okS := sse.closedOf(r.Probe)
		if okW {
			cv.SeenWS++
		}
		if okS {
			cv.SeenSSE++
		}
		switch {
		case okW:
			if w.Degraded {
				cv.Degraded++
			}
		case okS:
			if s.Degraded {
				cv.Degraded++
			}
		default:
			st := getTimed(c, api+"/probes/"+r.Probe, "coverage")
			if st.Status == http.StatusOK {
				cv.SeenAPIOnly++
			} else {
				cv.Missing++
				if len(cv.MissingIDs) < 50 {
					cv.MissingIDs = append(cv.MissingIDs, r.Probe+" "+r.Spec.Kind)
				}
			}
		}
	}
	return cv
}

// checkRetention espera o primeiro probe da carga passar de retenção + 75 s desde o fim e confere: os 20
// primeiros sumiram (404) e os fechados há 8,5–9,5 min continuam lá (200).
func checkRetention(ctx context.Context, c *http.Client, cfg config, conns []connResult, offset time.Duration) retentionCheck {
	var rc retentionCheck
	var done []connResult
	for _, r := range conns {
		if r.Closed {
			done = append(done, r)
		}
	}
	if len(done) == 0 {
		return rc
	}
	sort.Slice(done, func(i, j int) bool { return done[i].End.Before(done[j].End) })
	deadline := done[0].End.Add(cfg.Retention + 75*time.Second)
	logf("retenção: esperando até %s para conferir o expurgo", deadline.Format("15:04:05"))
	sleepCtx(ctx, time.Until(deadline))
	if ctx.Err() != nil {
		return rc
	}
	now := time.Now()
	for _, r := range done[:min(20, len(done))] {
		st := getTimed(c, cfg.API+"/probes/"+r.Probe, "retention")
		if st.Status == http.StatusNotFound {
			rc.OldGone++
		} else {
			rc.OldStill++
		}
	}
	for _, r := range done {
		age := now.Sub(r.End)
		if age < 8*time.Minute+30*time.Second || age > 9*time.Minute+30*time.Second {
			continue
		}
		if rc.RecentPresent+rc.RecentGone >= 20 {
			break
		}
		st := getTimed(c, cfg.API+"/probes/"+r.Probe, "retention")
		if st.Status == http.StatusOK {
			rc.RecentPresent++
		} else {
			rc.RecentGone++
		}
	}
	rc.Done = true
	rc.Notes = append(rc.Notes, fmt.Sprintf("conferido %s (relógio local; deslocamento %v)", now.Format(time.RFC3339), offset))
	return rc
}

func computeResults(g *gen, conns []connResult, ws, sse *feed, api []apiSample, warm, loadEnd time.Time, offset time.Duration) {
	res := &g.Results
	warmV, endV := warm.Add(offset).UnixNano(), loadEnd.Add(offset).UnixNano()
	res.Conns = map[string]kindStats{}
	recClient := map[string][]float64{}
	recEnded := map[string][]float64{}
	for _, r := range conns {
		ks := res.Conns[r.Spec.Kind]
		if ks.Errors == nil {
			ks.Errors, ks.Proto = map[string]int{}, map[string]int{}
		}
		ks.Launched++
		if r.Err != "" {
			msg := r.Err
			if len(msg) > 120 {
				msg = msg[:120]
			}
			ks.Errors[msg]++
		} else {
			ks.OK++
		}
		ci, ok := ws.closedOf(r.Probe)
		if !ok {
			ci, ok = sse.closedOf(r.Probe)
		}
		if ok {
			ks.Proto[ci.Proto]++
			if ci.Degraded {
				ks.Degraded++
			}
		}
		res.Conns[r.Spec.Kind] = ks
		if !ok || !r.Closed || r.End.Before(warm) {
			continue
		}
		l4 := "tcp"
		if r.Spec.Kind == "h3" {
			l4 = "quic"
		}
		recClient[l4] = append(recClient[l4], float64(ci.Recv-r.End.Add(offset).UnixNano())/1e6)
		if ci.Ended > 0 {
			recEnded[l4] = append(recEnded[l4], float64(ci.Recv-ci.Ended)/1e6)
		}
	}
	res.RecordMs, res.RecordEndMs = map[string]loadstat.Summary{}, map[string]loadstat.Summary{}
	for k, v := range recClient {
		res.RecordMs[k] = loadstat.Summarize(v)
	}
	for k, v := range recEnded {
		res.RecordEndMs[k] = loadstat.Summarize(v)
	}

	res.FeedDelayMs = map[string]loadstat.Summary{}
	res.FeedDropped = map[string][2]int{}
	res.FeedErrors = map[string][]string{}
	for _, f := range []*feed{ws, sse} {
		f.mu.Lock()
		all := []float64{}
		byKind := map[string][]float64{}
		for _, s := range f.samples {
			if s.TS < warmV || s.TS > endV || s.Kind == "stream.dropped" {
				continue
			}
			d := float64(s.Recv-s.TS) / 1e6
			all = append(all, d)
			byKind[s.Kind] = append(byKind[s.Kind], d)
			if s.Kind == "connection.updated" {
				byKind[s.Kind+"/"+s.Proto] = append(byKind[s.Kind+"/"+s.Proto], d)
			}
			// eventos cujo ts é o instante do fato relatado (sem o connection.updated retroativo do raw.session)
			if s.Kind != "connection.updated" || !strings.Contains(s.Proto, "raw") {
				byKind["@fact"] = append(byKind["@fact"], d)
			}
		}
		res.FeedDelayMs[f.name] = loadstat.Summarize(all)
		for k, v := range byKind {
			res.FeedDelayMs[f.name+"/"+k] = loadstat.Summarize(v)
		}
		res.FeedDropped[f.name] = [2]int{f.drops, f.dropped}
		res.FeedErrors[f.name] = f.errors
		f.mu.Unlock()
	}

	res.APIMs, res.APIErrors, res.APIChecks = map[string]loadstat.Summary{}, map[string]int{}, map[string]int{}
	byRoute := map[string][]float64{}
	for _, s := range api {
		if s.T < warm.UnixNano() || s.T > loadEnd.UnixNano() {
			continue
		}
		if s.Status != http.StatusOK {
			res.APIErrors[s.Route+" "+strconv.Itoa(s.Status)]++
			continue
		}
		byRoute[s.Route] = append(byRoute[s.Route], s.Ms)
		if s.OffloadSuspect {
			res.APIChecks["offload_suspect"]++
		}
		if s.PcapTruncated {
			res.APIChecks["pcap_truncated"]++
		}
		if s.Route == "GET /connections/{id}" {
			res.APIChecks["connections_checked"]++
		}
	}
	for k, v := range byRoute {
		res.APIMs[k] = loadstat.Summarize(v)
	}
}

func writeTimeline(p string, start time.Time, tl []tlRow, hs []healthSample) error {
	f, err := os.Create(p) //nolint:gosec // pasta do operador
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // gravação
	w := csv.NewWriter(f)
	_ = w.Write([]string{"second", "launched", "skipped", "client_errors", "store_connections_open", "web_connections_active", "raw_active_sessions"})
	open := map[int][3]float64{}
	for _, h := range hs {
		s := int(time.Unix(0, h.T).Sub(start) / time.Second)
		if h.Metrics == nil {
			continue
		}
		open[s] = [3]float64{h.Metrics["store"]["store_connections_open"], h.Metrics["web"]["web_connections_active"], h.Metrics["raw"]["raw_active_sessions"]}
	}
	for i, t := range tl {
		row := []string{strconv.Itoa(i), strconv.Itoa(t.launched), strconv.Itoa(t.skipped), strconv.Itoa(t.errs), "", "", ""}
		if o, ok := open[i]; ok {
			row[4], row[5], row[6] = fmtF(o[0]), fmtF(o[1]), fmtF(o[2])
		}
		_ = w.Write(row)
	}
	w.Flush()
	return w.Error()
}

func fmtF(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func writeFeedSeries(p string, f *feed, start time.Time, offset time.Duration) error {
	out, err := os.Create(p) //nolint:gosec // pasta do operador
	if err != nil {
		return err
	}
	defer out.Close() //nolint:errcheck // gravação
	w := csv.NewWriter(out)
	_ = w.Write([]string{"second", "events", "p50_ms", "p95_ms", "p99_ms", "max_ms"})
	base := start.Add(offset).UnixNano()
	f.mu.Lock()
	per := map[int][]float64{}
	maxS := 0
	for _, s := range f.samples {
		if s.Kind == "stream.dropped" {
			continue
		}
		sec := int((s.TS - base) / int64(time.Second))
		if sec < 0 {
			continue
		}
		per[sec] = append(per[sec], float64(s.Recv-s.TS)/1e6)
		maxS = max(maxS, sec)
	}
	f.mu.Unlock()
	for i := 0; i <= maxS; i++ {
		s := loadstat.Summarize(per[i])
		_ = w.Write([]string{strconv.Itoa(i), strconv.Itoa(s.N), f1(s.P50), f1(s.P95), f1(s.P99), f1(s.Max)})
	}
	w.Flush()
	return w.Error()
}

func f1(v float64) string {
	if math.IsNaN(v) {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func writeConns(p string, conns []connResult, ws, sse *feed, start time.Time, offset time.Duration) error {
	out, err := os.Create(p) //nolint:gosec // pasta do operador
	if err != nil {
		return err
	}
	defer out.Close() //nolint:errcheck // gravação
	w := csv.NewWriter(out)
	_ = w.Write([]string{"kind", "port", "probe", "start_s", "dur_ms", "reqs", "err", "conn_id", "proto", "degraded", "record_client_ms", "record_ended_ms"})
	sort.Slice(conns, func(i, j int) bool { return conns[i].Start.Before(conns[j].Start) })
	for _, r := range conns {
		row := []string{r.Spec.Kind, strconv.Itoa(r.Spec.Port), r.Probe, f1(r.Start.Sub(start).Seconds()), "", strconv.Itoa(r.Reqs), r.Err, "", "", "", "", ""}
		if !r.End.IsZero() {
			row[4] = f1(float64(r.End.Sub(r.Start).Microseconds()) / 1000)
		}
		ci, ok := ws.closedOf(r.Probe)
		if !ok {
			ci, ok = sse.closedOf(r.Probe)
		}
		if ok {
			row[7], row[8], row[9] = ci.ConnID, ci.Proto, strconv.FormatBool(ci.Degraded)
			if !r.End.IsZero() {
				row[10] = f1(float64(ci.Recv-r.End.Add(offset).UnixNano()) / 1e6)
			}
			if ci.Ended > 0 {
				row[11] = f1(float64(ci.Recv-ci.Ended) / 1e6)
			}
		}
		_ = w.Write(row)
	}
	w.Flush()
	return w.Error()
}
