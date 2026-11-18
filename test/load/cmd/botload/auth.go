//go:build load

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oklog/ulid/v2"
)

type authConfig struct {
	bot       string
	store     string
	ports     string
	site      string
	rate      int
	queryRate float64
	duration  time.Duration
	maxReqs   int
	maxAge    time.Duration
	inflight  int
	srcPrefix string
	out       string
}

// storeOpened é o LiveEvent connection.opened do store (só os campos usados).
type storeOpened struct {
	Kind string `json:"kind"`
	Data struct {
		L4  string `json:"l4"`
		Src struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"src"`
		Dst struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"dst"`
	} `json:"data"`
}

// simConn é uma conexão do traefix simulado, presa a uma conexão real da carga oficial vista pelo store.
type simConn struct {
	id      string
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
	tpl     *template
	created time.Time
	reqs    int // só o escalonador mexe
}

// ingestItem é um registro do lote; ok roda depois do 202 (a conexão só recebe requisições depois do registro dela
// estar no bot, como no traefix com o ingest antes do forwardAuth).
type ingestItem struct {
	rec map[string]any
	ok  func()
}

type authRun struct {
	cfg     authConfig
	key     string
	tpls    []*template
	rec     *recorder
	auth    *http.Client
	ingestC *http.Client
	items   chan ingestItem
	ready   chan *simConn
	pending sync.Map // caminho → envio (ns) do forwardAuth, até o veredito chegar pelo feed
	sem     chan struct{}

	nAuth, nAuthErr, nTCP, nQuery, nQueryErr, nFeed, nSkip, nBusy, nOpened, nIngestErr atomic.Int64
	winMu                                                                              sync.Mutex
	win                                                                                []float64 // latências do forwardAuth (ms) desde o último log
}

func authCmd(args []string) error {
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	var c authConfig
	fs.StringVar(&c.bot, "bot", "http://10.249.255.254:9003/bot/v1", "base da API interna do bot")
	fs.StringVar(&c.store, "store", "http://170.247.40.86:9001/api/v1", "base da API do store (feed connection.opened)")
	fs.StringVar(&c.ports, "ports", "8080,8443", "portas TCP do web cujas conexões viram conexões do traefix simulado")
	fs.StringVar(&c.site, "site", "fs-load.example", "X-Forwarded-Host/SNI simulado (domínio da chave)")
	fs.IntVar(&c.rate, "rate", 200, "forwardAuth por segundo")
	fs.Float64Var(&c.queryRate, "query-rate", 20, "consultas GET /bot/v1/verdict por segundo")
	fs.DurationVar(&c.duration, "duration", 10*time.Minute, "duração")
	fs.IntVar(&c.maxReqs, "max-reqs", 16, "requisições por conexão simulada")
	fs.DurationVar(&c.maxAge, "max-age", 30*time.Second, "idade máxima de uma conexão simulada para receber requisições")
	fs.IntVar(&c.inflight, "inflight", 512, "forwardAuth simultâneos no máximo")
	fs.StringVar(&c.srcPrefix, "src-prefix", "", "só conexões do store com src.ip começando assim (vazio = todas)")
	fs.StringVar(&c.out, "out", "/out", "pasta dos resultados")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := readKey(os.Stdin)
	if err != nil {
		return err
	}
	tpls, err := loadTemplates()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.out, 0o750); err != nil {
		return err
	}
	rec, err := newRecorder(filepath.Join(c.out, "samples.csv"))
	if err != nil {
		return err
	}
	r := &authRun{
		cfg: c, key: key, tpls: tpls, rec: rec, auth: newClient(c.inflight), ingestC: newClient(8),
		items: make(chan ingestItem, 1<<16), ready: make(chan *simConn, 1<<14), sem: make(chan struct{}, c.inflight),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return r.run(ctx)
}

func (r *authRun) logf(f string, a ...any) { log.Printf(f, a...) }

func (r *authRun) run(ctx context.Context) error {
	start := time.Now()
	r.logf("auth: %d/s por %v, consultas %.0f/s, site %s, portas %s (início %s)", r.cfg.rate, r.cfg.duration,
		r.cfg.queryRate, r.cfg.site, r.cfg.ports, ts(start))
	feedCtx, feedStop := context.WithCancel(ctx)
	defer feedStop()
	var bg sync.WaitGroup
	// feed do bot: atraso de cada veredito
	bg.Add(1)
	go func() {
		defer bg.Done()
		readSSE(feedCtx, sseClient(), r.cfg.bot+"/stream?site="+url.QueryEscape(r.cfg.site), r.key, r.onVerdict, r.logf)
	}()
	// feed do store: conexões reais da carga oficial
	opened := make(chan storeOpened, 1<<14)
	for _, p := range strings.Split(r.cfg.ports, ",") {
		u := r.cfg.store + "/stream?kind=connection.opened&dst_port=" + strings.TrimSpace(p)
		bg.Add(1)
		go func() {
			defer bg.Done()
			readSSE(feedCtx, sseClient(), u, "", func(d []byte) {
				var ev storeOpened
				if json.Unmarshal(d, &ev) != nil || ev.Kind != "connection.opened" || ev.Data.L4 != "tcp" {
					return
				}
				if r.cfg.srcPrefix != "" && !strings.HasPrefix(ev.Data.Src.IP, r.cfg.srcPrefix) {
					return
				}
				select {
				case opened <- ev:
				default:
				}
			}, r.logf)
		}()
	}
	ingDone := make(chan struct{})
	go func() { defer close(ingDone); r.batcher() }()
	makerDone := make(chan struct{})
	go func() { defer close(makerDone); r.connMaker(feedCtx, opened) }()

	runCtx, runStop := context.WithTimeout(ctx, r.cfg.duration)
	defer runStop()
	r.schedule(runCtx, start)
	// espera os forwardAuth em voo e os vereditos atrasados
	for i := 0; i < cap(r.sem); i++ {
		r.sem <- struct{}{}
	}
	time.Sleep(3 * time.Second)
	feedStop()
	<-makerDone
	close(r.items)
	<-ingDone
	missing := 0
	r.pending.Range(func(k, v any) bool {
		missing++
		r.rec.add(sample{t: v.(pendingReq).t0, kind: "feed_missing", flag: v.(pendingReq).n})
		return true
	})
	bg.Wait()
	lost := r.rec.close()
	r.logf("fim: auth %d (erro %d, view.tcp %d), consultas %d (erro %d), feed %d, sem veredito no feed %d, puladas %d "+
		"(sem conexão) %d (em voo), conexões do store %d, erros de ingest %d, amostras perdidas %d",
		r.nAuth.Load(), r.nAuthErr.Load(), r.nTCP.Load(), r.nQuery.Load(), r.nQueryErr.Load(), r.nFeed.Load(), missing,
		r.nSkip.Load(), r.nBusy.Load(), r.nOpened.Load(), r.nIngestErr.Load(), lost)
	return nil
}

type pendingReq struct {
	t0 int64
	n  int
}

// onVerdict é cada evento do feed do bot: casa o caminho da requisição com o envio do forwardAuth.
func (r *authRun) onVerdict(d []byte) {
	now := time.Now().UnixNano()
	var ev struct {
		Kind    string `json:"kind"`
		Dropped int    `json:"dropped"`
		Verdict struct {
			Subject struct {
				Path string `json:"path"`
			} `json:"subject"`
		} `json:"verdict"`
	}
	if json.Unmarshal(d, &ev) != nil {
		return
	}
	if ev.Kind == "stream.dropped" {
		r.rec.add(sample{t: now, kind: "feed_dropped", flag: ev.Dropped})
		return
	}
	v, ok := r.pending.LoadAndDelete(ev.Verdict.Subject.Path)
	if !ok {
		return
	}
	p := v.(pendingReq)
	r.nFeed.Add(1)
	r.rec.add(sample{t: p.t0, kind: "feed", latUS: (now - p.t0) / 1000, status: 200, flag: p.n})
}

// connMaker transforma cada conexão do store numa conexão do traefix simulado e manda o registro dela ao ingest.
func (r *authRun) connMaker(ctx context.Context, opened <-chan storeOpened) {
	i := 0
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-opened:
			r.nOpened.Add(1)
			now := time.Now()
			c := &simConn{
				id: ulid.Make().String(), srcIP: ev.Data.Src.IP, srcPort: ev.Data.Src.Port, dstIP: ev.Data.Dst.IP,
				dstPort: ev.Data.Dst.Port, tpl: r.tpls[i%len(r.tpls)], created: now,
			}
			i++
			rec := connRecord(c, r.cfg.site, now)
			select {
			case r.items <- ingestItem{rec: rec, ok: func() {
				select {
				case r.ready <- c:
				default:
				}
			}}:
			default:
			}
		}
	}
}

// connRecord é o registro type=connection traefix.fingerprint/v1 da conexão simulada (o traefix o manda na
// primeira requisição; aqui antes dela, como a carga da task 285, para o forwardAuth achar a visão do ingest).
func connRecord(c *simConn, site string, now time.Time) map[string]any {
	rec, tls := withTLS(c.tpl.conn)
	rec["connId"], rec["time"] = c.id, ts(now)
	rec["src"] = map[string]any{"ip": c.srcIP, "port": c.srcPort}
	rec["dst"] = map[string]any{"ip": c.dstIP, "port": c.dstPort}
	tls["sni"] = site
	return rec
}

// requestRecord é o registro type=request traefix.fingerprint/v1 de uma requisição da conexão simulada.
func requestRecord(c *simConn, site, path string, start, end time.Time) map[string]any {
	rq := clone(c.tpl.req)
	rq["connId"], rq["start"], rq["end"] = c.id, ts(start), ts(end)
	rq["path"], rq["authority"] = path, site
	return rq
}

// batcher junta os registros e manda um lote a cada 50 ms (ou com 1024 registros), como o traefix.
func (r *authRun) batcher() {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	var buf []ingestItem
	flush := func() {
		if len(buf) == 0 {
			return
		}
		recs := make([]map[string]any, len(buf))
		for i, it := range buf {
			recs[i] = it.rec
		}
		body, err := batchBody(recs)
		if err != nil {
			r.logf("lote: %v", err)
			buf = buf[:0]
			return
		}
		t0 := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		status, acc, rej, err := postIngest(ctx, r.ingestC, r.cfg.bot, r.key, body)
		cancel()
		r.rec.add(sample{t: t0.UnixNano(), kind: "ingest", latUS: time.Since(t0).Microseconds(), status: status, flag: len(recs)})
		if err != nil || status != http.StatusAccepted || rej > 0 {
			r.nIngestErr.Add(1)
			r.logf("ingest: status %d aceitos %d recusados %d erro %v", status, acc, rej, err)
		}
		if err == nil && status == http.StatusAccepted {
			for _, it := range buf {
				if it.ok != nil {
					it.ok()
				}
			}
		}
		buf = buf[:0]
	}
	for {
		select {
		case it, ok := <-r.items:
			if !ok {
				flush()
				return
			}
			buf = append(buf, it)
			if len(buf) >= 1024 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// schedule manda -rate forwardAuth por segundo em passo uniforme, revezando as conexões simuladas ativas.
func (r *authRun) schedule(ctx context.Context, start time.Time) {
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	logTick := time.NewTicker(10 * time.Second)
	defer logTick.Stop()
	var active []*simConn
	next, sent := 0, int64(0)
	t0 := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-logTick.C:
			r.logWindow(len(active))
			continue
		case <-tick.C:
		}
		for drained := false; !drained; {
			select {
			case c := <-r.ready:
				active = append(active, c)
			default:
				drained = true
			}
		}
		now := time.Now()
		// tira as conexões velhas ou já com todas as requisições
		keep := active[:0]
		for _, c := range active {
			if c.reqs < r.cfg.maxReqs && now.Sub(c.created) < r.cfg.maxAge {
				keep = append(keep, c)
			}
		}
		active = keep
		owed := int64(now.Sub(t0).Seconds()*float64(r.cfg.rate)) - sent
		for ; owed > 0; owed-- {
			sent++
			if len(active) == 0 {
				r.nSkip.Add(1)
				r.rec.add(sample{t: now.UnixNano(), kind: "skip"})
				continue
			}
			c := active[next%len(active)]
			next++
			c.reqs++
			select {
			case r.sem <- struct{}{}:
			default:
				r.nBusy.Add(1)
				r.rec.add(sample{t: now.UnixNano(), kind: "busy"})
				continue
			}
			go func(c *simConn, n int) {
				defer func() { <-r.sem }()
				r.doAuth(c, n)
			}(c, c.reqs)
		}
	}
}

func (r *authRun) logWindow(active int) {
	r.winMu.Lock()
	w := r.win
	r.win = nil
	r.winMu.Unlock()
	sort.Float64s(w)
	q := func(p float64) float64 {
		if len(w) == 0 {
			return 0
		}
		return w[min(len(w)-1, int(p*float64(len(w))))]
	}
	r.logf("10s: auth %d p50 %.1f p95 %.1f p99 %.1f máx %.1f ms | total auth %d erro %d tcp %d consultas %d feed %d puladas %d/%d ativas %d store %d",
		len(w), q(0.5), q(0.95), q(0.99), q(1), r.nAuth.Load(), r.nAuthErr.Load(), r.nTCP.Load(), r.nQuery.Load(),
		r.nFeed.Load(), r.nSkip.Load(), r.nBusy.Load(), active, r.nOpened.Load())
}

// authHeaders monta os cabeçalhos que o traefix manda ao forwardAuth (spec 019 RF-04 e RF-05, ADR 0063): os
// X-Traefix-* da conexão (origem, JA4, JA3, Akamai e ALPN oferecido) e da requisição (JA4H), a chave do middleware
// e os authRequestHeaders do visitante (sem Cookie). Sem X-Traefix-Ja4t: a carga não conhece o SYN das conexões
// reais (a visão TCP é a do store).
func authHeaders(c *simConn, site, path, key string) http.Header {
	h := http.Header{}
	h.Set("X-Traefix-Src-Ip", c.srcIP)
	h.Set("X-Traefix-Src-Port", strconv.Itoa(c.srcPort))
	h.Set("X-Traefix-Dst-Port", strconv.Itoa(c.dstPort))
	h.Set("X-Traefix-Conn-Id", c.id)
	h.Set("X-Traefix-Proto", c.tpl.proto)
	h.Set("X-Traefix-Ja4h", c.tpl.ja4h)
	h.Set("X-Traefix-Ja4", c.tpl.ja4)
	h.Set("X-Traefix-Ja3", c.tpl.ja3)
	if c.tpl.proto == "h2" && c.tpl.akamai != "" {
		h.Set("X-Traefix-H2", c.tpl.akamai)
	}
	if len(c.tpl.alpn) > 0 {
		h.Set("X-Traefix-Alpn", alpnHeader(c.tpl.alpn))
	}
	h.Set("X-Forwarded-Method", http.MethodGet)
	h.Set("X-Forwarded-Proto", "https")
	h.Set("X-Forwarded-Host", site)
	h.Set("X-Forwarded-Uri", path)
	h.Set("X-Forwarded-For", c.srcIP)
	h.Set("User-Agent", c.tpl.ua)
	h.Set("Accept", "*/*")
	if c.tpl.lang != "" {
		h.Set("Accept-Language", c.tpl.lang)
	}
	h.Set("Authorization", "Bearer "+key)
	return h
}

func (r *authRun) doAuth(c *simConn, n int) {
	path := fmt.Sprintf("/load/%s/%d", c.id, n)
	req, err := http.NewRequest(http.MethodGet, r.cfg.bot+"/auth", nil) //nolint:noctx // prazo no cliente
	if err != nil {
		return
	}
	req.Header = authHeaders(c, r.cfg.site, path, r.key)
	t0 := time.Now()
	// o veredito pode chegar pelo feed antes da resposta: o envio fica anotado antes do Do
	r.pending.Store(path, pendingReq{t0: t0.UnixNano(), n: n})
	resp, err := r.auth.Do(req)
	status, tcp := 0, 0
	if err == nil {
		var v struct {
			View struct {
				TCP bool `json:"tcp"`
			} `json:"view"`
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		status = resp.StatusCode
		if json.Unmarshal(b, &v) == nil && v.View.TCP {
			tcp = 1
		}
	}
	lat := time.Since(t0)
	r.nAuth.Add(1)
	if status != http.StatusOK {
		// erro não tem veredito no feed
		r.pending.Delete(path)
		r.nAuthErr.Add(1)
	}
	r.nTCP.Add(int64(tcp))
	r.rec.add(sample{t: t0.UnixNano(), kind: "auth", latUS: lat.Microseconds(), status: status, flag: tcp})
	r.winMu.Lock()
	r.win = append(r.win, float64(lat.Microseconds())/1000)
	r.winMu.Unlock()
	if status != http.StatusOK {
		return
	}
	// registro type=request no ingest, depois da resposta (o traefix manda o resumo no fim da requisição)
	rq := requestRecord(c, r.cfg.site, path, t0, t0.Add(lat+time.Millisecond))
	select {
	case r.items <- ingestItem{rec: rq}:
	default:
	}
	if rand.Float64() < r.cfg.queryRate/float64(r.cfg.rate) { //nolint:gosec // sorteio da amostragem de consultas
		r.query(c)
	}
}

// alpnHeader codifica o ALPN oferecido como o X-Traefix-Alpn: na ordem do cliente, por vírgula, %XX fora do ASCII
// visível e para `,` e `%` (spec 019 RF-05).
func alpnHeader(vs []string) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		var b strings.Builder
		for _, c := range []byte(v) {
			if c <= 0x20 || c >= 0x7f || c == ',' || c == '%' {
				_, _ = fmt.Fprintf(&b, "%%%02X", c)
				continue
			}
			b.WriteByte(c)
		}
		parts[i] = b.String()
	}
	return strings.Join(parts, ",")
}

// query é o GET /bot/v1/verdict pela origem da conexão (consulta do site, RNF-01 p95 ≤ 50 ms).
func (r *authRun) query(c *simConn) {
	u := fmt.Sprintf("%s/verdict?src_ip=%s&src_port=%d&site=%s", r.cfg.bot, url.QueryEscape(c.srcIP), c.srcPort, url.QueryEscape(r.cfg.site))
	req, err := http.NewRequest(http.MethodGet, u, nil) //nolint:noctx // prazo no cliente
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+r.key)
	t0 := time.Now()
	resp, err := r.auth.Do(req)
	status := 0
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		status = resp.StatusCode
	}
	r.nQuery.Add(1)
	if status != http.StatusOK {
		r.nQueryErr.Add(1)
	}
	r.rec.add(sample{t: t0.UnixNano(), kind: "query", latUS: time.Since(t0).Microseconds(), status: status})
}
