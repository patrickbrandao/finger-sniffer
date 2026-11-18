package bot

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/agg"
	"github.com/patrickbrandao/finger-sniffer/internal/bot/lists"
	"github.com/patrickbrandao/finger-sniffer/internal/bot/rules"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Origens do veredito (rótulo source de bot_verdicts_total, spec 018 RF-12).
const (
	SourceAuth  = "auth"
	SourceQuery = "query"
	SourceProbe = "probe"
)

// Métricas do veredito (spec 018 RF-12, ADR 0056 item 4).
const (
	metricVerdicts     = "bot_verdicts_total"
	metricViewWait     = "bot_view_wait_total"
	metricAuthSeconds  = "bot_auth_seconds"
	metricAuthWaitSecs = "bot_auth_wait_seconds"
	metricAuthJA4H     = "bot_auth_ja4h_total"
	metricAuthFP       = "bot_auth_fingerprint_total"
)

// Origens das visões do forwardAuth (rótulo source de bot_auth_fingerprint_total, ADRs 0062 item 4 e 0063 item 5).
const (
	fpFromIngest = "ingest"
	fpFromStore  = "store"
	fpFromHeader = "header"
	fpNone       = "none"
)

func authFPMetric(kind, source string) string {
	return metricAuthFP + `{kind="` + kind + `",source="` + source + `"}`
}

// fpSources diz de onde veio cada visão do veredito (tls, h2 e tcp).
type fpSources struct{ tls, h2, tcp string }

// Origens do JA4H do forwardAuth (rótulo source de bot_auth_ja4h_total, ADR 0058 item 1).
const (
	ja4hFromHeader = "header"
	ja4hFromIngest = "ingest"
	ja4hNone       = "none"
)

// ja4hPattern é o JA4H completo aceito em X-Traefix-Ja4h (e no X-Fs-Ja4h antigo; openapi do bot 0.4.0); fora dele o
// cabeçalho é ignorado.
var ja4hPattern = regexp.MustCompile(`^[a-z0-9]{12}_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$`)

func authJA4HMetric(source string) string { return metricAuthJA4H + `{source="` + source + `"}` }

// listsVersionNone é o lists_version sem gerenciador de listas (base própria inválida; não acontece com o binário
// publicado, cuja base é validada no teste).
const listsVersionNone = "none"

// Judge monta a entrada das regras a partir das duas visões do índice, avalia o veredito v1.2 (ADRs 0049, 0057 e 0058)
// e o entrega uma vez por requisição ao feed, ao webhook e aos agregados.
type Judge struct {
	engine    rules.Engine
	index     *Index
	agg       *agg.Aggregator
	hub       *Hub
	lists     *lists.Manager
	known     *knownSource
	ja4db     *ja4dbSource
	bg        *bgVerifier
	metrics   *service.Metrics
	now       func() time.Time
	authTime  *histogram
	authWait  *histogram
	classKeys map[string]map[string]string // source → class → chave da métrica
	// p0f é o p0f.fp da visão TCP do traefix (FS_BOT_P0F_DB), carregado no primeiro uso.
	p0f *p0fSource
}

// newJudge cria o avaliador; m pode ser nil (sem listas: só as regras que não dependem delas).
func newJudge(cfg Config, ix *Index, ag *agg.Aggregator, hub *Hub, m *lists.Manager, metrics *service.Metrics, now func() time.Time) *Judge {
	bg := newBGVerifier()
	j := &Judge{
		engine: rules.Engine{Sources: newRuleSources(m, cfg.JA4DBEnable, bg), RateHigh: cfg.RateHigh},
		index:  ix, agg: ag, hub: hub, lists: m, bg: bg, metrics: metrics, now: now,
		authTime: newHistogram(metrics, metricAuthSeconds, authBuckets),
		authWait: newHistogram(metrics, metricAuthWaitSecs, authBuckets),
		p0f:      newP0FSource(cfg.P0FPath, nil),
	}
	if k, ok := j.engine.Sources.Known.(*knownSource); ok {
		j.known = k
	}
	if d, ok := j.engine.Sources.JA4DB.(ja4dbSource); ok {
		j.ja4db = &d
	}
	j.classKeys = map[string]map[string]string{}
	for _, src := range []string{SourceAuth, SourceQuery, SourceProbe} {
		j.classKeys[src] = map[string]string{}
		for _, c := range []string{ClassHuman, ClassGoodBot, ClassBot, ClassSuspect, ClassUnknown} {
			key := metricVerdicts + `{class="` + c + `",source="` + src + `"}`
			j.classKeys[src][c] = key
			metrics.Add(key, 0)
		}
	}
	for _, m := range []string{"tcp", "fork"} {
		metrics.Add(viewWaitMetric(m), 0)
	}
	for _, src := range []string{ja4hFromHeader, ja4hFromIngest, ja4hNone} {
		metrics.Add(authJA4HMetric(src), 0)
	}
	for _, kind := range []string{"tls", "h2", "tcp"} {
		for _, src := range []string{fpFromIngest, fpFromStore, fpFromHeader, fpNone} {
			metrics.Add(authFPMetric(kind, src), 0)
		}
	}
	for _, k := range mismatchKinds {
		metrics.Add(mismatchMetric(k), 0)
	}
	return j
}

func viewWaitMetric(missing string) string { return metricViewWait + `{missing="` + missing + `"}` }

// count soma um veredito servido em bot_verdicts_total{class,source}.
func (j *Judge) count(source, class string) {
	if key := j.classKeys[source][class]; key != "" {
		j.metrics.Add(key, 1)
	}
}

// ListsVersion é o lists_version do veredito (ADR 0057 item 4).
func (j *Judge) ListsVersion() string {
	if j.lists == nil {
		return listsVersionNone
	}
	return j.lists.Version()
}

// storeRecord são as partes do Record do store que as regras leem (ip, tcp, tls, http2, http3).
type storeRecord struct {
	IP *struct {
		TTLInitial *int `json:"ttl_initial"`
	} `json:"ip"`
	TCP *struct {
		JA4T         *string `json:"ja4t"`
		OSGuess      *string `json:"os_guess"`
		MSSReduction *int    `json:"mss_reduction"`
		MTUImplied   *int    `json:"mtu_implied"`
	} `json:"tcp"`
	TLS   *recordTLS `json:"tls"`
	HTTP2 *struct {
		Akamai *string `json:"akamai"`
	} `json:"http2"`
	HTTP3 *struct {
		ClientHello *recordTLS `json:"client_hello"`
	} `json:"http3"`
}

type recordTLS struct {
	JA4     *string  `json:"ja4"`
	JA4R    *string  `json:"ja4_r"`
	JA4O    *string  `json:"ja4_o"`
	JA3MD5  *string  `json:"ja3_md5"`
	JA3NMD5 *string  `json:"ja3n_md5"`
	ALPN    []string `json:"alpn"`
}

// views é o que se sabe do sujeito: as duas visões (qualquer uma pode faltar) e a requisição.
type views struct {
	ip    netip.Addr
	site  string
	fork  *ForkConn
	store *StoreConn
	http  *rules.HTTP
	proto string // h1 | h2 | h3 da requisição ("" sem requisição)
	// hdr são os cabeçalhos do forwardAuth (só na fonte auth): fingerprints de reserva antes do registro de conexão.
	hdr *forkHeaders
	// src (opcional) recebe a origem de cada visão.
	src *fpSources
}

// evaluate avalia as regras sobre as visões e monta o Verdict do sujeito.
func (j *Judge) evaluate(vw views, subject Subject) (Verdict, rules.Result) {
	in := rules.Input{IP: vw.ip, HTTP: vw.http}
	fps := &Fingerprints{}
	var rec storeRecord
	if vw.store != nil && len(vw.store.Record) > 0 {
		_ = json.Unmarshal(vw.store.Record, &rec) // Record já validado na entrada; parte ausente fica nil
	}
	srcs := fpSources{tls: fpNone, h2: fpNone, tcp: fpNone}
	defer func() {
		if vw.src != nil {
			*vw.src = srcs
		}
	}()
	// TCP: o store casado; sem ele, o registro de conexão do traefix; sem ele, o JA4T do cabeçalho (ADR 0063 item 5).
	if vw.store != nil {
		srcs.tcp = fpFromStore
		t := &rules.TCP{}
		if rec.IP != nil && rec.IP.TTLInitial != nil {
			t.TTLInitial = *rec.IP.TTLInitial
			fps.TTLInitial = ptr(t.TTLInitial)
		}
		if rec.TCP != nil {
			t.JA4T, t.P0fOS = deref(rec.TCP.JA4T), deref(rec.TCP.OSGuess)
			t.MSSReduction, t.MTUImplied = rec.TCP.MSSReduction, rec.TCP.MTUImplied
			fps.JA4T, fps.P0fOS = optString(t.JA4T), optString(t.P0fOS)
		}
		in.TCP = t
	} else if vw.fork != nil && vw.fork.TCP != nil {
		// sem o store casado (site externo), a visão TCP do traefix (ADR 0063 item 5)
		srcs.tcp = fpFromIngest
		in.TCP = vw.fork.TCP.rules()
		fps.JA4T, fps.P0fOS = optString(in.TCP.JA4T), optString(in.TCP.P0fOS)
		if in.TCP.TTLInitial != 0 {
			fps.TTLInitial = ptr(in.TCP.TTLInitial)
		}
	} else if vw.hdr != nil && vw.hdr.ja4t != "" {
		// só o JA4T e o MSS dele: sem TTL nem SO
		srcs.tcp = fpFromHeader
		in.TCP = headerTCP(vw.hdr.ja4t, vw.ip)
		fps.JA4T = optString(in.TCP.JA4T)
	}
	// TLS: o ClientHello do registro de conexão (o traefix termina o TLS); sem ele, as fingerprints dos cabeçalhos do
	// forwardAuth; sem elas, o do espelho (conexão direta ou probe).
	switch f, h := vw.fork, vw.hdr; {
	case f != nil && f.TLS != nil && !f.TLS.ParseError && f.TLS.JA4 != "":
		alpn := f.TLS.ALPN
		if len(alpn) == 0 {
			alpn = f.ALPNOffered
		}
		in.TLS = &rules.TLS{JA4: f.TLS.JA4, JA4R: f.TLS.JA4R, ALPN: alpn}
		fps.JA3, fps.JA3N, fps.JA4O = optString(f.TLS.JA3MD5), optString(f.TLS.JA3NMD5), optString(f.TLS.JA4O)
		srcs.tls = fpFromIngest
	case h != nil && h.ja4 != "":
		// sem X-Traefix-Alpn o ALPN oferecido é desconhecido e as regras de ALPN não avaliam (ADR 0063 item 6)
		in.TLS = &rules.TLS{JA4: h.ja4, ALPN: h.alpn, ALPNUnknown: !h.alpnKnown}
		fps.JA3 = optString(h.ja3)
		srcs.tls = fpFromHeader
	default:
		t := rec.TLS
		if (t == nil || t.JA4 == nil) && rec.HTTP3 != nil {
			t = rec.HTTP3.ClientHello
		}
		if t != nil && deref(t.JA4) != "" {
			in.TLS = &rules.TLS{JA4: *t.JA4, JA4R: deref(t.JA4R), ALPN: t.ALPN}
			fps.JA3, fps.JA3N, fps.JA4O = t.JA3MD5, t.JA3NMD5, t.JA4O
			srcs.tls = fpFromStore
		}
	}
	if in.TLS != nil {
		fps.JA4, fps.JA4R = optString(in.TLS.JA4), optString(in.TLS.JA4R)
	}
	switch f := vw.fork; {
	case f != nil && f.H2 != nil && !f.H2.ParseError && f.H2.Akamai != "":
		in.H2, srcs.h2 = &rules.H2{Akamai: f.H2.Akamai}, fpFromIngest
	case vw.hdr != nil && vw.hdr.h2 != "":
		in.H2, srcs.h2 = &rules.H2{Akamai: vw.hdr.h2}, fpFromHeader
	case rec.HTTP2 != nil && deref(rec.HTTP2.Akamai) != "":
		in.H2, srcs.h2 = &rules.H2{Akamai: *rec.HTTP2.Akamai}, fpFromStore
	}
	if in.H2 != nil {
		fps.Akamai = optString(in.H2.Akamai)
	}
	if vw.http != nil {
		fps.JA4H = optString(vw.http.JA4H)
	}
	view := View{
		TCP: in.TCP != nil, TLS: in.TLS != nil, HTTP: in.HTTP != nil, H2: vw.proto == "h2" || (vw.proto == "" && in.H2 != nil),
		H3: vw.proto == "h3", ParseError: vw.fork != nil && vw.fork.ParseError(),
	}
	if vw.site != "" && vw.ip.IsValid() && j.agg != nil {
		if st := j.agg.Query(vw.ip, vw.site, j.now()); st.Known {
			in.Behavior = &rules.Behavior{
				RequestsPerMin: int(st.RequestsPerMin), RequestsHour: int(st.HourRequests), ConnsHour: int(st.HourConns),
				IntervalN: int(st.HourIntervals.N), IntervalSum: st.HourIntervals.Sum, IntervalSqSum: st.HourIntervals.SqSum,
				PathsHour: int(st.HourPaths), StaticsHour: int(st.HourStatics),
			}
			view.Behavior = true
		}
	}
	in.View = rules.View{TCP: view.TCP, TLS: view.TLS, HTTP: view.HTTP, H2: view.H2, H3: view.H3, Behavior: view.Behavior, ParseError: view.ParseError}
	res := j.engine.Evaluate(in)
	fps.UAFamily, fps.UAOS = optString(res.UAFamily), optString(res.UAOS)
	v := Verdict{
		Class: res.Class, Score: res.Score, Signals: make([]Signal, len(res.Signals)), View: view, Fingerprints: fps,
		Crawler: optString(res.Crawler), RulesVersion: rules.RulesVersion, ListsVersion: j.ListsVersion(),
		Subject: subject, Ts: event.FormatTime(j.now()),
	}
	for i, s := range res.Signals {
		v.Signals[i] = Signal{ID: s.ID, Kind: s.Kind, Weight: s.Weight, Detail: s.Detail}
	}
	return v, res
}

// httpVersion normaliza a versão HTTP para as regras ("1.1", "2", "3").
func httpVersion(proto, version string) string {
	switch {
	case version == "2.0" || version == "2":
		return "2"
	case version == "3.0" || version == "3":
		return "3"
	case version != "":
		return strings.TrimPrefix(version, "HTTP/")
	case proto == "h2":
		return "2"
	case proto == "h3":
		return "3"
	}
	return "1.1"
}

// httpFromAuth é a requisição vista pelo forwardAuth: o traefik repassa os cabeçalhos do visitante (mas não a
// ordem deles), então o bot não calcula o JA4H. Ele vem de X-Traefix-Ja4h (ou do X-Fs-Ja4h antigo), calculado pelo
// traefix, quando bem formado; sem ele, da última requisição da mesma conexão que o ingest já trouxe; sem as duas,
// nenhum (ADR 0058 item 1). source é a origem do JA4H (rótulo de bot_auth_ja4h_total).
func httpFromAuth(h http.Header, f *forkHeaders, fork *ForkConn) (out *rules.HTTP, source string) {
	proto := f.proto
	out = &rules.HTTP{
		UserAgent: clip(h.Get("User-Agent"), maxUserAgentBytes), Version: httpVersion(proto, ""),
		HasAcceptLanguage: len(h.Values("Accept-Language")) > 0,
	}
	// um único valor bem formado (parseForkHeaders): repetido é tão malformado quanto fora do padrão
	if f.ja4h != "" {
		out.JA4H = f.ja4h
		return out, ja4hFromHeader
	}
	if fork != nil && len(fork.Requests) > 0 {
		if out.JA4H = fork.Requests[len(fork.Requests)-1].JA4H; out.JA4H != "" {
			return out, ja4hFromIngest
		}
	}
	return out, ja4hNone
}

// httpFromFork é a requisição resumida pelo ingest do traefix (spec 019 RF-06 e RF-07).
func httpFromFork(r *ForkRequest) *rules.HTTP {
	out := &rules.HTTP{Version: httpVersion(r.Proto, r.HTTPVersion), JA4H: r.JA4H, FieldOrder: r.FieldNames}
	for k, v := range r.Fields {
		if strings.EqualFold(k, "user-agent") {
			out.UserAgent = v
		}
	}
	for _, n := range r.FieldNames {
		if strings.EqualFold(n, "accept-language") {
			out.HasAcceptLanguage = true
		}
	}
	return out
}

// httpFromStore é a requisição resumida pelo store (ADR 0056 item 3): probe e conexões diretas ao espelho.
func httpFromStore(r *StoreRequest) *rules.HTTP {
	out := &rules.HTTP{
		UserAgent: r.UserAgent, Version: httpVersion(r.Proto, r.Version), JA4H: r.JA4H, HasAcceptLanguage: r.AcceptLanguage,
	}
	if r.FieldOrder != "" {
		out.FieldOrder = strings.Split(r.FieldOrder, ",")
	}
	return out
}

// requestSubject monta o sujeito de uma requisição de uma conexão do fork.
func requestSubject(site string, ip netip.Addr, srcPort, dstPort int, fsConnID string, store *StoreConn, method, path string) Subject {
	s := Subject{
		Kind: "request", Site: optString(site), DstPort: ptr(dstPort), FsConnID: ptr(fsConnID), Method: optString(method),
		Path: optString(path),
	}
	if ip.IsValid() {
		s.Src = &endpoint{IP: ip.String(), Port: srcPort}
	}
	if store != nil {
		s.ConnID = ptr(store.ConnID)
	}
	return s
}

// published é o que entra nos agregados quando o veredito de uma requisição é publicado.
type published struct {
	ip   netip.Addr
	site string
	path string
}

// record guarda o veredito da requisição na conexão do fork e, se a requisição ainda não foi publicada pela outra
// fonte, publica no feed e no webhook e soma nos agregados (uma vez por requisição, spec 018 "Comportamento").
// init (opcional) completa a conexão criada pelo forwardAuth antes do registro do traefix.
func (j *Judge) record(id string, fromAuth bool, v *Verdict, res rules.Result, p published, init func(c *ForkConn)) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	var publish, reused bool
	j.index.UpdateFork(id, j.now(), func(c *ForkConn) {
		if init != nil {
			init(c)
		}
		publish, reused = c.claim(fromAuth)
		c.LastVerdict, c.LastClass = data, v.Class
	})
	if !publish {
		return
	}
	j.hub.Publish(v)
	if j.agg == nil {
		return
	}
	fps := []agg.Fingerprint{}
	if f := v.Fingerprints; f != nil {
		for _, x := range []struct {
			kind string
			v    *string
		}{{"ja4", f.JA4}, {"akamai", f.Akamai}, {"ja4h", f.JA4H}, {"ja4t", f.JA4T}} {
			if x.v != nil && *x.v != "" {
				fps = append(fps, agg.Fingerprint{Kind: x.kind, Value: *x.v})
			}
		}
	}
	j.agg.Observe(agg.Request{
		Time: j.now(), IP: p.ip, Site: p.site, Path: p.path, Reused: reused, Class: v.Class, UAFamily: res.UAFamily,
		Fingerprints: fps,
	})
}

// Auth avalia a requisição do forwardAuth com as visões que chegaram na espera e a registra (fonte auth).
func (j *Judge) Auth(f forkHeaders, site, method, path string, h http.Header, fork *ForkConn, store *StoreConn) Verdict {
	req, ja4hSource := httpFromAuth(h, &f, fork)
	j.metrics.Add(authJA4HMetric(ja4hSource), 1)
	var src fpSources
	vw := views{ip: f.srcIP, site: site, fork: fork, store: store, http: req, proto: f.proto, hdr: &f, src: &src}
	v, res := j.evaluate(vw, requestSubject(site, f.srcIP, f.srcPort, f.dstPort, f.fsConnID, store, method, path))
	j.metrics.Add(authFPMetric("tls", src.tls), 1)
	j.metrics.Add(authFPMetric("h2", src.h2), 1)
	j.metrics.Add(authFPMetric("tcp", src.tcp), 1)
	j.record(f.fsConnID, true, &v, res, published{ip: f.srcIP, site: site, path: path}, func(c *ForkConn) {
		// conexão ainda sem registro do traefix: a origem vem dos cabeçalhos (o registro de conexão completa depois). First
		// fica zero: o instante do forwardAuth não é o início da conexão, e numa conexão longa (keep-alive) ele
		// tiraria a do store da janela de 5 s do casamento (RF-04).
		if !c.HasSrc {
			c.SrcIP, c.SrcPort, c.DstPort, c.HasSrc = f.srcIP, f.srcPort, f.dstPort, true
		}
	})
	j.count(SourceAuth, v.Class)
	return v
}

// Ingest avalia a requisição que acabou de chegar pelo ingest do traefix (a última da conexão) e a registra.
// allows confere o site final contra a chave do ingest (nil sem chave): defesa em profundidade da conferência do
// API.ingest, para nenhum veredito, agregado, feed ou webhook sair com o domínio de outra chave (spec 020 RF-03).
// Devolve false quando o site final não é permitido (nada é registrado).
func (j *Judge) Ingest(id string, allows func(string) bool) bool {
	now := j.now()
	fork, ok := j.index.Fork(id, now)
	if !ok || len(fork.Requests) == 0 {
		return true
	}
	req := &fork.Requests[len(fork.Requests)-1]
	var store *StoreConn
	if fork.HasSrc {
		if s, ok := j.index.MatchStore(fork.SrcIP, fork.SrcPort, fork.DstPort, fork.First, now); ok {
			store = &s
		}
	}
	site := fork.Site()
	if a := NormalizeSite(req.Authority); a != "" {
		site = a
	}
	if allows != nil && site != "" && !allows(site) {
		return false
	}
	ip := netip.Addr{}
	if fork.HasSrc {
		ip = fork.SrcIP
	}
	vw := views{ip: ip, site: site, fork: &fork, store: store, http: httpFromFork(req), proto: req.Proto}
	v, res := j.evaluate(vw, requestSubject(site, ip, fork.SrcPort, fork.DstPort, id, store, req.Method, req.Path))
	var init func(c *ForkConn)
	if store != nil && fork.TCP != nil && !fork.ja4tChecked {
		j.compareJA4T(fork.TCP, store)
		init = func(c *ForkConn) { c.ja4tChecked = true }
	}
	j.record(id, false, &v, res, published{ip: ip, site: site, path: req.Path}, init)
	return true
}

// compareJA4T conta a divergência entre o JA4T da visão TCP do traefix e o do store casado, uma vez por conexão
// (bot_ingest_fingerprint_mismatch_total{kind="ja4t"}, ADR 0063 item 5); a visão do store é a que vale nas regras.
func (j *Judge) compareJA4T(t *ForkTCP, store *StoreConn) {
	var rec struct {
		TCP *struct {
			JA4T *string `json:"ja4t"`
		} `json:"tcp"`
	}
	if t.JA4T == "" || json.Unmarshal(store.Record, &rec) != nil || rec.TCP == nil || deref(rec.TCP.JA4T) == "" {
		return
	}
	if *rec.TCP.JA4T != t.JA4T {
		j.metrics.Add(mismatchMetric(mismatchJA4T), 1)
	}
}

// connectionVerdict avalia uma conexão sem veredito de requisição guardado (consulta): a do fork com a do store
// casada, ou só a do store (conexão direta ao espelho).
func (j *Judge) connectionVerdict(fork *ForkConn, store *StoreConn) Verdict {
	vw := views{fork: fork, store: store}
	s := Subject{Kind: "connection"}
	switch {
	case fork != nil:
		vw.site = fork.Site()
		if fork.HasSrc {
			vw.ip = fork.SrcIP
			s.Src, s.DstPort = &endpoint{IP: fork.SrcIP.String(), Port: fork.SrcPort}, ptr(fork.DstPort)
		}
		s.FsConnID = ptr(fork.FsConnID)
		if n := len(fork.Requests); n > 0 {
			vw.http, vw.proto = httpFromFork(&fork.Requests[n-1]), fork.Requests[n-1].Proto
		}
	case store != nil:
		vw.ip, vw.site = store.SrcIP.Unmap(), storeSite(store)
		s.Src, s.DstPort = &endpoint{IP: vw.ip.String(), Port: store.SrcPort}, ptr(store.DstPort)
		if n := len(store.Requests); n > 0 {
			vw.http, vw.proto = httpFromStore(store.Requests[n-1]), store.Requests[n-1].Proto
		}
	}
	if store != nil {
		s.ConnID = ptr(store.ConnID)
		if store.ProbeID != "" {
			s.ProbeID = ptr(store.ProbeID)
		}
	}
	s.Site = optString(vw.site)
	v, _ := j.evaluate(vw, s)
	return v
}

// storeSite é o host da última requisição da conexão do store ("" sem requisição).
func storeSite(c *StoreConn) string {
	for i := len(c.Requests) - 1; i >= 0; i-- {
		if c.Requests[i].Host != "" {
			return c.Requests[i].Host
		}
	}
	return ""
}

// probeSites são os domínios do probe: os hosts de Origin/Referer das requisições dele (ADR 0051 item 3).
func probeSites(conns []StoreConn) []string {
	var out []string
	for i := range conns {
		for _, r := range conns[i].Requests {
			for _, h := range []string{r.OriginHost, r.RefererHost} {
				if h != "" && !containsStr(out, h) {
					out = append(out, h)
				}
			}
		}
	}
	return out
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// probeVerdict avalia cada conexão do probe com requisição HTTP e devolve o veredito mais forte: `good_bot` se
// alguma conexão provou o robô, senão a de maior score (a mais recente no empate). site é o domínio do probe.
func (j *Judge) probeVerdict(probeID, site string, conns []StoreConn) (Verdict, bool) {
	var (
		best  Verdict
		found bool
	)
	for i := range conns {
		c := &conns[i]
		if len(c.Requests) == 0 {
			continue
		}
		r := c.Requests[len(c.Requests)-1]
		ip := c.SrcIP.Unmap()
		vw := views{ip: ip, site: site, store: c, http: httpFromStore(r), proto: r.Proto}
		s := Subject{
			Kind: "probe", Site: optString(site), Src: &endpoint{IP: ip.String(), Port: c.SrcPort}, DstPort: ptr(c.DstPort),
			ConnID: ptr(c.ConnID), ProbeID: ptr(probeID), Method: optString(r.Method),
		}
		v, _ := j.evaluate(vw, s)
		switch {
		case !found, best.Class != ClassGoodBot && (v.Class == ClassGoodBot || v.Score >= best.Score):
			best, found = v, true
		}
	}
	return best, found
}

// ipLists devolve as listas de IP em que o IP está e o robô verificado: pela lista basta para OpenAI e DuckDuckGo
// (ADR 0057 item 1); para os demais, o resultado em cache da verificação por DNS (sem cache: null e a verificação
// vai para o segundo plano, a consulta nunca espera o DNS).
func (j *Judge) ipLists(ip netip.Addr) ([]string, *string) {
	names := []string{}
	if j.lists == nil {
		return names, nil
	}
	var crawler *string
	for _, m := range j.lists.Lookup(ip) {
		names = append(names, m.List)
		if m.Kind != lists.KindGoodBot || crawler != nil {
			continue
		}
		op := robotOperator[m.Robot]
		switch {
		case op != "" && rules.VerifiedByList(op):
			crawler = ptr(m.Robot)
		case lists.HasDNS(m.Robot):
			res, _, ok := j.lists.Verifier().Cached(m.Robot, ip)
			if !ok {
				j.bg.start(j.lists.Verifier(), m.Robot, ip)
			} else if res == lists.VerifyPassed {
				crawler = ptr(m.Robot)
			}
		}
	}
	return names, crawler
}

// fingerprintLabels devolve os rótulos da base própria e da ja4db (só JA4, só com a ja4db ligada).
func (j *Judge) fingerprintLabels(kind, value string) (known, ja4db *string) {
	if j.known != nil {
		known = j.known.label(kind, value)
	}
	if j.ja4db != nil && kind == "ja4" {
		ja4db = j.ja4db.labelText(value)
	}
	return known, ja4db
}

// headerTCP é a visão TCP só do JA4T de X-Traefix-Ja4t (ADR 0063 item 5): o JA4T e os derivados do MSS dele (spec
// 013 RF-06a, família pela origem), sem TTL inicial nem SO.
func headerTCP(ja4t string, ip netip.Addr) *rules.TCP {
	t := &rules.TCP{JA4T: ja4t}
	if mss, ok := ja4tMSS(ja4t); ok {
		family := 4
		if ip.Unmap().Is6() {
			family = 6
		}
		_, t.MTUImplied, t.MSSReduction = mssDerived(mss, family)
	}
	return t
}
