package bot

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Códigos de erro da spec 020 RF-07.
const (
	errInvalidKey         = "invalid_key"
	errRateLimited        = "rate_limited"
	errNotFound           = "not_found"
	errBadRequest         = "bad_request"
	errMissingForkHeaders = "missing_fork_headers"
	errPayloadTooLarge    = "payload_too_large"
	errForbiddenOrigin    = "forbidden_origin"
	errInternal           = "internal"
)

// Métricas do heartbeat (spec 018 RF-12) já existentes nesta entrega.
const (
	metricIngestRecords     = "bot_ingest_records_total"
	metricIngestDropped     = "bot_ingest_dropped_total"
	metricIngestParseErrors = "bot_ingest_parse_errors_total"
	metricConnsEvicted      = "bot_conns_evicted_total"
	metricStoreFeedMessages = "bot_store_feed_messages_total"
	metricKeysActive        = "bot_keys_active"
	metricRateLimited       = "bot_rate_limited_total"
	metricDBBytes           = "bot_db_bytes"
	metricPurged            = "bot_purged_total"
)

var probeIDPattern = regexp.MustCompile(`^[a-z0-9]{8,32}$`)

// errorBody é o schema Error.
type errorBody struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// Health é o schema BotHealth do openapi.
type Health struct {
	Status       string       `json:"status"`
	Version      string       `json:"version"`
	Reasons      []string     `json:"reasons,omitempty"`
	RulesVersion string       `json:"rules_version"`
	ListsVersion string       `json:"lists_version"`
	Lists        []ListHealth `json:"lists"`
}

// ListHealth é o estado de uma lista de referência no health.
type ListHealth struct {
	Name      string  `json:"name"`
	Entries   int     `json:"entries"`
	FetchedAt *string `json:"fetched_at"`
	Stale     bool    `json:"stale"`
}

// API atende as rotas /bot/v1 (spec 020, openapi do bot). A mesma API serve a 9002 (Internal=false: chave
// obrigatória exceto em health e openapi.yaml) e a 9003 (Internal=true: só origens de loopback e de Allow, chave
// opcional).
type API struct {
	Keys     *KeyStore
	Limiter  *Limiter
	Index    *Index
	Hub      *Hub
	DB       *sql.DB
	OpenAPI  []byte
	Health   func() Health
	Metrics  *service.Metrics
	Now      func() time.Time
	ViewWait time.Duration
	Judge    *Judge
	// Log (opcional) recebe as linhas do ingest (divergência de fingerprint); nil = slog.Default().
	Log *slog.Logger
	// ignored são os rótulos de bot_ingest_ignored_total{type}; mismatchLog limita o log de divergência a uma
	// linha por minuto (ADRs 0062 item 3 e 0063 item 2).
	ignored     ignoredTypes
	mismatchLog rateLog
}

type ctxKey struct{}

// principal é quem fez a requisição: a chave, ou nil na 9003 sem chave (vale para qualquer domínio).
type principal struct{ key *Key }

func (p principal) allows(site string) bool {
	return p.key == nil || MatchDomain(p.key.Domains, site)
}

func principalFrom(r *http.Request) principal {
	p, _ := r.Context().Value(ctxKey{}).(principal)
	return p
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) count(name string, v float64) {
	if a.Metrics != nil {
		a.Metrics.Add(name, v)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// verdictHeaders são os cabeçalhos do veredito, nos dois conjuntos (os X-Fs-* obsoletos, ADR 0063 item 1).
var verdictHeaders = [...]string{
	"X-Traefix-Verdict", "X-Traefix-Score", "X-Traefix-Signals", "X-Fs-Verdict", "X-Fs-Score", "X-Fs-Signals",
}

// Nenhuma resposta de erro leva os cabeçalhos do veredito (X-Traefix-* nem X-Fs-*), nem os postos antes do erro:
// o traefix separa pelo Verdict o bloqueio (403 do modo block) da falha de configuração ou de limite (fail-open de
// 4xx, ADRs 0058 item 3 e 0063 item 1).
func writeError(w http.ResponseWriter, status int, code, detail string) {
	for _, k := range verdictHeaders {
		w.Header().Del(k)
	}
	writeJSON(w, status, errorBody{Error: code, Detail: detail})
}

// notFound é a resposta única de recurso desconhecido, expirado ou fora dos domínios da chave (spec 020 RF-03):
// o mesmo corpo nos três casos, para não revelar a existência.
func notFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, errNotFound, "unknown, expired or outside the key domains")
}

// Handler devolve o handler de uma das portas; allow são as redes aceitas na 9003, além do loopback.
func (a *API) Handler(internal bool, allow []netip.Prefix) http.Handler {
	mux := http.NewServeMux()
	open := func(h http.HandlerFunc) http.Handler { return h }
	keyed := func(h http.HandlerFunc) http.Handler { return a.authenticate(internal, h) }
	mux.Handle("GET /bot/v1/health", open(a.health))
	mux.Handle("GET /bot/v1/openapi.yaml", open(a.openapi))
	mux.Handle("GET /bot/v1/auth", keyed(a.forwardAuth(internal)))
	mux.Handle("GET /bot/v1/verdict", keyed(a.verdictBySource))
	mux.Handle("GET /bot/v1/verdict/conn/{fs_conn_id}", keyed(a.verdictByConn))
	mux.Handle("GET /bot/v1/probes/{id}/verdict", keyed(a.probeVerdict))
	mux.Handle("GET /bot/v1/ip/{ip}", keyed(a.ipReputation))
	mux.Handle("GET /bot/v1/fingerprints/{kind}/{value}", keyed(a.fingerprintStats))
	mux.Handle("GET /bot/v1/stream", keyed(a.stream))
	mux.Handle("POST /bot/v1/ingest/traefik", keyed(a.ingest))
	mux.Handle("/", keyed(func(w http.ResponseWriter, _ *http.Request) { notFound(w) }))
	if !internal {
		return mux
	}
	return originGuard(allow, mux)
}

// originGuard recusa na 9003 toda origem fora do loopback e das redes permitidas (spec 020 RF-01).
func originGuard(allow []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !originAllowed(r.RemoteAddr, allow) {
			writeError(w, http.StatusForbidden, errForbiddenOrigin, "origin not allowed on the internal port")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func originAllowed(remote string, allow []netip.Prefix) bool {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	if ip.IsLoopback() {
		return true
	}
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// authenticate confere a chave e os limites dela (spec 020 RF-02 e RF-04) e põe o principal no contexto.
func (a *API) authenticate(internal bool, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret, present := bearerKey(r.Header.Get("Authorization"))
		// Na 9003 o forwardAuth repassa os cabeçalhos do visitante: um Authorization que não é chave nossa (Basic,
		// outro Bearer) é do site e não pode virar 401.
		if internal && !strings.HasPrefix(secret, keyPrefix) {
			present = false
		}
		var p principal
		switch {
		case present:
			k, ok := a.Keys.Lookup(secret)
			if !ok {
				writeError(w, http.StatusUnauthorized, errInvalidKey, "unknown or revoked key")
				return
			}
			p.key = k
		case !internal:
			writeError(w, http.StatusUnauthorized, errInvalidKey, "missing Authorization: Bearer fsk_...")
			return
		}
		if p.key != nil {
			if ok, retry := a.Limiter.Allow(r.Context(), p.key); !ok {
				a.count(metricRateLimited, 1)
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				writeError(w, http.StatusTooManyRequests, errRateLimited, "key limit reached")
				return
			}
			a.cors(w, r, p.key)
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

// bearerKey extrai o token de "Authorization: Bearer <token>"; present diz se havia o cabeçalho.
func bearerKey(h string) (string, bool) {
	if h == "" {
		return "", false
	}
	scheme, tok, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", true
	}
	return strings.TrimSpace(tok), true
}

// cors libera a origem só se ela for um domínio da chave, nas rotas GET (spec 020 RF-08).
func (a *API) cors(w http.ResponseWriter, r *http.Request, k *Key) {
	origin := r.Header.Get("Origin")
	if r.Method != http.MethodGet || origin == "" {
		return
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || !MatchDomain(k.Domains, u.Host) {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Add("Vary", "Origin")
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Health())
}

func (a *API) openapi(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(a.OpenAPI)
}

// Prefixos dos cabeçalhos de origem do forwardAuth (ADR 0063 item 1): os do traefix e os antigos, obsoletos.
const (
	prefixTraefix = "X-Traefix-"
	prefixFs      = "X-Fs-"
)

// forkHeaders são os cabeçalhos de origem e de fingerprint que o traefix acrescenta ao forwardAuth (spec 019 RF-05
// e RF-08), de um só conjunto: X-Traefix-* ou, só sem X-Traefix-Conn-Id, os X-Fs-* antigos (nunca misturados).
type forkHeaders struct {
	prefix   string
	srcIP    netip.Addr
	srcPort  int
	dstPort  int
	fsConnID string
	proto    string
	// Fingerprints calculadas pelo traefix (um único valor bem formado; senão vazio, ADRs 0058, 0062 e 0063).
	ja4h string
	ja4  string
	ja3  string
	h2   string
	ja4t string
	// alpn é o ALPN oferecido de X-Traefix-Alpn, decodificado; alpnKnown diz que o cabeçalho veio bem formado.
	alpn      []string
	alpnKnown bool
}

// Formatos dos cabeçalhos de fingerprint (openapi do bot 0.4.0, /bot/v1/auth).
var (
	ja4HeaderPattern  = regexp.MustCompile(`^[tq][0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
	ja4tHeaderPattern = regexp.MustCompile(`^[0-9]+_[0-9-]+_[0-9]{2,}_[0-9]+$`)
)

// Limites de X-Traefix-Alpn (ADR 0063 item 6).
const (
	maxALPNHeader = 1024
	maxALPNValues = 16
	maxALPNValue  = 255
)

// single devolve o valor do cabeçalho quando veio uma vez só (repetido é tão malformado quanto fora do padrão).
func single(h http.Header, name string) string {
	if v := h.Values(name); len(v) == 1 {
		return v[0]
	}
	return ""
}

func parseForkHeaders(h http.Header) (forkHeaders, string, string) {
	f := forkHeaders{prefix: prefixTraefix}
	if len(h.Values(prefixTraefix+"Conn-Id")) == 0 {
		f.prefix = prefixFs
	}
	name := func(n string) string { return f.prefix + n }
	var missing []string
	for _, n := range []string{"Src-Ip", "Src-Port", "Dst-Port", "Conn-Id", "Proto"} {
		if h.Get(name(n)) == "" {
			missing = append(missing, name(n))
		}
	}
	if len(missing) > 0 {
		return f, errMissingForkHeaders, "missing " + strings.Join(missing, ", ")
	}
	var err error
	if f.srcIP, err = netip.ParseAddr(h.Get(name("Src-Ip"))); err != nil {
		return f, errBadRequest, "invalid " + name("Src-Ip")
	}
	f.srcIP = f.srcIP.Unmap().WithZone("")
	if f.srcPort, err = parsePort(h.Get(name("Src-Port"))); err != nil {
		return f, errBadRequest, "invalid " + name("Src-Port")
	}
	if f.dstPort, err = parsePort(h.Get(name("Dst-Port"))); err != nil {
		return f, errBadRequest, "invalid " + name("Dst-Port")
	}
	if f.fsConnID = h.Get(name("Conn-Id")); !ulidPattern(f.fsConnID) {
		return f, errBadRequest, "invalid " + name("Conn-Id")
	}
	switch f.proto = h.Get(name("Proto")); f.proto {
	case "h1", "h2", "h3":
	default:
		return f, errBadRequest, "invalid " + name("Proto")
	}
	// Fingerprints: malformada ou repetida é ausente, sem erro (o veredito sai com o que houver).
	if v := single(h, name("Ja4h")); ja4hPattern.MatchString(v) {
		f.ja4h = v
	}
	if v := single(h, name("Ja4")); ja4HeaderPattern.MatchString(v) {
		f.ja4 = v
	}
	if v := single(h, name("Ja3")); md5Pattern.MatchString(v) {
		f.ja3 = v
	}
	if v := single(h, name("H2")); f.proto == "h2" && len(v) <= maxReadyAkamai && akamaiPattern.MatchString(v) {
		if _, ok := parseAkamai(v); ok {
			f.h2 = v
		}
	}
	// X-Traefix-Alpn e X-Traefix-Ja4t só existem no conjunto novo.
	if f.prefix == prefixTraefix {
		if v := single(h, name("Ja4t")); len(v) <= maxTCPText && ja4tHeaderPattern.MatchString(v) {
			f.ja4t = v
		}
		if vs := h.Values(name("Alpn")); len(vs) == 1 {
			f.alpn, f.alpnKnown = decodeALPNHeader(vs[0])
		}
	}
	return f, "", ""
}

// decodeALPNHeader lê X-Traefix-Alpn: valores por vírgula, na ordem do cliente, com %XX fora do ASCII visível e
// para `,` e `%` (ADR 0063 item 6); até 16 valores de até 255 bytes. Presente e vazio é o ClientHello sem ALPN
// (lista vazia conhecida, pedido PT-15 ao traefix). Fora disso, ok é false (cabeçalho ausente).
func decodeALPNHeader(s string) ([]string, bool) {
	if s == "" {
		return []string{}, true
	}
	if len(s) > maxALPNHeader {
		return nil, false
	}
	parts := strings.Split(s, ",")
	if len(parts) > maxALPNValues {
		return nil, false
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v, err := url.PathUnescape(p)
		if err != nil || v == "" || len(v) > maxALPNValue {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

// coversFork diz se os cabeçalhos já trazem a visão TLS (e a h2, em h2) que o registro de conexão do ingest daria:
// com eles, o forwardAuth não espera o traefix (ADR 0062 item 4).
func (f *forkHeaders) coversFork() bool {
	return f.ja4 != "" && (f.proto != "h2" || f.h2 != "")
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 0 || p > 65535 {
		return 0, errors.New("bot: invalid port")
	}
	return p, nil
}

// cutPath tira a query e corta o caminho em 256 bytes sem partir um caractere (ADR 0052 item 2).
func cutPath(uri string) string {
	path, _, _ := strings.Cut(uri, "?")
	if len(path) <= maxPathBytes {
		return path
	}
	path = path[:maxPathBytes]
	for !utf8.ValidString(path) {
		path = path[:len(path)-1]
	}
	return path
}

// forwardAuth devolve o GET /bot/v1/auth da porta (spec 020 RF-05): espera as visões até FS_BOT_VIEW_WAIT, avalia
// o veredito da requisição e responde 200 (ou 403 em modo block para `bot`) com os cabeçalhos do veredito nos dois
// conjuntos e o Verdict. A verificação de robô nunca segura a resposta (cache ou desconhecido, com a verificação em
// segundo plano). Espera (ADR 0063 item 7): na 9002 (internal=false) o store nunca tem a conexão e não é esperado;
// com X-Traefix-Ja4 (e -H2 em h2) a visão do traefix não é esperada.
func (a *API) forwardAuth(internal bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		f, code, detail := parseForkHeaders(r.Header)
		if code != "" {
			writeError(w, http.StatusBadRequest, code, detail)
			return
		}
		p := principalFrom(r)
		site := NormalizeSite(r.Header.Get("X-Forwarded-Host"))
		if !p.allows(site) {
			// O contrato do forwardAuth não tem 404: o site fora dos domínios da chave é configuração errada do traefik.
			writeError(w, http.StatusBadRequest, errBadRequest, "site outside the key domains")
			return
		}
		var (
			fork    ForkConn
			store   StoreConn
			hasFork bool
			hasTCP  bool
		)
		needFork, needTCP := !f.coversFork(), internal
		a.Index.Wait(r.Context(), a.ViewWait, func() bool {
			now := a.now()
			if !hasFork {
				fork, hasFork = a.Index.Fork(f.fsConnID, now)
			}
			if !hasTCP && internal {
				first := time.Time{}
				if hasFork {
					first = fork.First
				}
				store, hasTCP = a.Index.MatchStore(f.srcIP, f.srcPort, f.dstPort, first, now)
			}
			return (hasFork || !needFork) && (hasTCP || !needTCP)
		})
		waited := time.Since(start)
		if !hasFork && needFork {
			a.count(viewWaitMetric("fork"), 1)
		}
		if !hasTCP && needTCP {
			a.count(viewWaitMetric("tcp"), 1)
		}
		var fp *ForkConn
		if hasFork {
			fp = &fork
		}
		var sp *StoreConn
		if hasTCP {
			sp = &store
		}
		v := a.Judge.Auth(f, site, r.Header.Get("X-Forwarded-Method"), cutPath(r.Header.Get("X-Forwarded-Uri")), r.Header, fp, sp)
		vals := [3]string{v.Class, strconv.Itoa(v.Score), signalIDs(v.Signals)}
		for i, k := range verdictHeaders {
			w.Header().Set(k, vals[i%3])
		}
		status := http.StatusOK
		if p.key != nil && p.key.Mode == ModeBlock && v.Class == ClassBot {
			status = http.StatusForbidden
		}
		writeJSON(w, status, v)
		a.Judge.authWait.Observe(waited)
		a.Judge.authTime.Observe(time.Since(start))
	}
}

// signalIDs junta os ids por vírgula, até 1 KiB (cabeçalhos X-Traefix-Signals e X-Fs-Signals).
func signalIDs(s []Signal) string {
	var b strings.Builder
	for _, sig := range s {
		if b.Len()+len(sig.ID)+1 > 1024 {
			break
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(sig.ID)
	}
	return b.String()
}

// parseWait lê o parâmetro wait (0–1000 ms).
func parseWait(r *http.Request) (time.Duration, bool) {
	s := r.URL.Query().Get("wait")
	if s == "" {
		return 0, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 1000 {
		return 0, false
	}
	return time.Duration(n) * time.Millisecond, true
}

// writeVerdict responde um veredito já serializado (o guardado na conexão).
func writeVerdict(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// connResult é o que a consulta achou de uma conexão: a do fork (com o veredito guardado) e a do store casada.
type connResult struct {
	fork    ForkConn
	hasFork bool
	store   StoreConn
	hasTCP  bool
}

// lookupFork lê a conexão do fork e a do store casada; ready diz se já há o que responder sem esperar mais.
func (a *API) lookupFork(c *connResult, fork ForkConn, now time.Time) bool {
	c.fork, c.hasFork = fork, true
	if !c.hasTCP && fork.HasSrc {
		c.store, c.hasTCP = a.Index.MatchStore(fork.SrcIP, fork.SrcPort, fork.DstPort, fork.First, now)
	}
	return fork.LastVerdict != nil || c.hasTCP
}

// answerConn responde o último veredito da conexão do fork (o da última requisição) ou, sem ele, o da conexão.
func (a *API) answerConn(w http.ResponseWriter, c *connResult) {
	if c.hasFork && c.fork.LastVerdict != nil {
		a.Judge.count(SourceQuery, c.fork.LastClass)
		writeVerdict(w, c.fork.LastVerdict)
		return
	}
	var fp *ForkConn
	if c.hasFork {
		fp = &c.fork
	}
	var sp *StoreConn
	if c.hasTCP {
		sp = &c.store
	}
	v := a.Judge.connectionVerdict(fp, sp)
	a.Judge.count(SourceQuery, v.Class)
	writeJSON(w, http.StatusOK, v)
}

// verdictBySource é o GET /bot/v1/verdict: a conexão mais recente com a origem dada e o site pedido (a do fork; sem
// ela, a do store com requisição daquele host). Site fora da chave, conexão desconhecida ou de outro site: o mesmo
// 404.
func (a *API) verdictBySource(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip, err := netip.ParseAddr(q.Get("src_ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, errBadRequest, "invalid src_ip")
		return
	}
	port, err := parsePort(q.Get("src_port"))
	if err != nil {
		writeError(w, http.StatusBadRequest, errBadRequest, "invalid src_port")
		return
	}
	site := NormalizeSite(q.Get("site"))
	if site == "" {
		writeError(w, http.StatusBadRequest, errBadRequest, "site is required")
		return
	}
	wait, ok := parseWait(r)
	if !ok {
		writeError(w, http.StatusBadRequest, errBadRequest, "wait must be 0-1000")
		return
	}
	if !principalFrom(r).allows(site) {
		notFound(w)
		return
	}
	ip = ip.Unmap().WithZone("")
	var (
		c        connResult
		direct   StoreConn
		hasStore bool
	)
	a.Index.Wait(r.Context(), wait, func() bool {
		now := a.now()
		if fork, ok := a.Index.ForkByOrigin(ip, port, now); ok && fork.Site() == site {
			return a.lookupFork(&c, fork, now)
		}
		if s, ok := a.Index.StoreByOrigin(ip, port, now); ok && storeSite(&s) == site {
			direct, hasStore = s, true
			return true
		}
		return false
	})
	switch {
	case c.hasFork:
		a.answerConn(w, &c)
	case hasStore:
		a.answerConn(w, &connResult{store: direct, hasTCP: true})
	default:
		notFound(w)
	}
}

// verdictByConn é o GET /bot/v1/verdict/conn/{fs_conn_id}.
func (a *API) verdictByConn(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("fs_conn_id")
	if !ulidPattern(id) {
		writeError(w, http.StatusBadRequest, errBadRequest, "invalid fs_conn_id")
		return
	}
	wait, ok := parseWait(r)
	if !ok {
		writeError(w, http.StatusBadRequest, errBadRequest, "wait must be 0-1000")
		return
	}
	var c connResult
	a.Index.Wait(r.Context(), wait, func() bool {
		now := a.now()
		fork, ok := a.Index.Fork(id, now)
		return ok && a.lookupFork(&c, fork, now)
	})
	if !c.hasFork || !principalFrom(r).allows(c.fork.Site()) {
		notFound(w)
		return
	}
	a.answerConn(w, &c)
}

// probeVerdict é o GET /bot/v1/probes/{id}/verdict: veredito sobre as conexões do probe vistas pelo store; o
// domínio é o host de Origin/Referer delas (ADR 0051 item 3). Sem conexões com requisição, ou sem domínio da chave:
// o mesmo 404.
func (a *API) probeVerdict(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !probeIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, errBadRequest, "invalid probe id")
		return
	}
	wait, ok := parseWait(r)
	if !ok {
		writeError(w, http.StatusBadRequest, errBadRequest, "wait must be 0-1000")
		return
	}
	var conns []StoreConn
	a.Index.Wait(r.Context(), wait, func() bool {
		conns = a.Index.StoreByProbe(id, a.now())
		for i := range conns {
			if len(conns[i].Requests) > 0 {
				return true
			}
		}
		return false
	})
	p := principalFrom(r)
	site, allowed := "", p.key == nil
	for _, s := range probeSites(conns) {
		if p.allows(s) {
			site, allowed = s, true
			break
		}
	}
	if !allowed {
		notFound(w)
		return
	}
	v, ok := a.Judge.probeVerdict(id, site, conns)
	if !ok {
		notFound(w)
		return
	}
	a.Judge.count(SourceProbe, v.Class)
	writeJSON(w, http.StatusOK, v)
}

// ipDay é um item de IPReputation.days.
type ipDay struct {
	Day      string           `json:"day"`
	Site     string           `json:"site"`
	Requests int64            `json:"requests"`
	Conns    int64            `json:"conns"`
	Classes  map[string]int64 `json:"classes"`
}

// ipReputation é o GET /bot/v1/ip/{ip}: agregados por dia nos domínios da chave, as listas de IP em que o IP
// está e o robô verificado (cache da verificação; sem cache, null e a verificação segue em segundo plano).
func (a *API) ipReputation(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, errBadRequest, "invalid ip")
		return
	}
	ip = ip.Unmap().WithZone("")
	rows, err := a.DB.QueryContext(r.Context(), `SELECT site, hour / 24, sum(requests), sum(conns), sum(class_human),
		sum(class_bot), sum(class_suspect), sum(class_good_bot), sum(class_unknown)
		FROM ip_hourly WHERE ip = ? GROUP BY site, hour / 24 ORDER BY hour / 24, site`, ipKey(ip))
	if err != nil {
		writeError(w, http.StatusInternalServerError, errInternal, "query failed")
		return
	}
	defer func() { _ = rows.Close() }()
	p := principalFrom(r)
	days := []ipDay{}
	for rows.Next() {
		var (
			d                               ipDay
			day                             int64
			human, bot, suspect, good, unkn int64
		)
		if err := rows.Scan(&d.Site, &day, &d.Requests, &d.Conns, &human, &bot, &suspect, &good, &unkn); err != nil {
			writeError(w, http.StatusInternalServerError, errInternal, "query failed")
			return
		}
		if !p.allows(d.Site) {
			continue
		}
		d.Day = time.Unix(day*86400, 0).UTC().Format(time.DateOnly)
		d.Classes = map[string]int64{ClassHuman: human, ClassBot: bot, ClassSuspect: suspect, ClassGoodBot: good, ClassUnknown: unkn}
		days = append(days, d)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, errInternal, "query failed")
		return
	}
	names, crawler := a.Judge.ipLists(ip)
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip.String(), "days": days, "lists": names, "crawler_verified": crawler})
}

// fpDay é um item de FingerprintStats.days.
type fpDay struct {
	Day        string `json:"day"`
	UAFamily   string `json:"ua_family"`
	Requests   int64  `json:"requests"`
	IPs        int64  `json:"ips"`
	ClassBot   int64  `json:"class_bot"`
	ClassHuman int64  `json:"class_human"`
}

// fingerprintStats é o GET /bot/v1/fingerprints/{kind}/{value}: contagens dos 7 dias (sem IP), o rótulo da base
// própria (famílias medidas) e o da ja4db (null com ela desligada, ADR 0056 item 1).
func (a *API) fingerprintStats(w http.ResponseWriter, r *http.Request) {
	kind, value := r.PathValue("kind"), r.PathValue("value")
	switch kind {
	case "ja4", "akamai", "ja4h", "ja4t":
	default:
		writeError(w, http.StatusBadRequest, errBadRequest, "kind must be ja4, akamai, ja4h or ja4t")
		return
	}
	if value == "" || utf8.RuneCountInString(value) > 512 {
		writeError(w, http.StatusBadRequest, errBadRequest, "invalid value")
		return
	}
	rows, err := a.DB.QueryContext(r.Context(), `SELECT day, ua_family, requests, ips, class_bot, class_human
		FROM fp_daily WHERE kind = ? AND value = ? ORDER BY day, ua_family`, kind, value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errInternal, "query failed")
		return
	}
	defer func() { _ = rows.Close() }()
	days := []fpDay{}
	for rows.Next() {
		var d fpDay
		var day int64
		if err := rows.Scan(&day, &d.UAFamily, &d.Requests, &d.IPs, &d.ClassBot, &d.ClassHuman); err != nil {
			writeError(w, http.StatusInternalServerError, errInternal, "query failed")
			return
		}
		d.Day = time.Unix(day*86400, 0).UTC().Format(time.DateOnly)
		days = append(days, d)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, errInternal, "query failed")
		return
	}
	known, label := a.Judge.fingerprintLabels(kind, value)
	writeJSON(w, http.StatusOK, map[string]any{"kind": kind, "value": value, "known_client": known, "ja4db_label": label, "days": days})
}

// stream é o GET /bot/v1/stream (SSE de VerdictEvent dos domínios da chave).
func (a *API) stream(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	c := &streamClient{queue: make(chan *Verdict, streamQueue), site: NormalizeSite(r.URL.Query().Get("site"))}
	if p.key != nil {
		c.domains = p.key.Domains
	}
	if cl := r.URL.Query().Get("class"); cl != "" {
		c.classes = map[string]bool{}
		for _, x := range strings.Split(cl, ",") {
			if x = strings.TrimSpace(x); x != "" {
				c.classes[x] = true
			}
		}
	}
	if err := a.Hub.add(c); err != nil {
		writeError(w, http.StatusServiceUnavailable, errInternal, "too many stream clients")
		return
	}
	defer a.Hub.remove(c)
	a.Hub.serve(r.Context(), w, c)
}

// ingest é o POST /bot/v1/ingest/traefik (spec 020 RF-05, spec 018 RF-03).
func (a *API) ingest(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > MaxIngestBytes {
		writeError(w, http.StatusRequestEntityTooLarge, errPayloadTooLarge, "batch larger than 4 MiB")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxIngestBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, errPayloadTooLarge, "batch larger than 4 MiB")
			return
		}
		writeError(w, http.StatusBadRequest, errBadRequest, "body read failed")
		return
	}
	batch, err := decodeBatch(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, errBadRequest, err.Error())
		return
	}
	var env ingestEnv
	if batch.schema == SchemaTraefixV1 && a.Judge != nil {
		env.p0f = a.Judge.p0f.get()
	}
	p := principalFrom(r)
	accepted, rejected := 0, 0
	for _, raw := range batch.records {
		var (
			rec parsedRecord
			err error
		)
		if batch.schema == SchemaTraefixV1 {
			rec, err = parseTraefixRecord(raw, batch.entryPoint, env)
		} else {
			rec, err = parseRecord(raw)
		}
		// Tipo de registro desconhecido do traefix: ignorado, fora de accepted e rejected (ADR 0063 item 2).
		if err == nil && rec.ignored {
			a.count(metricIngestIgnored+`{type="`+a.ignored.label(rec.ignoredType)+`"}`, 1)
			continue
		}
		// Com chave, só entram registros de sites dela: SNI e authority do registro e o domínio que a conexão já
		// tem no índice precisam todos ser da chave (spec 020 RF-03). Sem site conhecido, o registro entra (a
		// conexão ainda pode trazer o SNI depois, e o Judge e a consulta conferem o domínio de novo).
		if err == nil && p.key != nil && !a.ingestAllowed(p, &rec) {
			err = errBadRecord
		}
		if err != nil {
			rejected++
			continue
		}
		for _, part := range rec.ParseErrors() {
			a.count(metricIngestParseErrors+`{part="`+part+`"}`, 1)
		}
		a.countMismatches(rec.mismatches, rec.r.FsConnID)
		a.Index.UpdateFork(rec.r.FsConnID, a.now(), rec.apply)
		if rec.r.Type == "request" {
			// veredito por requisição na chegada do resumo (publicado se o forwardAuth ainda não o fez)
			if !a.Judge.Ingest(rec.r.FsConnID, p.allows) {
				rejected++
				continue
			}
		}
		accepted++
	}
	a.count(metricIngestRecords, float64(accepted))
	a.count(metricIngestDropped, float64(rejected))
	writeJSON(w, http.StatusAccepted, map[string]int{"accepted": accepted, "rejected": rejected})
}

// countMismatches conta as divergências entre o calculado pelo bot e o pronto do traefix e escreve no máximo uma
// linha de log por minuto (ADR 0062 item 3).
func (a *API) countMismatches(kinds []string, connID string) {
	if len(kinds) == 0 {
		return
	}
	for _, k := range kinds {
		a.count(mismatchMetric(k), 1)
	}
	if a.mismatchLog.allow(a.now()) {
		logger(a.Log).Warn("bot: traefix fingerprint differs from the computed one", "kinds", kinds, "conn_id", connID)
	}
}

// ingestAllowed confere os domínios do registro e o da conexão já indexada contra os da chave.
func (a *API) ingestAllowed(p principal, rec *parsedRecord) bool {
	for _, s := range rec.sites() {
		if !p.allows(s) {
			return false
		}
	}
	if c, ok := a.Index.Fork(rec.r.FsConnID, a.now()); ok {
		if s := c.Site(); s != "" && !p.allows(s) {
			return false
		}
	}
	return true
}

// listenerAddrs combina cada IP com a porta.
func listenerAddrs(ips []netip.Addr, port int) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}
	sort.Strings(out)
	return out
}
