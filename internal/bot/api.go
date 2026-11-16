package bot

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
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

func writeError(w http.ResponseWriter, status int, code, detail string) {
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
	mux.Handle("GET /bot/v1/auth", keyed(a.forwardAuth))
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

// forkHeaders são os X-Fs-* que o fork acrescenta (spec 019 RF-06).
type forkHeaders struct {
	srcIP    netip.Addr
	srcPort  int
	dstPort  int
	fsConnID string
	proto    string
}

func parseForkHeaders(h http.Header) (forkHeaders, string, string) {
	var f forkHeaders
	names := []string{"X-Fs-Src-Ip", "X-Fs-Src-Port", "X-Fs-Dst-Port", "X-Fs-Conn-Id", "X-Fs-Proto"}
	var missing []string
	for _, n := range names {
		if h.Get(n) == "" {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return f, errMissingForkHeaders, "missing " + strings.Join(missing, ", ")
	}
	var err error
	if f.srcIP, err = netip.ParseAddr(h.Get("X-Fs-Src-Ip")); err != nil {
		return f, errBadRequest, "invalid X-Fs-Src-Ip"
	}
	f.srcIP = f.srcIP.Unmap().WithZone("")
	if f.srcPort, err = parsePort(h.Get("X-Fs-Src-Port")); err != nil {
		return f, errBadRequest, "invalid X-Fs-Src-Port"
	}
	if f.dstPort, err = parsePort(h.Get("X-Fs-Dst-Port")); err != nil {
		return f, errBadRequest, "invalid X-Fs-Dst-Port"
	}
	if f.fsConnID = h.Get("X-Fs-Conn-Id"); !ulidPattern(f.fsConnID) {
		return f, errBadRequest, "invalid X-Fs-Conn-Id"
	}
	switch f.proto = h.Get("X-Fs-Proto"); f.proto {
	case "h1", "h2", "h3":
	default:
		return f, errBadRequest, "invalid X-Fs-Proto"
	}
	return f, "", ""
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

// forwardAuth é o GET /bot/v1/auth (spec 020 RF-05). Sem regras nesta entrega, o veredito é `unknown`; espera
// as duas visões até FS_BOT_VIEW_WAIT e diz em `view` o que havia.
func (a *API) forwardAuth(w http.ResponseWriter, r *http.Request) {
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
	a.Index.Wait(r.Context(), a.ViewWait, func() bool {
		now := a.now()
		if !hasFork {
			fork, hasFork = a.Index.Fork(f.fsConnID, now)
		}
		if !hasTCP {
			first := time.Time{}
			if hasFork {
				first = fork.First
			}
			store, hasTCP = a.Index.MatchStore(f.srcIP, f.srcPort, f.dstPort, first, now)
		}
		return hasFork && hasTCP
	})
	subject := Subject{
		Kind: "request", Site: optString(site), Src: &endpoint{IP: f.srcIP.String(), Port: f.srcPort},
		DstPort: ptr(f.dstPort), FsConnID: ptr(f.fsConnID), Method: optString(r.Header.Get("X-Forwarded-Method")),
		Path: optString(cutPath(r.Header.Get("X-Forwarded-Uri"))),
	}
	if hasTCP {
		subject.ConnID = ptr(store.ConnID)
	}
	view := View{
		TCP: hasTCP, TLS: hasFork && fork.TLS != nil && !fork.TLS.ParseError, HTTP: true, H2: f.proto == "h2",
		H3: f.proto == "h3", ParseError: hasFork && fork.ParseError(),
	}
	v := unknownVerdict(subject, view, a.now())
	w.Header().Set("X-Fs-Verdict", v.Class)
	w.Header().Set("X-Fs-Score", strconv.Itoa(v.Score))
	w.Header().Set("X-Fs-Signals", signalIDs(v.Signals))
	status := http.StatusOK
	if p.key != nil && p.key.Mode == ModeBlock && v.Class == ClassBot {
		status = http.StatusForbidden
	}
	writeJSON(w, status, v)
}

// signalIDs junta os ids por vírgula, até 1 KiB (cabeçalho X-Fs-Signals).
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

// verdictBySource é o GET /bot/v1/verdict. Os vereditos chegam na segunda onda: por ora 404 para tudo, depois de
// validar os parâmetros (e o domínio, que dá o mesmo 404).
func (a *API) verdictBySource(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if _, err := netip.ParseAddr(q.Get("src_ip")); err != nil {
		writeError(w, http.StatusBadRequest, errBadRequest, "invalid src_ip")
		return
	}
	if _, err := parsePort(q.Get("src_port")); err != nil {
		writeError(w, http.StatusBadRequest, errBadRequest, "invalid src_port")
		return
	}
	site := NormalizeSite(q.Get("site"))
	if site == "" {
		writeError(w, http.StatusBadRequest, errBadRequest, "site is required")
		return
	}
	if _, ok := parseWait(r); !ok {
		writeError(w, http.StatusBadRequest, errBadRequest, "wait must be 0-1000")
		return
	}
	notFound(w)
}

// verdictByConn é o GET /bot/v1/verdict/conn/{fs_conn_id}; 404 até a segunda onda.
func (a *API) verdictByConn(w http.ResponseWriter, r *http.Request) {
	if !ulidPattern(r.PathValue("fs_conn_id")) {
		writeError(w, http.StatusBadRequest, errBadRequest, "invalid fs_conn_id")
		return
	}
	if _, ok := parseWait(r); !ok {
		writeError(w, http.StatusBadRequest, errBadRequest, "wait must be 0-1000")
		return
	}
	notFound(w)
}

// probeVerdict é o GET /bot/v1/probes/{id}/verdict; 404 até a segunda onda.
func (a *API) probeVerdict(w http.ResponseWriter, r *http.Request) {
	if !probeIDPattern.MatchString(r.PathValue("id")) {
		writeError(w, http.StatusBadRequest, errBadRequest, "invalid probe id")
		return
	}
	if _, ok := parseWait(r); !ok {
		writeError(w, http.StatusBadRequest, errBadRequest, "wait must be 0-1000")
		return
	}
	notFound(w)
}

// ipDay é um item de IPReputation.days.
type ipDay struct {
	Day      string           `json:"day"`
	Site     string           `json:"site"`
	Requests int64            `json:"requests"`
	Conns    int64            `json:"conns"`
	Classes  map[string]int64 `json:"classes"`
}

// ipReputation é o GET /bot/v1/ip/{ip}: agregados por dia nos domínios da chave. As listas e a verificação de
// robô vêm na segunda onda (vazias por ora).
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
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip.String(), "days": days, "lists": []string{}, "crawler_verified": nil})
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

// fingerprintStats é o GET /bot/v1/fingerprints/{kind}/{value}: contagens dos 7 dias (sem IP). Os rótulos da
// base própria e da ja4db vêm na segunda onda.
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
	writeJSON(w, http.StatusOK, map[string]any{"kind": kind, "value": value, "known_client": nil, "ja4db_label": nil, "days": days})
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
	batch, err := DecodeIngestBatch(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, errBadRequest, err.Error())
		return
	}
	p := principalFrom(r)
	accepted, rejected := 0, 0
	for _, raw := range batch.Records {
		rec, err := parseRecord(raw)
		// Com chave, só entram registros de sites dela; sem site conhecido, o registro entra (a conexão ainda pode
		// trazer o SNI depois, e a consulta confere o domínio de novo).
		if err == nil && p.key != nil {
			if s := rec.site(); s != "" && !p.allows(s) {
				err = errBadRecord
			}
		}
		if err != nil {
			rejected++
			continue
		}
		for _, part := range rec.ParseErrors() {
			a.count(metricIngestParseErrors+`{part="`+part+`"}`, 1)
		}
		a.Index.UpdateFork(rec.r.FsConnID, a.now(), rec.apply)
		accepted++
	}
	a.count(metricIngestRecords, float64(accepted))
	a.count(metricIngestDropped, float64(rejected))
	writeJSON(w, http.StatusAccepted, map[string]int{"accepted": accepted, "rejected": rejected})
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
