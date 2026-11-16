package bot

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Estágios de fs.v1.store.connection (asyncapi 0.6.0, StoreConnectionPayload).
const (
	StageOpened  = "opened"
	StageUpdated = "updated"
	StageClosed  = "closed"
)

// keepSpec diz que chaves de um objeto do Connection o Record guarda; o valor nil guarda a chave inteira.
type keepSpec map[string]keepSpec

// tlsKeep são as partes do TLSInfo que entram nos sinais (ADR 0049 item 5): fingerprints, SNI, ALPN e o
// negociado. As listas analisadas (cipher suites com nome, extensões, ClientHello em base64) ficam fora: só elas
// passam de 6 KiB por conexão. Do JA3/JA3N fica só o MD5 (o texto é a lista inteira de novo).
var tlsKeep = keepSpec{
	"sni": nil, "alpn": nil, "ja3_md5": nil, "ja3n_md5": nil, "ja4": nil, "ja4_r": nil,
	"ja4_o": nil, "ja4_stable": nil, "lists_truncated": nil, "negotiated": nil, "handshake_ms": nil,
	"client_hello_truncated": nil,
}

// recordKeep é o que o Record guarda do Connection (memória do índice cheio, spec 018 RNF-02): a identidade, o
// fechamento e o que a visão TCP/TLS/h2/h3 do veredito lê. As requisições viram StoreConn.Requests (ADR 0056
// item 3); websocket, raw, times, totals e as séries do TCP ficam fora.
var recordKeep = keepSpec{
	"conn_id": nil, "probe_id": nil, "proto": nil, "l4": nil, "family": nil, "src": nil, "dst": nil, "started": nil,
	"ended": nil, "requests": nil, "degraded": nil, "close": nil, "offload_suspect": nil,
	"ip":  {"src_kind": nil, "ttl": nil, "ttl_initial": nil, "hops": nil, "df": nil},
	"tcp": {"syn_mss": nil, "mtu_implied": nil, "mss_reduction": nil, "ja4t": nil, "p0f": nil, "os_guess": nil, "rtt_handshake_ms": nil, "rtt_app_ms": nil, "ts_clock_hz": nil},
	"tls": tlsKeep,
	"http2": {
		"mode": nil, "preface_ok": nil, "settings": nil, "window_update": nil, "priorities": nil,
		"priority_frames_capped": nil, "akamai": nil,
	},
	"http3": {
		"version": nil, "transport_params": nil, "transport_params_truncated": nil, "h3_settings": nil,
		"h3_control_stream_seen": nil, "client_hello": tlsKeep,
	},
}

// Tetos do resumo HTTP do store (ADR 0056 item 3).
const (
	maxStoreRequests  = 16  // por conexão: a primeira e as mais recentes
	maxUserAgentBytes = 512 // User-Agent guardado
	maxHostBytes      = 255 // host de authority, Origin e Referer
	maxFieldNames     = 128 // nomes de campo por requisição
)

// StoreRequest é o resumo de uma requisição vista pelo web do espelho (h1, h2 ou h3): nunca caminho, query,
// corpo nem valor de campo além do User-Agent (ADR 0052 item 2, ADR 0056 item 3). É comparável e compartilhado
// entre conexões pelo interner (somente leitura: quem lê não altera).
type StoreRequest struct {
	Proto          string // h1 | h2 | h3
	Method         string
	Version        string // 1.0, 1.1, 2.0, 3.0
	Host           string // só o host da authority (ou do Host), sem porta
	UserAgent      string // até 512 bytes
	HasUserAgent   bool
	FieldOrder     string // nomes dos campos na ordem recebida, sem as pseudo-headers, separados por vírgula
	PseudoOrder    string // h2/h3: pseudo-headers na ordem, separadas por vírgula (`:method,:authority,...`)
	AcceptLanguage bool
	JA4H           string
	OriginHost     string
	RefererHost    string

	fieldCount int // só durante a montagem (zerado antes do interner)
}

// joinNames junta até n nomes (de até 32 bytes cada) por vírgula.
func joinNames(names []string, n int) string {
	var b strings.Builder
	for i, p := range names[:min(len(names), n)] {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(clip(p, 32))
	}
	return b.String()
}

// recordHTTP são as listas de requisições do Connection, decodificadas só nos itens que entram no resumo.
type recordHTTP struct {
	HTTP  []json.RawMessage `json:"http"`
	HTTP2 *struct {
		Streams []json.RawMessage `json:"streams"`
	} `json:"http2"`
	HTTP3 *struct {
		Requests []json.RawMessage `json:"requests"`
	} `json:"http3"`
}

// h1Request são os campos de HTTP1Request lidos para o resumo.
type h1Request struct {
	RequestLine struct {
		Method  string `json:"method"`
		Target  string `json:"target"`
		Form    string `json:"form"`
		Version string `json:"version"`
	} `json:"request_line"`
	Fields [][]string `json:"fields"` // [nome, separador, valor, terminador]
	JA4H   *string    `json:"ja4h"`
}

// hxRequest são os campos de HTTP2Stream/HTTP3Request lidos para o resumo.
type hxRequest struct {
	PseudoOrder []string `json:"pseudo_order"`
	Fields      []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"fields"`
	JA4H *string `json:"ja4h"`
}

// storeRequests monta o resumo HTTP do Connection: h1, depois os streams h2 e as requisições h3, ficando com a
// primeira e as maxStoreRequests-1 mais recentes. Devolve também o total visto e o custo dos resumos que a conexão
// owner criou (contados uma vez cada).
func storeRequests(raw json.RawMessage, owner string) ([]*StoreRequest, int, int64) {
	var rh recordHTTP
	if err := json.Unmarshal(raw, &rh); err != nil {
		return nil, 0, 0
	}
	type item struct {
		proto string
		raw   json.RawMessage
	}
	all := make([]item, 0, len(rh.HTTP))
	for _, r := range rh.HTTP {
		all = append(all, item{"h1", r})
	}
	if rh.HTTP2 != nil {
		for _, r := range rh.HTTP2.Streams {
			all = append(all, item{"h2", r})
		}
	}
	if rh.HTTP3 != nil {
		for _, r := range rh.HTTP3.Requests {
			all = append(all, item{"h3", r})
		}
	}
	if len(all) == 0 {
		return nil, 0, 0
	}
	pick := all
	if len(all) > maxStoreRequests {
		pick = append([]item{all[0]}, all[len(all)-(maxStoreRequests-1):]...)
	}
	out := make([]*StoreRequest, 0, len(pick))
	var charge int64
	for _, it := range pick {
		var (
			r  StoreRequest
			ok bool
		)
		if it.proto == "h1" {
			r, ok = summarizeH1(it.raw)
		} else {
			r, ok = summarizeHX(it.proto, it.raw)
		}
		if ok {
			p, c := internRequest(r, owner)
			if !slices.Contains(out, p) { // o mesmo resumo repetido na conexão conta uma vez
				charge += c
			}
			out = append(out, p)
		}
	}
	return out, len(all), charge
}

func summarizeH1(raw json.RawMessage) (StoreRequest, bool) {
	var q h1Request
	if err := json.Unmarshal(raw, &q); err != nil {
		return StoreRequest{}, false
	}
	r := StoreRequest{
		Proto: "h1", Method: clip(q.RequestLine.Method, 32), JA4H: deref(q.JA4H),
		Version: clip(strings.TrimPrefix(q.RequestLine.Version, "HTTP/"), 8),
	}
	for _, f := range q.Fields {
		if len(f) < 3 {
			continue
		}
		r.addField(f[0], f[2])
	}
	// Em absolute-form o host do alvo vale sobre o Host (RFC 9112 3.2.2); só o host é guardado.
	if q.RequestLine.Form == "absolute" {
		if u, err := url.Parse(q.RequestLine.Target); err == nil && u.Host != "" {
			r.Host = clip(NormalizeSite(u.Host), maxHostBytes)
		}
	}
	return r, true
}

func summarizeHX(proto string, raw json.RawMessage) (StoreRequest, bool) {
	var q hxRequest
	if err := json.Unmarshal(raw, &q); err != nil {
		return StoreRequest{}, false
	}
	r := StoreRequest{Proto: proto, JA4H: deref(q.JA4H), Version: "2.0"}
	if proto == "h3" {
		r.Version = "3.0"
	}
	r.PseudoOrder = joinNames(q.PseudoOrder, 8)
	for _, f := range q.Fields {
		switch {
		case f.Name == ":method":
			r.Method = clip(f.Value, 32)
		case f.Name == ":authority":
			r.Host = clip(NormalizeSite(f.Value), maxHostBytes)
		case strings.HasPrefix(f.Name, ":"):
			// :path e :scheme não entram (nada de caminho, ADR 0052).
		default:
			r.addField(f.Name, f.Value)
		}
	}
	return r, true
}

// addField registra um campo regular: o nome na ordem e, só dos campos do resumo, o valor reduzido.
func (r *StoreRequest) addField(name, value string) {
	if r.fieldCount < maxFieldNames {
		if r.fieldCount > 0 {
			r.FieldOrder += ","
		}
		r.FieldOrder += clip(name, 64)
		r.fieldCount++
	}
	switch strings.ToLower(name) {
	case "host":
		if r.Host == "" {
			r.Host = clip(NormalizeSite(value), maxHostBytes)
		}
	case "user-agent":
		if !r.HasUserAgent {
			r.UserAgent, r.HasUserAgent = clip(value, maxUserAgentBytes), true
		}
	case "accept-language":
		r.AcceptLanguage = true
	case "origin":
		r.OriginHost = urlHost(value)
	case "referer":
		r.RefererHost = urlHost(value)
	}
}

// urlHost devolve só o host de um Origin/Referer (sem esquema, porta, caminho nem query); `null` e inválidos
// dão vazio.
func urlHost(v string) string {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Host == "" {
		return ""
	}
	return clip(NormalizeSite(u.Hostname()), maxHostBytes)
}

// clip corta s em n bytes numa fronteira de runa (a cópia, que solta o texto original, é feita no interner).
func clip(s string, n int) string {
	if len(s) > n {
		s = s[:n]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// interner compartilha os resumos repetidos entre conexões (o mesmo navegador manda o mesmo UA, a mesma ordem de
// campos e o mesmo JA4H em quase todas as requisições): o índice cheio guarda um ponteiro por requisição em vez
// de uma cópia (spec 018 RNF-02). Cheio, recomeça vazio: os resumos já entregues seguem nas conexões até o TTL, e
// nada fica retido além delas por mais que uma geração. Não tem IP nem conn_id (forget não precisa dele).
//
// Contabilidade (ADR 0057 item 2): o texto, a lista, o mapa ou o resumo criado numa geração soma seu custo em c
// (o acumulador de quem pediu) só na criação; quem o reencontra não soma. Assim o texto compartilhado conta uma
// vez, na conexão que o trouxe, e o texto único (tráfego hostil) conta inteiro na sua conexão. O resumo do store
// guarda o conn_id de quem o criou: a mesma conexão republicada (updated/closed) soma de novo, porque a versão
// anterior, que o contava, sai do índice na substituição.
type interner struct {
	mu    sync.Mutex
	max   int
	reqs  map[StoreRequest]*reqItem
	strs  map[string]string
	lists map[string][]string
	maps  map[string]map[string]string
}

// reqItem é um resumo compartilhado, com a conexão que o criou e o custo que ele soma ao índice.
type reqItem struct {
	req    StoreRequest
	owner  string
	charge int64
}

// maxInterned é o teto de cada mapa do interner (resumos e textos), por geração.
const maxInterned = 8192

var shared = &interner{max: maxInterned}

// internRequest devolve o resumo compartilhado igual a r, com os textos copiados (sem segurar o JSON de origem),
// e o custo que ele soma à conexão owner (zero quando outra conexão o criou).
func internRequest(r StoreRequest, owner string) (*StoreRequest, int64) {
	r.fieldCount = 0
	return shared.request(r, owner)
}

func (in *interner) request(r StoreRequest, owner string) (*StoreRequest, int64) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if it, ok := in.reqs[r]; ok {
		if it.owner == owner {
			return &it.req, it.charge
		}
		return &it.req, 0
	}
	if in.reqs == nil || len(in.reqs) >= in.max {
		in.reqs = make(map[StoreRequest]*reqItem, 256)
	}
	c := reqItemBytes
	r.Method, r.Version, r.Host = in.strLocked(r.Method, &c), in.strLocked(r.Version, &c), in.strLocked(r.Host, &c)
	r.UserAgent, r.FieldOrder, r.PseudoOrder = in.strLocked(r.UserAgent, &c), in.strLocked(r.FieldOrder, &c), in.strLocked(r.PseudoOrder, &c)
	r.JA4H, r.OriginHost, r.RefererHost = in.strLocked(r.JA4H, &c), in.strLocked(r.OriginHost, &c), in.strLocked(r.RefererHost, &c)
	it := &reqItem{req: r, owner: owner, charge: c}
	in.reqs[r] = it // chave com os textos copiados: não segura o JSON de origem
	return &it.req, c
}

// str devolve a cópia compartilhada do texto; c (opcional) recebe o custo se o texto foi criado agora.
func (in *interner) str(s string, c *int64) string {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.strLocked(s, c)
}

func (in *interner) strLocked(s string, c *int64) string {
	if s == "" {
		return ""
	}
	if v, ok := in.strs[s]; ok {
		return v
	}
	if in.strs == nil || len(in.strs) >= in.max {
		in.strs = make(map[string]string, 256)
	}
	v := strings.Clone(s)
	in.strs[v] = v
	if c != nil {
		*c += strBytes(len(v))
	}
	return v
}

// list devolve a lista compartilhada igual a l (somente leitura; nil e vazia continuam como vieram).
func (in *interner) list(l []string, c *int64) []string {
	if len(l) == 0 {
		return l
	}
	key := strings.Join(l, "\x00")
	in.mu.Lock()
	defer in.mu.Unlock()
	if v, ok := in.lists[key]; ok {
		return v
	}
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = in.strLocked(s, c)
	}
	if in.lists == nil || len(in.lists) >= in.max {
		in.lists = make(map[string][]string, 256)
	}
	in.lists[strings.Clone(key)] = out
	if c != nil {
		*c += listBytes(len(out))
	}
	return out
}

// fields devolve o mapa compartilhado igual a m (somente leitura).
func (in *interner) fields(m map[string]string, c *int64) map[string]string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(m[k])
		b.WriteByte(0)
	}
	key := b.String()
	in.mu.Lock()
	defer in.mu.Unlock()
	if v, ok := in.maps[key]; ok {
		return v
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[in.strLocked(k, c)] = in.strLocked(v, c)
	}
	if in.maps == nil || len(in.maps) >= in.max {
		in.maps = make(map[string]map[string]string, 256)
	}
	in.maps[key] = out
	if c != nil {
		*c += mapBytes(len(out), fieldSlot)
	}
	return out
}

// storeConnectionPayload é o payload de fs.v1.store.connection.
type storeConnectionPayload struct {
	Stage               string          `json:"stage"`
	ConnectionTruncated bool            `json:"connection_truncated,omitempty"`
	Connection          json.RawMessage `json:"connection"`
}

// connectionSummary são os campos do Connection usados para indexar (ConnectionSummary do openapi do store).
type connectionSummary struct {
	ConnID  string   `json:"conn_id"`
	ProbeID *string  `json:"probe_id"`
	Proto   string   `json:"proto"`
	L4      string   `json:"l4"`
	Src     endpoint `json:"src"`
	Dst     endpoint `json:"dst"`
	Started string   `json:"started"`
}

type endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// errBadStoreConnection marca uma mensagem fora do contrato.
var errBadStoreConnection = errors.New("bot: invalid fs.v1.store.connection")

// ParseStoreConnection lê uma mensagem de fs.v1.store.connection.
func ParseStoreConnection(data []byte) (*StoreConn, error) {
	env, err := event.Decode(data)
	if err != nil {
		return nil, err
	}
	var p storeConnectionPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return nil, fmt.Errorf("%w: %w", errBadStoreConnection, err)
	}
	switch p.Stage {
	case StageOpened, StageUpdated, StageClosed:
	default:
		return nil, fmt.Errorf("%w: stage %q", errBadStoreConnection, p.Stage)
	}
	var s connectionSummary
	if err := json.Unmarshal(p.Connection, &s); err != nil {
		return nil, fmt.Errorf("%w: %w", errBadStoreConnection, err)
	}
	if !ulidPattern(s.ConnID) {
		return nil, fmt.Errorf("%w: conn_id %q", errBadStoreConnection, s.ConnID)
	}
	c := &StoreConn{ConnID: s.ConnID, Stage: p.Stage, L4: s.L4, Proto: s.Proto, SrcPort: s.Src.Port, DstPort: s.Dst.Port}
	if s.ProbeID != nil {
		c.ProbeID = *s.ProbeID
	}
	if c.SrcIP, err = netip.ParseAddr(s.Src.IP); err != nil {
		return nil, fmt.Errorf("%w: src.ip", errBadStoreConnection)
	}
	c.DstIP, _ = netip.ParseAddr(s.Dst.IP)
	if s.Src.Port < 0 || s.Src.Port > 65535 || s.Dst.Port < 0 || s.Dst.Port > 65535 {
		return nil, fmt.Errorf("%w: port", errBadStoreConnection)
	}
	c.Started, _ = time.Parse(time.RFC3339Nano, s.Started)
	c.Requests, c.RequestsSeen, c.reqCharge = storeRequests(p.Connection, c.ConnID)
	c.Record = slimRecord(p.Connection)
	return c, nil
}

// slimRecord guarda do Connection só o que recordKeep lista.
func slimRecord(raw json.RawMessage) json.RawMessage {
	out, ok := keepFields(raw, recordKeep)
	if !ok {
		return nil
	}
	return out
}

// keepFields devolve o objeto só com as chaves de spec (recursivo); fora de objeto (null, lista) fica como veio.
func keepFields(raw json.RawMessage, spec keepSpec) (json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return raw, false
	}
	out := make(map[string]json.RawMessage, len(spec))
	for k, sub := range spec {
		v, ok := m[k]
		if !ok {
			continue
		}
		if sub != nil {
			if kept, ok := keepFields(v, sub); ok {
				v = kept
			}
		}
		out[k] = v
	}
	b, err := json.Marshal(out)
	if err != nil {
		return raw, false
	}
	return b, true
}

// StoreFeed recebe fs.v1.store.connection e alimenta o índice (spec 018 RF-02).
type StoreFeed struct {
	ix       *Index
	now      func() time.Time
	messages atomic.Int64
	invalid  atomic.Int64
	last     atomic.Int64 // unix nano da última mensagem válida
}

// NewStoreFeed cria o receptor.
func NewStoreFeed(ix *Index, now func() time.Time) *StoreFeed {
	if now == nil {
		now = time.Now
	}
	return &StoreFeed{ix: ix, now: now}
}

// Handle trata uma mensagem; inválida é contada e ignorada.
func (f *StoreFeed) Handle(data []byte) error {
	c, err := ParseStoreConnection(data)
	if err != nil {
		f.invalid.Add(1)
		return err
	}
	now := f.now()
	f.messages.Add(1)
	f.last.Store(now.UnixNano())
	f.ix.PutStore(c, now)
	return nil
}

// Messages conta as mensagens válidas (bot_store_feed_messages_total).
func (f *StoreFeed) Messages() int64 { return f.messages.Load() }

// Invalid conta as mensagens fora do contrato.
func (f *StoreFeed) Invalid() int64 { return f.invalid.Load() }

// LastMessage é o instante da última mensagem válida (zero se nenhuma).
func (f *StoreFeed) LastMessage() time.Time {
	if n := f.last.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// ulidPattern confere o formato ULID do contrato (^[0-9A-HJKMNP-TV-Z]{26}$).
func ulidPattern(s string) bool {
	if len(s) != 26 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z' && c != 'I' && c != 'L' && c != 'O' && c != 'U':
		default:
			return false
		}
	}
	return true
}
