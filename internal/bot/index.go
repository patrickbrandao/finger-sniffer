package bot

import (
	"container/list"
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
)

// matchWindow é a diferença máxima entre o início da conexão no fork e no store para casar as duas (RF-04).
const matchWindow = 5 * time.Second

// maxForkRequests é quantos resumos de requisição o índice guarda por conexão do fork (os mais novos), o mesmo
// teto do resumo do store (ADR 0056 item 3): com 64, uma conexão h2 longa de navegador passava de 30 KiB e o
// índice cheio não cabia no GOMEMLIMIT (spec 018 RNF-02, benchmark da task 277).
const maxForkRequests = 16

// srcKey é a chave de casamento das duas visões: origem e porta de destino (spec 018 RF-04), com o IPv4 mapeado
// em IPv6 normalizado.
type srcKey struct {
	ip      netip.Addr
	port    uint16
	dstPort uint16
}

func newSrcKey(ip netip.Addr, port, dstPort int) srcKey {
	return srcKey{ip: ip.Unmap().WithZone(""), port: uint16(port), dstPort: uint16(dstPort)} //nolint:gosec // portas já validadas
}

// StoreConn é a visão de uma conexão publicada pelo store (fs.v1.store.connection).
type StoreConn struct {
	ConnID  string
	ProbeID string
	Stage   string
	L4      string
	Proto   string
	SrcIP   netip.Addr
	SrcPort int
	DstIP   netip.Addr
	DstPort int
	Started time.Time
	// Requests é o resumo HTTP do web (até 16: a primeira e as mais recentes, ADR 0056 item 3); RequestsSeen é
	// quantas requisições o Connection trazia.
	Requests     []*StoreRequest // compartilhados entre conexões (interner): somente leitura
	RequestsSeen int
	// Record é o Connection do store sem as listas grandes nem o ClientHello cru (droppedRecordFields).
	Record json.RawMessage
	// reqCharge é o custo dos resumos de Requests que esta conexão criou no interner (storeBytes).
	reqCharge int64
}

// ForkConn é a visão de uma conexão vista pelo traefik modificado (POST /bot/v1/ingest/traefik).
type ForkConn struct {
	FsConnID    string
	First       time.Time
	SrcIP       netip.Addr
	SrcPort     int
	DstPort     int
	HasSrc      bool
	EntryPoint  string
	SNI         string
	ALPNOffered []string
	ALPN        string
	TLSVersion  string
	Cipher      string
	// TLS e H2 são as visões calculadas do client_hello e do h2_prefix do registro de conexão (spec 018 RF-03);
	// nil quando o traefix não mandou a parte. Os bytes crus não ficam no índice.
	TLS           *ForkTLS
	H2            *ForkH2
	HasConnRecord bool
	Requests      []ForkRequest
	// connCost é o que os textos do registro de conexão somaram no interner (forkBytes).
	connCost int64
}

// ParseError diz se alguma parte do registro de conexão não pôde ser analisada (View.parse_error).
func (f *ForkConn) ParseError() bool {
	return (f.TLS != nil && f.TLS.ParseError) || (f.H2 != nil && f.H2.ParseError)
}

// ForkTLS é a visão TLS do fork: as fingerprints do ClientHello cru, iguais às do web do espelho para os mesmos
// bytes (pkg/tlsparse, pkg/fingerprint). Com ParseError, nenhuma fingerprint é preenchida.
type ForkTLS struct {
	JA3        string
	JA3MD5     string
	JA3N       string
	JA3NMD5    string
	JA4        string
	JA4R       string
	JA4O       string
	SNI        string
	ALPN       []string // ALPN oferecido, na ordem do ClientHello
	Truncated  bool
	ParseError bool
	cost       int64 // estrutura e textos criados (forkBytes)
}

// ForkH2 é a visão h2 do fork, do prefixo do cliente até o primeiro HEADERS (pkg/h2passive). Sem campos nem
// valores: só a ordem das pseudo-headers.
type ForkH2 struct {
	Settings     [][2]uint32
	WindowUpdate *uint32
	Priorities   []h2passive.Priority // anteriores ao primeiro HEADERS, até maxForkPriorities
	PseudoOrder  []string
	HeadersSeen  bool
	Akamai       string
	Truncated    bool
	ParseError   bool
	cost         int64 // estrutura, fatias e textos criados (forkBytes)
}

// ForkRequest é o resumo de uma requisição vista pelo fork (sem query, corpo nem valores de cookie, ADR 0052).
type ForkRequest struct {
	Ts          time.Time
	Proto       string
	Method      string
	Authority   string
	Path        string
	HTTPVersion string
	FieldNames  []string
	Fields      map[string]string
	CookieNames []string
	JA4H        string
	Status      *int
	Router      string
	Service     string
	cost        int64 // caminho, status e textos criados no interner (forkBytes)
}

// Site devolve o domínio da conexão do fork: o SNI ou, sem ele, o authority da última requisição.
func (f *ForkConn) Site() string {
	if f.SNI != "" {
		return NormalizeSite(f.SNI)
	}
	for i := len(f.Requests) - 1; i >= 0; i-- {
		if f.Requests[i].Authority != "" {
			return NormalizeSite(f.Requests[i].Authority)
		}
	}
	return ""
}

// ttlTable guarda entradas por id (e opcionalmente por origem) em ordem de atualização, com TTL e teto: cheia,
// despeja a mais antiga (spec 018 RF-02 e RF-03).
type ttlTable[V any] struct {
	ttl   time.Duration
	max   int
	order *list.List
	byID  map[string]*list.Element
	bySrc map[srcKey]*list.Element
	// bytes é a soma dos custos das entradas (contabilidade aproximada, ADR 0057 item 2).
	bytes int64
	// seq numera as atualizações, em comum entre as visões do índice: ordena o despejo por bytes entre as duas
	// tabelas mesmo com o mesmo instante.
	seq *uint64
	// onRemove (opcional) é chamado quando uma entrada sai (TTL, teto ou forget), para os índices secundários.
	onRemove func(val V)
}

type ttlEntry[V any] struct {
	id      string
	src     srcKey
	hasSrc  bool
	touched time.Time
	seq     uint64
	val     V
	cost    int64
}

func newTTLTable[V any](ttl time.Duration, maxEntries int) *ttlTable[V] {
	return &ttlTable[V]{
		ttl: ttl, max: maxEntries, order: list.New(), byID: map[string]*list.Element{}, bySrc: map[srcKey]*list.Element{},
		seq: new(uint64),
	}
}

// put insere ou substitui a entrada com o custo dado; devolve quantas entradas foram despejadas pelo teto de
// entradas.
func (t *ttlTable[V]) put(id string, src srcKey, hasSrc bool, val V, cost int64, now time.Time) (evicted int) {
	t.expire(now)
	*t.seq++
	if el, ok := t.byID[id]; ok {
		e := el.Value.(*ttlEntry[V]) //nolint:forcetypeassert // só ttlEntry[V] entra na lista
		if e.hasSrc && (!hasSrc || e.src != src) && t.bySrc[e.src] == el {
			delete(t.bySrc, e.src)
		}
		t.bytes += cost - e.cost
		e.src, e.hasSrc, e.touched, e.seq, e.val, e.cost = src, hasSrc, now, *t.seq, val, cost
		if hasSrc {
			t.bySrc[src] = el
		}
		t.order.MoveToBack(el)
		return 0
	}
	el := t.order.PushBack(&ttlEntry[V]{id: id, src: src, hasSrc: hasSrc, touched: now, seq: *t.seq, val: val, cost: cost})
	t.bytes += cost
	t.byID[id] = el
	if hasSrc {
		t.bySrc[src] = el
	}
	for t.order.Len() > t.max {
		t.remove(t.order.Front())
		evicted++
	}
	return evicted
}

func (t *ttlTable[V]) remove(el *list.Element) {
	e := el.Value.(*ttlEntry[V]) //nolint:forcetypeassert // só ttlEntry[V] entra na lista
	t.order.Remove(el)
	t.bytes -= e.cost
	delete(t.byID, e.id)
	if e.hasSrc && t.bySrc[e.src] == el {
		delete(t.bySrc, e.src)
	}
	if t.onRemove != nil {
		t.onRemove(e.val)
	}
}

// oldest devolve o número de atualização da entrada mais antiga (false com a tabela vazia).
func (t *ttlTable[V]) oldest() (uint64, bool) {
	el := t.order.Front()
	if el == nil {
		return 0, false
	}
	return el.Value.(*ttlEntry[V]).seq, true //nolint:forcetypeassert // só ttlEntry[V] entra na lista
}

// peek devolve o valor guardado pelo id, sem conferir o TTL.
func (t *ttlTable[V]) peek(id string) (V, bool) {
	var zero V
	el, ok := t.byID[id]
	if !ok {
		return zero, false
	}
	return el.Value.(*ttlEntry[V]).val, true //nolint:forcetypeassert // idem
}

// expire tira as entradas sem atualização há mais que o TTL.
func (t *ttlTable[V]) expire(now time.Time) {
	cut := now.Add(-t.ttl)
	for el := t.order.Front(); el != nil; el = t.order.Front() {
		if !el.Value.(*ttlEntry[V]).touched.Before(cut) { //nolint:forcetypeassert // só ttlEntry[V] entra na lista
			return
		}
		t.remove(el)
	}
}

func (t *ttlTable[V]) getByID(id string, now time.Time) (V, bool) {
	var zero V
	el, ok := t.byID[id]
	if !ok || el.Value.(*ttlEntry[V]).touched.Before(now.Add(-t.ttl)) { //nolint:forcetypeassert // idem
		return zero, false
	}
	return el.Value.(*ttlEntry[V]).val, true //nolint:forcetypeassert // idem
}

func (t *ttlTable[V]) getBySrc(k srcKey, now time.Time) (V, bool) {
	var zero V
	el, ok := t.bySrc[k]
	if !ok || el.Value.(*ttlEntry[V]).touched.Before(now.Add(-t.ttl)) { //nolint:forcetypeassert // idem
		return zero, false
	}
	return el.Value.(*ttlEntry[V]).val, true //nolint:forcetypeassert // idem
}

// removeSrcIn apaga as entradas cuja origem está no prefixo (forget); devolve quantas saíram.
func (t *ttlTable[V]) removeSrcIn(p netip.Prefix) (n int) {
	for el := t.order.Front(); el != nil; {
		next := el.Next()
		if e := el.Value.(*ttlEntry[V]); e.hasSrc && p.Contains(e.src.ip) { //nolint:forcetypeassert // idem
			t.remove(el)
			n++
		}
		el = next
	}
	return n
}

// Motivos de despejo do índice (rótulo reason de bot_conns_evicted_total, spec 018 RF-02); o vencimento pelo TTL
// não é despejo.
const (
	evictCount = "count"
	evictBytes = "bytes"
)

// Index guarda em memória as conexões vistas pelo store e pelo fork nos últimos FS_BOT_CONN_TTL, com teto de
// conexões por visão (FS_BOT_MAX_CONNS) e de bytes das duas juntas (FS_BOT_INDEX_MAX_BYTES, ADR 0057 item 2).
type Index struct {
	mu    sync.Mutex
	store *ttlTable[*StoreConn]
	fork  *ttlTable[*ForkConn]
	// byProbe são os conn_id do store por probe_id (veredito por probe, spec 018 "Comportamento").
	byProbe  map[string]map[string]struct{}
	changed  chan struct{}
	maxBytes int64
	onEvict  func(reason string, n int)
	// lastBytesEvict é o instante do último despejo por bytes (health "index bytes").
	lastBytesEvict time.Time
}

// NewIndex cria o índice com TTL, teto de conexões por visão e teto de bytes (<= 0 desliga); onEvict (opcional)
// recebe os despejos pelos tetos, com o motivo.
func NewIndex(ttl time.Duration, maxConns int, maxBytes int64, onEvict func(reason string, n int)) *Index {
	ix := &Index{
		store: newTTLTable[*StoreConn](ttl, maxConns), fork: newTTLTable[*ForkConn](ttl, maxConns),
		byProbe: map[string]map[string]struct{}{}, changed: make(chan struct{}), maxBytes: maxBytes, onEvict: onEvict,
	}
	ix.fork.seq = ix.store.seq // a mesma numeração nas duas visões
	ix.store.onRemove = ix.unlinkProbeLocked
	return ix
}

// linkProbeLocked e unlinkProbeLocked mantêm byProbe; chamados com mu travado.
func (ix *Index) linkProbeLocked(c *StoreConn) {
	if c.ProbeID == "" {
		return
	}
	set := ix.byProbe[c.ProbeID]
	if set == nil {
		set = map[string]struct{}{}
		ix.byProbe[c.ProbeID] = set
	}
	set[c.ConnID] = struct{}{}
}

func (ix *Index) unlinkProbeLocked(c *StoreConn) {
	if c.ProbeID == "" {
		return
	}
	if set := ix.byProbe[c.ProbeID]; set != nil {
		delete(set, c.ConnID)
		if len(set) == 0 {
			delete(ix.byProbe, c.ProbeID)
		}
	}
}

// notifyLocked acorda quem espera uma visão (Wait); chamado com mu travado.
func (ix *Index) notifyLocked() {
	close(ix.changed)
	ix.changed = make(chan struct{})
}

func (ix *Index) evicted(byCount, byBytes int) {
	if ix.onEvict == nil {
		return
	}
	if byCount > 0 {
		ix.onEvict(evictCount, byCount)
	}
	if byBytes > 0 {
		ix.onEvict(evictBytes, byBytes)
	}
}

// bytesLocked é o total contabilizado: o índice vazio mais as entradas das duas visões.
func (ix *Index) bytesLocked() int64 { return indexEmptyBytes + ix.store.bytes + ix.fork.bytes }

// enforceBytesLocked despeja as conexões mais antigas das duas visões (a ordem do teto de conexões) até o total
// voltar a caber no teto; devolve quantas saíram.
func (ix *Index) enforceBytesLocked(now time.Time) (n int) {
	for ix.maxBytes > 0 && ix.bytesLocked() > ix.maxBytes {
		st, sok := ix.store.oldest()
		ft, fok := ix.fork.oldest()
		switch {
		case sok && (!fok || st < ft):
			ix.store.remove(ix.store.order.Front())
		case fok:
			ix.fork.remove(ix.fork.order.Front())
		default:
			return n
		}
		n++
	}
	if n > 0 {
		ix.lastBytesEvict = now
	}
	return n
}

// Bytes devolve o total contabilizado do índice depois de vencer o TTL (gauge bot_index_bytes).
func (ix *Index) Bytes(now time.Time) int64 {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.store.expire(now)
	ix.fork.expire(now)
	return ix.bytesLocked()
}

// LastBytesEviction devolve o instante do último despejo por bytes (zero se nenhum).
func (ix *Index) LastBytesEviction() time.Time {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.lastBytesEvict
}

// PutStore guarda (ou substitui) o estado da conexão do store.
func (ix *Index) PutStore(c *StoreConn, now time.Time) {
	ix.mu.Lock()
	if old, ok := ix.store.peek(c.ConnID); ok {
		ix.unlinkProbeLocked(old)
	}
	n := ix.store.put(c.ConnID, newSrcKey(c.SrcIP, c.SrcPort, c.DstPort), c.SrcIP.IsValid(), c, storeBytes(c), now)
	if _, ok := ix.store.peek(c.ConnID); ok {
		ix.linkProbeLocked(c)
	}
	nb := ix.enforceBytesLocked(now)
	ix.notifyLocked()
	ix.mu.Unlock()
	ix.evicted(n, nb)
}

// UpdateFork aplica f à conexão do fork (criada vazia se não existe) e a guarda.
func (ix *Index) UpdateFork(id string, now time.Time, f func(c *ForkConn)) {
	ix.mu.Lock()
	c, ok := ix.fork.getByID(id, now)
	if !ok {
		c = &ForkConn{FsConnID: id}
	}
	f(c)
	n := ix.fork.put(id, newSrcKey(c.SrcIP, c.SrcPort, c.DstPort), c.HasSrc, c, forkBytes(c), now)
	nb := ix.enforceBytesLocked(now)
	ix.notifyLocked()
	ix.mu.Unlock()
	ix.evicted(n, nb)
}

// Fork devolve uma cópia rasa da conexão do fork pelo fs_conn_id.
func (ix *Index) Fork(id string, now time.Time) (ForkConn, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	c, ok := ix.fork.getByID(id, now)
	if !ok {
		return ForkConn{}, false
	}
	return *c, true
}

// ForkBySource devolve a conexão do fork mais recente com a origem e a porta de destino.
func (ix *Index) ForkBySource(ip netip.Addr, port, dstPort int, now time.Time) (ForkConn, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	c, ok := ix.fork.getBySrc(newSrcKey(ip, port, dstPort), now)
	if !ok {
		return ForkConn{}, false
	}
	return *c, true
}

// StoreByID devolve a conexão do store pelo conn_id.
func (ix *Index) StoreByID(id string, now time.Time) (StoreConn, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	c, ok := ix.store.getByID(id, now)
	if !ok {
		return StoreConn{}, false
	}
	return *c, true
}

// StoreByProbe devolve as conexões do store do probe, em ordem de início (veredito por probe, task 282).
func (ix *Index) StoreByProbe(probeID string, now time.Time) []StoreConn {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.store.expire(now)
	set := ix.byProbe[probeID]
	out := make([]StoreConn, 0, len(set))
	for id := range set {
		if c, ok := ix.store.getByID(id, now); ok {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Started.Equal(out[j].Started) {
			return out[i].Started.Before(out[j].Started)
		}
		return out[i].ConnID < out[j].ConnID
	})
	return out
}

// MatchStore casa uma origem vista pelo fork com a conexão do store (spec 018 RF-04): mesma origem, mesma porta
// de destino e início a menos de 5 s (first zero dispensa a conferência do início).
func (ix *Index) MatchStore(ip netip.Addr, port, dstPort int, first, now time.Time) (StoreConn, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	c, ok := ix.store.getBySrc(newSrcKey(ip, port, dstPort), now)
	if !ok {
		return StoreConn{}, false
	}
	if !first.IsZero() && !c.Started.IsZero() {
		if d := first.Sub(c.Started); d > matchWindow || d < -matchWindow {
			return StoreConn{}, false
		}
	}
	return *c, true
}

// Wait espera até ready dar true, o prazo passar ou ctx acabar; ready roda sem a trava do índice.
func (ix *Index) Wait(ctx context.Context, d time.Duration, ready func() bool) bool {
	if ready() {
		return true
	}
	if d <= 0 {
		return false
	}
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		ix.mu.Lock()
		ch := ix.changed
		ix.mu.Unlock()
		if ready() {
			return true
		}
		select {
		case <-ch:
		case <-t.C:
			return ready()
		case <-ctx.Done():
			return false
		}
	}
}

// Forget apaga do índice as conexões com origem no prefixo (ADR 0052 item 5).
func (ix *Index) Forget(p netip.Prefix) int {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.store.removeSrcIn(p) + ix.fork.removeSrcIn(p)
}

// Len devolve quantas conexões há em cada visão.
func (ix *Index) Len() (store, fork int) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.store.order.Len(), ix.fork.order.Len()
}
