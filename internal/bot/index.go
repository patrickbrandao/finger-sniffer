package bot

import (
	"container/list"
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"time"
)

// matchWindow é a diferença máxima entre o início da conexão no fork e no store para casar as duas (RF-04).
const matchWindow = 5 * time.Second

// maxForkRequests é quantos resumos de requisição o índice guarda por conexão do fork (os mais novos).
const maxForkRequests = 64

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
	// Record é o Connection do store sem as listas grandes (http, websocket, raw), para a segunda onda.
	Record json.RawMessage
}

// ForkConn é a visão de uma conexão vista pelo traefik modificado (POST /bot/v1/ingest/traefik).
type ForkConn struct {
	FsConnID             string
	First                time.Time
	SrcIP                netip.Addr
	SrcPort              int
	DstPort              int
	HasSrc               bool
	EntryPoint           string
	SNI                  string
	ALPNOffered          []string
	ALPN                 string
	TLSVersion           string
	Cipher               string
	ClientHello          []byte
	ClientHelloTruncated bool
	H2Prefix             []byte
	H2PrefixTruncated    bool
	HasConnRecord        bool
	Requests             []ForkRequest
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
}

type ttlEntry[V any] struct {
	id      string
	src     srcKey
	hasSrc  bool
	touched time.Time
	val     V
}

func newTTLTable[V any](ttl time.Duration, maxEntries int) *ttlTable[V] {
	return &ttlTable[V]{ttl: ttl, max: maxEntries, order: list.New(), byID: map[string]*list.Element{}, bySrc: map[srcKey]*list.Element{}}
}

// put insere ou substitui; devolve quantas entradas foram despejadas pelo teto.
func (t *ttlTable[V]) put(id string, src srcKey, hasSrc bool, val V, now time.Time) (evicted int) {
	t.expire(now)
	if el, ok := t.byID[id]; ok {
		e := el.Value.(*ttlEntry[V]) //nolint:forcetypeassert // só ttlEntry[V] entra na lista
		if e.hasSrc && (!hasSrc || e.src != src) && t.bySrc[e.src] == el {
			delete(t.bySrc, e.src)
		}
		e.src, e.hasSrc, e.touched, e.val = src, hasSrc, now, val
		if hasSrc {
			t.bySrc[src] = el
		}
		t.order.MoveToBack(el)
		return 0
	}
	el := t.order.PushBack(&ttlEntry[V]{id: id, src: src, hasSrc: hasSrc, touched: now, val: val})
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
	delete(t.byID, e.id)
	if e.hasSrc && t.bySrc[e.src] == el {
		delete(t.bySrc, e.src)
	}
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

// Index guarda em memória as conexões vistas pelo store e pelo fork nos últimos FS_BOT_CONN_TTL.
type Index struct {
	mu      sync.Mutex
	store   *ttlTable[*StoreConn]
	fork    *ttlTable[*ForkConn]
	changed chan struct{}
	onEvict func(n int)
}

// NewIndex cria o índice com TTL e teto por visão; onEvict (opcional) recebe os despejos pelo teto.
func NewIndex(ttl time.Duration, maxConns int, onEvict func(n int)) *Index {
	return &Index{
		store: newTTLTable[*StoreConn](ttl, maxConns), fork: newTTLTable[*ForkConn](ttl, maxConns),
		changed: make(chan struct{}), onEvict: onEvict,
	}
}

// notifyLocked acorda quem espera uma visão (Wait); chamado com mu travado.
func (ix *Index) notifyLocked() {
	close(ix.changed)
	ix.changed = make(chan struct{})
}

func (ix *Index) evicted(n int) {
	if n > 0 && ix.onEvict != nil {
		ix.onEvict(n)
	}
}

// PutStore guarda (ou substitui) o estado da conexão do store.
func (ix *Index) PutStore(c *StoreConn, now time.Time) {
	ix.mu.Lock()
	n := ix.store.put(c.ConnID, newSrcKey(c.SrcIP, c.SrcPort, c.DstPort), c.SrcIP.IsValid(), c, now)
	ix.notifyLocked()
	ix.mu.Unlock()
	ix.evicted(n)
}

// UpdateFork aplica f à conexão do fork (criada vazia se não existe) e a guarda.
func (ix *Index) UpdateFork(id string, now time.Time, f func(c *ForkConn)) {
	ix.mu.Lock()
	c, ok := ix.fork.getByID(id, now)
	if !ok {
		c = &ForkConn{FsConnID: id}
	}
	f(c)
	n := ix.fork.put(id, newSrcKey(c.SrcIP, c.SrcPort, c.DstPort), c.HasSrc, c, now)
	ix.notifyLocked()
	ix.mu.Unlock()
	ix.evicted(n)
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
