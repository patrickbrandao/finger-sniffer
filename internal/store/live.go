package store

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Tipos de LiveEvent (spec 004 "Tempo real").
const (
	LiveConnOpened   = "connection.opened"
	LiveConnUpdated  = "connection.updated"
	LiveConnClosed   = "connection.closed"
	LiveHTTPRequest  = "http.request"
	LiveDNSQuery     = "dns.query"
	LivePacketStray  = "packet.stray"
	LiveStreamDrop   = "stream.dropped"
	liveUpdateWindow = 250 * time.Millisecond // no máximo um connection.updated por conexão nessa janela
)

// LiveKinds lista os kind aceitos no filtro (stream.dropped não se filtra: vai sempre para quem perdeu eventos).
var LiveKinds = []string{LiveConnOpened, LiveConnUpdated, LiveConnClosed, LiveHTTPRequest, LiveDNSQuery, LivePacketStray}

// Padrões de FS_LIVE_BUFFER e FS_LIVE_MAX_CLIENTS (ADR 0020).
const (
	DefaultLiveBuffer     = 1024
	DefaultLiveMaxClients = 64
)

// ErrTooManyLiveClients é devolvido quando FS_LIVE_MAX_CLIENTS já estão conectados (503).
var ErrTooManyLiveClients = errors.New("too many live clients")

// liveEventJSON é o schema LiveEvent.
type liveEventJSON struct {
	Kind    string          `json:"kind"`
	Ts      string          `json:"ts"`
	ConnID  *string         `json:"conn_id"`
	ProbeID *string         `json:"probe_id"`
	Data    json.RawMessage `json:"data"`
}

// liveMsg é um evento já serializado (uma vez), compartilhado entre os clientes, com os campos dos filtros.
type liveMsg struct {
	kind    string
	connID  string
	probe   string
	srcIP   netip.Addr // cliente (dns.query: o resolvedor)
	dstPort int        // porta do espelho (dns.query: 53)
	origin  int64      // ts do evento de origem (ns), para o atraso
	data    []byte     // LiveEvent em JSON
}

// newLiveMsg serializa o LiveEvent.
func newLiveMsg(kind string, origin int64, connID, probe string, src netip.Addr, dstPort int, data []byte) *liveMsg {
	ev := liveEventJSON{Kind: kind, Ts: event.FormatTime(time.Unix(0, origin)), Data: data}
	if connID != "" {
		ev.ConnID = &connID
	}
	if probe != "" {
		ev.ProbeID = &probe
	}
	b, _ := json.Marshal(ev)
	return &liveMsg{kind: kind, connID: connID, probe: probe, srcIP: src, dstPort: dstPort, origin: origin, data: b}
}

// LiveFilter são os filtros do /stream e do /ws (spec 004 RF-08).
type LiveFilter struct {
	Probe   string
	SrcIP   netip.Addr
	DstPort int             // -1 = qualquer
	Kinds   map[string]bool // nil = todos
}

// ParseLiveFilter valida os filtros; erro vira 400 antes do stream/upgrade.
func ParseLiveFilter(get func(string) string) (LiveFilter, error) {
	f := LiveFilter{DstPort: -1}
	if v := get("probe"); v != "" {
		if !validProbeID(v) {
			return f, bad("invalid probe %q", v)
		}
		f.Probe = v
	}
	if v := get("src_ip"); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return f, bad("invalid src_ip %q", v)
		}
		f.SrcIP = a.Unmap()
	}
	if v := get("dst_port"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return f, bad("invalid dst_port %q", v)
		}
		f.DstPort = n
	}
	if v := get("kind"); v != "" {
		f.Kinds = map[string]bool{}
		for _, k := range strings.Split(v, ",") {
			k = strings.TrimSpace(k)
			if !isLiveKind(k) {
				return f, bad("invalid kind %q", k)
			}
			f.Kinds[k] = true
		}
	}
	return f, nil
}

func isLiveKind(k string) bool {
	for _, x := range LiveKinds {
		if k == x {
			return true
		}
	}
	return false
}

// validProbeID segue o pattern ProbeID do openapi (^[a-z0-9]{8,32}$).
func validProbeID(s string) bool {
	if len(s) < 8 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (f LiveFilter) match(m *liveMsg) bool {
	if f.Kinds != nil && !f.Kinds[m.kind] {
		return false
	}
	if f.Probe != "" && m.probe != f.Probe {
		return false
	}
	if f.SrcIP.IsValid() && m.srcIP != f.SrcIP {
		return false
	}
	return f.DstPort < 0 || m.dstPort == f.DstPort
}

// liveClient é um assinante (SSE ou WS) com fila própria.
type liveClient struct {
	filter    LiveFilter
	transport string
	ch        chan *liveMsg
	dropped   atomic.Int64  // descartados desde o último stream.dropped
	notify    chan struct{} // avisa o escritor de que houve descarte
}

// nextDropped devolve o stream.dropped pendente (nil se nada foi descartado) e zera a contagem.
func (c *liveClient) nextDropped(now time.Time) []byte {
	n := c.dropped.Swap(0)
	if n == 0 {
		return nil
	}
	data, _ := json.Marshal(map[string]int64{"dropped": n})
	return newLiveMsg(LiveStreamDrop, now.UnixNano(), "", "", netip.Addr{}, 0, data).data
}

// LiveStats são os contadores do hub (expostos para as métricas do task 054).
type LiveStats struct {
	Clients map[string]int   // por transporte (sse, ws)
	Events  map[string]int64 // emitidos por kind
	Dropped int64
}

// Hub distribui os eventos ao vivo (ADR 0020): em memória, sem replay, fila por cliente com descarte. Publish
// nunca bloqueia.
type Hub struct {
	buffer, max int
	now         func() time.Time
	// OnSend, se definido, recebe o atraso entre o evento de origem e o envio a um cliente.
	OnSend func(kind string, delay time.Duration)

	mu      sync.Mutex
	clients map[*liveClient]struct{}
	events  map[string]int64
	dropped int64
	// Agregação de connection.updated: último envio e o estado mais recente à espera, por conexão.
	lastUpd map[string]int64
	pendUpd map[string]*liveMsg
}

// NewHub cria o hub com FS_LIVE_BUFFER e FS_LIVE_MAX_CLIENTS.
func NewHub(buffer, maxClients int) *Hub {
	if buffer <= 0 {
		buffer = DefaultLiveBuffer
	}
	if maxClients <= 0 {
		maxClients = DefaultLiveMaxClients
	}
	return &Hub{
		buffer: buffer, max: maxClients, now: time.Now, clients: map[*liveClient]struct{}{},
		events: map[string]int64{}, lastUpd: map[string]int64{}, pendUpd: map[string]*liveMsg{},
	}
}

// join registra um cliente; ErrTooManyLiveClients acima do limite.
func (h *Hub) join(f LiveFilter, transport string) (*liveClient, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.clients) >= h.max {
		return nil, ErrTooManyLiveClients
	}
	c := &liveClient{filter: f, transport: transport, ch: make(chan *liveMsg, h.buffer), notify: make(chan struct{}, 1)}
	h.clients[c] = struct{}{}
	return c, nil
}

// leave libera a vaga.
func (h *Hub) leave(c *liveClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, c)
}

// Publish entrega os eventos (já depois do commit) aos clientes cujo filtro casa. connection.updated é
// agregado por conexão; connection.closed descarta o updated pendente da mesma conexão.
func (h *Hub) Publish(msgs ...*liveMsg) {
	if h == nil || len(msgs) == 0 {
		return
	}
	now := h.now().UnixNano()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range msgs {
		switch m.kind {
		case LiveConnUpdated:
			if last, ok := h.lastUpd[m.connID]; ok && now-last < liveUpdateWindow.Nanoseconds() {
				h.pendUpd[m.connID] = m // o último estado vale
				continue
			}
			h.lastUpd[m.connID] = now
		case LiveConnClosed:
			delete(h.pendUpd, m.connID)
			delete(h.lastUpd, m.connID)
		}
		h.fanout(m)
	}
}

// flushUpdates manda os connection.updated cuja janela venceu e esquece as conexões sem atividade.
func (h *Hub) flushUpdates() {
	now := h.now().UnixNano()
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, last := range h.lastUpd {
		if now-last < liveUpdateWindow.Nanoseconds() {
			continue
		}
		if m := h.pendUpd[id]; m != nil {
			delete(h.pendUpd, id)
			h.lastUpd[id] = now
			h.fanout(m)
			continue
		}
		delete(h.lastUpd, id)
	}
}

// fanout enfileira sem bloquear; fila cheia descarta para aquele cliente. Chamado com a trava.
func (h *Hub) fanout(m *liveMsg) {
	h.events[m.kind]++
	for c := range h.clients {
		if !c.filter.match(m) {
			continue
		}
		select {
		case c.ch <- m:
		default:
			c.dropped.Add(1)
			h.dropped++
			select {
			case c.notify <- struct{}{}:
			default:
			}
		}
	}
}

// Stats devolve os contadores atuais.
func (h *Hub) Stats() LiveStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := LiveStats{Clients: map[string]int{"sse": 0, "ws": 0}, Events: map[string]int64{}, Dropped: h.dropped}
	for c := range h.clients {
		s.Clients[c.transport]++
	}
	for k, v := range h.events {
		s.Events[k] = v
	}
	return s
}

// sent registra o atraso de um envio.
func (h *Hub) sent(m *liveMsg) {
	if h.OnSend != nil && m.origin != 0 {
		h.OnSend(m.kind, h.now().Sub(time.Unix(0, m.origin)))
	}
}

// Run agrega os connection.updated até done fechar.
func (h *Hub) Run(done <-chan struct{}) {
	t := time.NewTicker(liveUpdateWindow / 5)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			h.flushUpdates()
		}
	}
}
