package bot

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Limites de conexão da 9002 (ADR 0073 item 1; spec 020 RF-04). Constantes do código, como o teto global da ADR
// 0051 item 4.
const (
	// MaxConnsPerSource é o teto de conexões simultâneas por origem (IPv4; IPv6 por /64) na 9002.
	MaxConnsPerSource = 16
	// publicIdleHigh é o uso a partir do qual as conexões ociosas mais antigas da 9002 são fechadas (90% de 200).
	publicIdleHigh = 180
	// publicIdleTimeout e internalIdleTimeout são os IdleTimeout das duas portas; readHeaderTimeout vale nas duas e é
	// também o prazo do handshake TLS no net/http.
	publicIdleTimeout   = 30 * time.Second
	internalIdleTimeout = 120 * time.Second
	readHeaderTimeout   = 5 * time.Second
	// publicFullDegraded é por quanto tempo a 9002 cheia deixa o health degraded com "public conns".
	publicFullDegraded = 60 * time.Second
	// metricPublicConnsClosed conta as conexões da 9002 fechadas pelos limites, reason = source | idle.
	metricPublicConnsClosed = "bot_public_conns_closed_total"
)

// Motivos de bot_public_conns_closed_total.
const (
	closedSource = "source"
	closedIdle   = "idle"
)

func publicClosedMetric(reason string) string {
	return metricPublicConnsClosed + `{reason="` + reason + `"}`
}

// sourceOf é a origem de um endereço remoto para o teto por origem: o IPv4 (o mapeado em IPv6 normalizado) ou o /64
// do IPv6. ok é false se o endereço não for IP:porta.
func sourceOf(a net.Addr) (netip.Addr, bool) {
	var ip netip.Addr
	switch v := a.(type) {
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(v.IP)
	default:
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.Addr{}, false
		}
		ip = ap.Addr()
	}
	if !ip.IsValid() {
		return netip.Addr{}, false
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		return ip, true
	}
	p, err := ip.Prefix(64)
	if err != nil {
		return netip.Addr{}, false
	}
	return p.Addr(), true
}

// sourceListener fecha no Accept a conexão que passaria de max por origem, sem entregá-la (embrulhado pelo
// LimitListener, a recusada não ocupa vaga global).
type sourceListener struct {
	net.Listener
	max      int
	onReject func()

	mu     sync.Mutex
	counts map[netip.Addr]int
}

func newSourceListener(l net.Listener, maxPerSource int, onReject func()) *sourceListener {
	return &sourceListener{Listener: l, max: maxPerSource, onReject: onReject, counts: map[netip.Addr]int{}}
}

// Accept devolve a próxima conexão dentro do teto da origem dela; as excedentes são fechadas e contadas.
func (l *sourceListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		src, ok := sourceOf(c.RemoteAddr())
		if !ok {
			return c, nil
		}
		l.mu.Lock()
		if l.counts[src] >= l.max {
			l.mu.Unlock()
			_ = c.Close()
			if l.onReject != nil {
				l.onReject()
			}
			continue
		}
		l.counts[src]++
		l.mu.Unlock()
		return &sourceConn{Conn: c, release: func() { l.release(src) }}, nil
	}
}

func (l *sourceListener) release(src netip.Addr) {
	l.mu.Lock()
	if l.counts[src]--; l.counts[src] <= 0 {
		delete(l.counts, src)
	}
	l.mu.Unlock()
}

// sourceConn devolve a vaga da origem uma vez, no primeiro Close.
type sourceConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *sourceConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// connTracker acompanha as conexões de um http.Server pelo ConnState: com high ou mais abertas, fecha as ociosas
// mais antigas até ficarem menos de high (ADR 0073 item 1.3) e marca quando o uso chegou a full (health).
type connTracker struct {
	high    int
	full    int
	now     func() time.Time
	onClose func()

	mu     sync.Mutex
	open   map[net.Conn]time.Time // aberta → início da ociosidade (zero se não está ociosa)
	fullAt time.Time
}

func newConnTracker(high, full int, now func() time.Time, onClose func()) *connTracker {
	return &connTracker{high: high, full: full, now: now, onClose: onClose, open: map[net.Conn]time.Time{}}
}

// state é o http.Server.ConnState.
func (t *connTracker) state(c net.Conn, s http.ConnState) {
	var victims []net.Conn
	t.mu.Lock()
	switch s {
	case http.StateNew:
		t.open[c] = time.Time{}
		if len(t.open) >= t.full {
			t.fullAt = t.now()
		}
		victims = t.trimLocked()
	case http.StateActive:
		if _, ok := t.open[c]; ok {
			t.open[c] = time.Time{}
		}
	case http.StateIdle:
		if _, ok := t.open[c]; ok {
			t.open[c] = time.Now()
		}
		victims = t.trimLocked()
	case http.StateClosed, http.StateHijacked:
		delete(t.open, c)
	}
	t.mu.Unlock()
	for _, v := range victims {
		_ = v.Close()
		if t.onClose != nil {
			t.onClose()
		}
	}
}

// trimLocked tira do conjunto as ociosas mais antigas enquanto houver high ou mais abertas e as devolve para fechar.
func (t *connTracker) trimLocked() []net.Conn {
	var out []net.Conn
	for len(t.open) >= t.high {
		var (
			oldest net.Conn
			since  time.Time
		)
		for c, idle := range t.open {
			if !idle.IsZero() && (oldest == nil || idle.Before(since)) {
				oldest, since = c, idle
			}
		}
		if oldest == nil {
			break
		}
		delete(t.open, oldest)
		out = append(out, oldest)
	}
	return out
}

// fullSince diz se o uso chegou ao teto nos últimos d.
func (t *connTracker) fullSince(now time.Time, d time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.fullAt.IsZero() && now.Sub(t.fullAt) < d
}
