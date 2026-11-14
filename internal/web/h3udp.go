package web

import (
	"container/list"
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// Tetos da análise do Initial antes do quic-go (spec 011 RF-02, ADR 0019).
const (
	// initWindow é por quanto tempo, desde o primeiro datagrama da 5-tupla, os Initials são analisados.
	initWindow = 2 * time.Second
	// initMaxBytes é o teto global de bytes de datagramas analisados pelas 5-tuplas vivas (memória).
	initMaxBytes = 8 << 20
	// initMaxEntries é o teto de 5-tuplas acompanhadas ao mesmo tempo.
	initMaxEntries = 4096
	// initSweepEvery é o intervalo mínimo entre limpezas da tabela.
	initSweepEvery = time.Second
)

// MetricH3InitTableFull conta as 5-tuplas novas que acharam a tabela de Initials cheia (com ou sem despejo;
// spec 011, task 143).
const MetricH3InitTableFull = "web_h3_init_table_full_total"

// initOrphanAfter: 5-tupla com ClientHello completo e sem conexão aceita depois disso vira handshake_failed
// (variável para os testes). Sem ClientHello completo, a entrada não reclamada sai ao fim de initWindow.
var initOrphanAfter = 10 * time.Second

// udpConn envolve o socket UDP e entrega cada datagrama ao tracker antes do quic-go. Só implementa
// net.PacketConn e os ajustes de buffer: sem ReadMsgUDP/SyscallConn o quic-go não usa GSO, GRO nem ECN
// (ADR 0019).
type udpConn struct {
	c   *net.UDPConn
	obs func(local, remote net.Addr, b []byte)
}

func (u *udpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := u.c.ReadFrom(b)
	if n > 0 && u.obs != nil {
		u.obs(u.c.LocalAddr(), addr, b[:n])
	}
	return n, addr, err
}

func (u *udpConn) WriteTo(b []byte, addr net.Addr) (int, error) { return u.c.WriteTo(b, addr) }
func (u *udpConn) Close() error                                 { return u.c.Close() }
func (u *udpConn) LocalAddr() net.Addr                          { return u.c.LocalAddr() }
func (u *udpConn) SetDeadline(t time.Time) error                { return u.c.SetDeadline(t) }
func (u *udpConn) SetReadDeadline(t time.Time) error            { return u.c.SetReadDeadline(t) }
func (u *udpConn) SetWriteDeadline(t time.Time) error           { return u.c.SetWriteDeadline(t) }

// SetReadBuffer e SetWriteBuffer deixam o quic-go pedir o buffer de 7 MiB (sysctl da ADR 0019).
func (u *udpConn) SetReadBuffer(n int) error  { return u.c.SetReadBuffer(n) }
func (u *udpConn) SetWriteBuffer(n int) error { return u.c.SetWriteBuffer(n) }

// initEntry é a análise dos Initials de uma 5-tupla.
type initEntry struct {
	key    string
	first  time.Time
	asm    *quicparse.Assembler
	bytes  int
	flow   event.Flow
	connID *connIDFuture
	// done fecha quando a análise termina (ClientHello completo, erro, teto ou janela de 2 s).
	done    chan struct{}
	stopped bool
	claimed bool
	closed  bool
	// orphan: já publicado como handshake_failed sem conexão.
	orphan bool
	// evict é o lugar da entrada na fila de despejo (não reclamada e com a análise encerrada); nil fora dela.
	evict *list.Element
}

func (e *initEntry) stop() {
	if !e.stopped {
		e.stopped = true
		close(e.done)
	}
}

// initTracker acompanha, por 5-tupla, os datagramas do cliente até o ClientHello do Initial completar.
type initTracker struct {
	srv *Server
	ctx context.Context

	mu        sync.Mutex
	m         map[string]*initEntry
	bytes     int
	lastSweep time.Time
	// evictNoCH e evictCH são as entradas não reclamadas com a análise encerrada, na ordem em que
	// encerraram (a da frente é a mais antiga): sem e com ClientHello completo. Com a tabela cheia, a 5-tupla
	// nova despeja a da frente, preferindo evictNoCH (spec 011, task 143), sem varrer a tabela.
	evictNoCH list.List
	evictCH   list.List
	// orphans recebe as entradas sem conexão aceita (handshake recusado antes do quic-go devolver a
	// conexão); o web publica handshake_failed para elas.
	orphans func(e *initEntry, info *quicparse.Info)
}

func newInitTracker(ctx context.Context, srv *Server) *initTracker {
	return &initTracker{srv: srv, ctx: ctx, m: map[string]*initEntry{}}
}

// udpFlow monta a 5-tupla UDP do ponto de vista do cliente.
func udpFlow(local, remote net.Addr) event.Flow {
	f := event.Flow{L4: "udp"}
	if ap, ok := udpAddrPort(remote); ok {
		f.SrcIP, f.SrcPort = ap.Addr().String(), int(ap.Port())
	}
	if ap, ok := udpAddrPort(local); ok {
		f.DstIP, f.DstPort = ap.Addr().String(), int(ap.Port())
	}
	return f
}

func udpAddrPort(a net.Addr) (netip.AddrPort, bool) {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := ua.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// observe recebe um datagrama do cliente (antes do quic-go). Nunca altera nem guarda b.
func (t *initTracker) observe(local, remote net.Addr, b []byte) {
	if len(b) == 0 {
		return
	}
	now := t.srv.now()
	key := remote.String()
	var orphans []*initEntry
	t.mu.Lock()
	if now.Sub(t.lastSweep) >= initSweepEvery {
		orphans = t.sweepLocked(now)
	}
	e := t.m[key]
	if e != nil && e.closed {
		t.dropLocked(e)
		e = nil
	}
	if e == nil {
		// só um cabeçalho longo abre uma 5-tupla nova (o quic-go cuida do resto)
		if b[0]&0x80 == 0 {
			t.mu.Unlock()
			t.publishOrphans(orphans)
			return
		}
		if len(t.m) >= initMaxEntries {
			// tabela cheia: despeja a não reclamada encerrada mais antiga; sem nenhuma, a 5-tupla fica sem
			// análise do Initial (o h3 continua)
			t.srv.metrics.Add(MetricH3InitTableFull, 1)
			if !t.evictLocked(&orphans) {
				t.mu.Unlock()
				t.publishOrphans(orphans)
				return
			}
		}
		e = &initEntry{key: key, first: now, asm: quicparse.NewAssembler(quicparse.Options{
			InlineMax: t.srv.cfg.EventInlineMax,
		}), flow: udpFlow(local, remote), done: make(chan struct{})}
		if h, err := quicparse.ParseLongHeader(b); err == nil {
			e.flow.QUICDCIDHex = hex.EncodeToString(h.DCID)
		}
		// RF-07: o conn_id é pedido no primeiro datagrama da 5-tupla
		e.connID = t.srv.requestConnID(t.ctx, e.flow, now)
		t.m[key] = e
	}
	if !e.stopped {
		switch {
		case now.Sub(e.first) > initWindow || t.bytes+len(b) > initMaxBytes:
			t.stopLocked(e)
		default:
			e.asm.Add(b)
			e.bytes += len(b)
			t.bytes += len(b)
			if e.asm.Done() {
				t.stopLocked(e)
			}
		}
	}
	t.mu.Unlock()
	t.publishOrphans(orphans)
}

// sweepLocked tira as entradas fechadas, as não reclamadas sem ClientHello depois de initWindow e as não
// reclamadas com ClientHello depois de initOrphanAfter; devolve as órfãs a publicar.
func (t *initTracker) sweepLocked(now time.Time) []*initEntry {
	t.lastSweep = now
	var orphans []*initEntry
	for _, e := range t.m {
		age := now.Sub(e.first)
		if e.closed {
			t.dropLocked(e)
			continue
		}
		if age > initWindow {
			t.stopLocked(e)
		}
		if !e.claimed && (age > initOrphanAfter || (age > initWindow && !e.asm.Complete())) {
			t.orphanLocked(e, &orphans)
			t.dropLocked(e)
		}
	}
	return orphans
}

// stopLocked encerra a análise da entrada e, se ninguém a reclamou, a põe na fila de despejo.
func (t *initTracker) stopLocked(e *initEntry) {
	e.stop()
	if e.claimed || e.evict != nil || t.m[e.key] != e {
		return
	}
	if e.asm.Complete() {
		e.evict = t.evictCH.PushBack(e)
	} else {
		e.evict = t.evictNoCH.PushBack(e)
	}
}

// unevictLocked tira a entrada da fila de despejo.
func (t *initTracker) unevictLocked(e *initEntry) {
	if e.evict == nil {
		return
	}
	if e.asm.Complete() {
		t.evictCH.Remove(e.evict)
	} else {
		t.evictNoCH.Remove(e.evict)
	}
	e.evict = nil
}

// evictLocked despeja a entrada não reclamada encerrada mais antiga, preferindo as sem ClientHello; a
// despejada com versão legível vira handshake_failed, como na limpeza. false se não há candidata.
func (t *initTracker) evictLocked(orphans *[]*initEntry) bool {
	el := t.evictNoCH.Front()
	if el == nil {
		el = t.evictCH.Front()
	}
	if el == nil {
		return false
	}
	e := el.Value.(*initEntry) //nolint:forcetypeassert // a fila só guarda *initEntry
	t.orphanLocked(e, orphans)
	t.dropLocked(e)
	return true
}

// orphanLocked marca a entrada sem conexão aceita como handshake_failed (uma vez, só com versão legível).
func (t *initTracker) orphanLocked(e *initEntry, orphans *[]*initEntry) {
	if !e.orphan && e.asm.Version() != 0 {
		e.orphan = true
		t.stopLocked(e)
		*orphans = append(*orphans, e)
	}
}

func (t *initTracker) dropLocked(e *initEntry) {
	t.unevictLocked(e)
	if t.m[e.key] == e {
		delete(t.m, e.key)
	}
	t.bytes -= e.bytes
	e.bytes = 0
}

func (t *initTracker) publishOrphans(list []*initEntry) {
	if t.orphans == nil {
		return
	}
	for _, e := range list {
		t.orphans(e, snapshotInfo(e.asm))
	}
}

// sweep força uma limpeza (usado pelo laço de manutenção, sem tráfego novo).
func (t *initTracker) sweep() {
	t.mu.Lock()
	orphans := t.sweepLocked(t.srv.now())
	t.mu.Unlock()
	t.publishOrphans(orphans)
}

// claim entrega a entrada da 5-tupla à conexão aceita, esperando a análise terminar por até wait.
func (t *initTracker) claim(remote net.Addr, wait time.Duration) (*initEntry, *quicparse.Info) {
	t.mu.Lock()
	e := t.m[remote.String()]
	if e != nil {
		e.claimed = true
		t.unevictLocked(e) // reclamada nunca é despejada
	}
	t.mu.Unlock()
	if e == nil {
		return nil, nil
	}
	timer := time.NewTimer(wait)
	select {
	case <-e.done:
	case <-timer.C:
	}
	timer.Stop()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked(e)
	return e, snapshotInfo(e.asm)
}

// release marca a 5-tupla como encerrada: o próximo Initial dela abre uma entrada nova (conexão nova no
// store, spec 004).
func (t *initTracker) release(e *initEntry) {
	if e == nil {
		return
	}
	t.mu.Lock()
	e.closed = true
	t.mu.Unlock()
}

// snapshotInfo copia a análise do Initial (chamar com a análise encerrada ou sob t.mu).
func snapshotInfo(a *quicparse.Assembler) *quicparse.Info {
	src := a.Info()
	in := *src
	in.InitialFrames = slices.Clone(src.InitialFrames)
	in.TransportParams = slices.Clone(src.TransportParams)
	in.H3Settings = [][2]uint64{}
	in.Requests = []quicparse.HTTP3Request{}
	if src.ClientHello != nil {
		ch := *src.ClientHello
		in.ClientHello = &ch
	}
	return &in
}
