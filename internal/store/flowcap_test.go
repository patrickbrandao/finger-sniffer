package store

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// Teto da tabela de fluxos, ociosidade do meio-aberto e do estabelecido, registro de relógios (ADR 0034 itens 1,
// 2 e 5; tasks 128, 151 e 141).

// srcN devolve a origem n (5-tuplas distintas: IP e porta variam).
func srcN(n int) netip.AddrPort {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], 0xc6120000+uint32(n>>14)) //nolint:gosec // teste
	return netip.AddrPortFrom(netip.AddrFrom4(a), uint16(1024+n&0x3fff))
}

func feed(ft *flowTable, cli, srv netip.AddrPort, proto byte, ms int64, fromCli bool, flags byte) result {
	src, dst := cli, srv
	if !fromCli {
		src, dst = srv, cli
	}
	return ft.handle(parseFrame(frame(src, dst, proto, flags, 0)), base+ms*1e6)
}

// TestFlowTableCapHalfOpen: 100.000 SYNs de 5-tuplas distintas, com SYN-ACK e sem o ACK do cliente, nunca passam
// do teto; o excedente despeja a mais antiga.
func TestFlowTableCapHalfOpen(t *testing.T) {
	ft := newLimitTable()
	evicted := 0
	var first string
	for i := range 100_000 {
		r := feed(ft, srcN(i), mirror, protoTCP, int64(i)/100, true, tcpSYN)
		if i == 0 {
			first = r.conn.id
		}
		if r.evicted != nil {
			if evicted == 0 && r.evicted.id != first {
				t.Fatal("must evict the oldest")
			}
			evicted++
		}
		if r.dropped {
			t.Fatal("half-open entries must be evicted, not refused")
		}
		feed(ft, srcN(i), mirror, protoTCP, int64(i)/100, false, tcpSYN|tcpACK)
		if ft.open() > maxFlows {
			t.Fatalf("open %d", ft.open())
		}
	}
	if ft.open() != maxFlows || evicted != 100_000-maxFlows || ft.half.Len() != maxFlows {
		t.Fatalf("open %d evicted %d half %d", ft.open(), evicted, ft.half.Len())
	}
}

// TestFlowTableCapUDP: o mesmo com UDP não-QUIC sem resposta.
func TestFlowTableCapUDP(t *testing.T) {
	ft := newLimitTable()
	for i := range 100_000 {
		feed(ft, srcN(i), netip.MustParseAddrPort("170.247.40.86:5353"), protoUDP, int64(i)/100, true, 0)
	}
	if ft.open() != maxFlows {
		t.Fatalf("open %d", ft.open())
	}
}

// TestFlowTableFullRefuses: tabela cheia de estabelecidas recusa a 5-tupla nova; com uma meio-aberta, a nova
// despeja essa e entra (a conexão legítima não é cega pelo flood).
func TestFlowTableFullRefuses(t *testing.T) {
	ft := newLimitTable()
	ft.maxFlows = 3
	handshake := func(i int) {
		feed(ft, srcN(i), mirror, protoTCP, 0, true, tcpSYN)
		feed(ft, srcN(i), mirror, protoTCP, 1, false, tcpSYN|tcpACK)
		feed(ft, srcN(i), mirror, protoTCP, 2, true, tcpACK)
	}
	for i := range 3 {
		handshake(i)
	}
	if r := feed(ft, srcN(9), mirror, protoTCP, 10, true, tcpSYN); !r.dropped || r.conn != nil || ft.open() != 3 {
		t.Fatalf("must refuse: %+v", r)
	}
	// Pacotes de uma estabelecida continuam normais com a tabela cheia.
	if r := feed(ft, srcN(0), mirror, protoTCP, 11, true, tcpACK); r.dropped || r.conn == nil {
		t.Fatal("established flow must keep working")
	}
	// Uma fecha (RST) e dá lugar a uma meio-aberta; a seguinte despeja a meio-aberta.
	feed(ft, srcN(1), mirror, protoTCP, 12, true, tcpRST)
	ft.due(base + 13e6)
	half := feed(ft, srcN(10), mirror, protoTCP, 14, true, tcpSYN)
	if half.conn == nil || half.dropped {
		t.Fatal("free slot must be used")
	}
	r := feed(ft, srcN(11), mirror, protoTCP, 15, true, tcpSYN)
	if r.evicted == nil || r.evicted.id != half.conn.id || r.conn == nil {
		t.Fatalf("must evict the half-open: %+v", r)
	}
	if n := ft.liveLimited(); n != 3 {
		t.Fatalf("live %d", n)
	}
}

// TestDueIdleByState: meio-aberta sai em 10 s; estabelecida ociosa há 300 s continua (ociosidade de 630 s,
// task 151) e sai depois dela.
func TestDueIdleByState(t *testing.T) {
	ft := newFlowTable(IngestConfig{TCPIdle: 630 * time.Second, QUICIdle: 150 * time.Second, UDPIdle: 30 * time.Second, CloseGrace: 100 * time.Millisecond, MaxOpen: 200, MaxNewPerS: 50})
	feed(ft, srcN(1), mirror, protoTCP, 0, true, tcpSYN)
	feed(ft, srcN(1), mirror, protoTCP, 1, false, tcpSYN|tcpACK)
	feed(ft, srcN(2), mirror, protoTCP, 0, true, tcpSYN)
	feed(ft, srcN(2), mirror, protoTCP, 1, false, tcpSYN|tcpACK)
	feed(ft, srcN(2), mirror, protoTCP, 2, true, tcpACK)
	if out := ft.due(base + 9_000e6); len(out) != 0 {
		t.Fatal("nothing due at 9 s")
	}
	if out := ft.due(base + 10_100e6); len(out) != 1 || out[0].client != srcN(1) {
		t.Fatalf("half-open must leave after 10 s: %d", len(out))
	}
	if out := ft.due(base + 300_000e6); len(out) != 0 {
		t.Fatal("established idle for 300 s must stay")
	}
	if out := ft.due(base + 631_000e6); len(out) != 1 {
		t.Fatal("established must leave after 630 s")
	}
}

// TestIngestEvictionDeletesRow: a entrada despejada sai do banco sem virar avulso; a 5-tupla recusada não grava
// nada.
func TestIngestEvictionDeletesRow(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	in.flows.maxFlows = 2
	run(t, in, 0, batch(srcN(1), mirror, protoTCP, []pkt{{0, true, tcpSYN, 0}}))
	run(t, in, 0, batch(srcN(2), mirror, protoTCP, fullTCP[:3]))
	run(t, in, 0, batch(srcN(3), mirror, protoTCP, fullTCP[:3]))
	if count(t, db, "SELECT count(*) FROM connections") != 2 || count(t, db, "SELECT count(*) FROM stray_packets") != 0 ||
		count(t, db, "SELECT count(*) FROM connections WHERE src_port = ?", int(srcN(1).Port())) != 0 {
		t.Fatal("evicted entry must leave no row and no stray")
	}
	run(t, in, 0, batch(srcN(4), mirror, protoTCP, fullTCP[:3]))
	if count(t, db, "SELECT count(*) FROM connections") != 2 || count(t, db, "SELECT count(*) FROM stray_packets") != 0 ||
		pktCount(t, in, db) != 6 {
		t.Fatal("refused 5-tuple must store nothing")
	}
}

// TestClockRegistryCap: 3×clockMax relógios distintos não passam do teto; o teto é atingido e sai o grupo usado
// há mais tempo (LRU); os recentes continuam casando. 3×clockMax já força 2×clockMax despejos; mais iterações só
// repetiam o mesmo caminho e levavam ~170 s com -race no CI (task 294).
func TestClockRegistryCap(t *testing.T) {
	var r clockRegistry
	mk := func(i int, ts int64, v uint32) *conn {
		c := &conn{id: fmt.Sprint(i), ana: newAnalysis()}
		c.ana.tsCount = 2
		c.ana.tsFirst = tsSample{t: ts - 1e9, v: v - 1000}
		c.ana.tsLast = tsSample{t: ts, v: v}
		return c
	}
	const n = 3 * clockMax
	for i := range n {
		// relógios de 1000 Hz com deslocamentos sem relação entre si (passo grande, fora da tolerância)
		r.assign(mk(i, base+int64(i)*1e6, uint32(i)*7919), true) //nolint:gosec // teste
		if len(r.entries) > clockMax {
			t.Fatalf("entries %d", len(r.entries))
		}
	}
	// a janela cobre ~12 s, longe de clockKeep: o tamanho final vem do teto, não da poda por idade
	if len(r.entries) != clockMax {
		t.Fatalf("entries %d, want %d", len(r.entries), clockMax)
	}
	last := n - 1
	now := base + int64(last)*1e6 + 5e9
	at := func(i int) *string {
		// o relógio i, 5 s depois do último registro, sem registrar (não mexe no LRU)
		return r.assign(mk(-1, now, uint32(i)*7919+uint32(int64(last-i)+5000)), false) //nolint:gosec // teste
	}
	for _, i := range []int{0, n - clockMax - 1} {
		if g := at(i); g != nil {
			t.Fatalf("evicted clock %d still matches: %v", i, *g)
		}
	}
	for _, i := range []int{n - clockMax, last} {
		if g := at(i); g == nil || *g != "clk-"+fmt.Sprint(i) {
			t.Fatalf("recent clock %d must still match: %v", i, g)
		}
	}
	g := r.assign(mk(-1, now, uint32(last)*7919+5000), true) //nolint:gosec // teste
	if g == nil || *g != "clk-"+fmt.Sprint(last) {
		t.Fatalf("recent clock must still match: %v", g)
	}
}

// BenchmarkHandleNewConn: o custo de uma conexão nova não cresce com a tabela (liveLimited O(1), teto).
func BenchmarkHandleNewConn(b *testing.B) {
	for _, n := range []int{0, 1000, maxFlows} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			ft := newLimitTable()
			ft.maxNewPerS = 1 << 30
			for i := range n {
				feed(ft, srcN(i), mirror, protoTCP, 0, true, tcpSYN)
			}
			frames := make([]frameInfo, b.N)
			for i := range frames {
				frames[i] = parseFrame(frame(srcN(n+i), mirror, protoTCP, tcpSYN, 0))
			}
			b.ResetTimer()
			for i := range b.N {
				ft.handle(frames[i], base)
			}
		})
	}
}

// feedUDP manda um datagrama UDP com os dados dados.
func feedUDP(ft *flowTable, cli, srv netip.AddrPort, ms int64, fromCli bool, data []byte) result {
	src, dst := cli, srv
	if !fromCli {
		src, dst = srv, cli
	}
	return ft.handle(parseFrame(udpFrame(src, dst, data)), base+ms*1e6)
}

// TestFlowTableFakeQUICInitialEvictable (task 321, ADR 0069 item 1): a tabela cheia de falsos Initials QUIC sem
// resposta não recusa o SYN legítimo; eles não contam nas simultâneas nem gastam ficha das novas/s.
func TestFlowTableFakeQUICInitialEvictable(t *testing.T) {
	ft := newLimitTable()
	fake := []byte{0xc0, 0, 0, 0, 1, 0, 0} // 7 bytes: cabeçalho longo, versão 1, DCID vazio
	srv := netip.MustParseAddrPort("170.247.40.86:9999")
	for i := range maxFlows {
		if r := feedUDP(ft, srcN(i), srv, int64(i)*30_000/maxFlows, true, fake); r.dropped {
			t.Fatalf("fake initial %d refused", i)
		}
	}
	if ft.open() != maxFlows || ft.liveLimited() != 0 || ft.half.Len() != maxFlows {
		t.Fatalf("open %d live %d half %d", ft.open(), ft.liveLimited(), ft.half.Len())
	}
	if ft.newTokens < float64(ft.maxNewPerS) {
		t.Fatalf("tokens spent: %v", ft.newTokens)
	}
	r := feed(ft, srcN(maxFlows+1), mirror, protoTCP, 30_000, true, tcpSYN)
	if r.dropped || r.conn == nil || r.evicted == nil || r.conn.degraded {
		t.Fatalf("legit SYN: %+v", r)
	}
}

// TestFlowTableFakeQUICDoesNotDegrade (task 321): com os padrões de produção, 1 100 falsos Initials em 30 s não
// degradam o SYN legítimo.
func TestFlowTableFakeQUICDoesNotDegrade(t *testing.T) {
	ft := newFlowTable(IngestConfig{TCPIdle: 150 * time.Second, UDPIdle: 30 * time.Second, CloseGrace: 100 * time.Millisecond, MaxOpen: DefaultMaxConns, MaxNewPerS: DefaultMaxNewConnsPerS})
	fake := quicInitial([]byte{1, 2, 3, 4})
	for i := range 1100 {
		feedUDP(ft, srcN(i), mirror, int64(i)*30_000/1100, true, fake)
	}
	if ft.liveLimited() != 0 {
		t.Fatalf("live %d", ft.liveLimited())
	}
	if r := feed(ft, srcN(5000), mirror, protoTCP, 30_000, true, tcpSYN); r.conn == nil || r.conn.degraded {
		t.Fatalf("legit SYN degraded: %+v", r)
	}
}

// TestFlowTableQUICEstablishedByReply (task 321): o Initial só vira QUIC (limited, fora da fila half) com a
// resposta do espelho com cabeçalho longo.
func TestFlowTableQUICEstablishedByReply(t *testing.T) {
	ft := newLimitTable()
	r := feedUDP(ft, client, mirror, 0, true, quicInitial([]byte{1, 2, 3, 4}))
	if r.conn.limited || r.conn.halfEl == nil || ft.liveLimited() != 0 {
		t.Fatal("initial without reply must be evictable")
	}
	feedUDP(ft, client, mirror, 5, false, quicLong(0, []byte{9}, []byte{5, 5, 5, 5}, 1200))
	if !r.conn.limited || r.conn.halfEl != nil || r.conn.ansEl != nil || ft.liveLimited() != 1 {
		t.Fatalf("reply must establish: limited %v live %d", r.conn.limited, ft.liveLimited())
	}
}

// TestFlowTableAnsweredUDPCap (task 321, ADR 0069 item 2): consultas DNS respondidas ficam no teto de 2048 (a
// nova despeja a mais antiga do tipo) e, com a tabela cheia, o SYN legítimo despeja a respondida mais antiga.
func TestFlowTableAnsweredUDPCap(t *testing.T) {
	ft := newLimitTable()
	dns := netip.MustParseAddrPort("170.247.40.86:53")
	q := make([]byte, 40)
	var first string
	evicted := 0
	for i := range maxFlows {
		r := feedUDP(ft, srcN(i), dns, int64(i)*30_000/maxFlows, true, q)
		if i == 0 {
			first = r.conn.id
		}
		a := feedUDP(ft, srcN(i), dns, int64(i)*30_000/maxFlows, false, q)
		if a.evicted != nil {
			if evicted == 0 && a.evicted.id != first {
				t.Fatal("must evict the oldest answered")
			}
			evicted++
		}
	}
	if ft.open() != maxAnsweredUDP || ft.answered.Len() != maxAnsweredUDP || evicted != maxFlows-maxAnsweredUDP {
		t.Fatalf("open %d answered %d evicted %d", ft.open(), ft.answered.Len(), evicted)
	}
	// Tabela cheia só de respondidas: o SYN despeja a mais antiga em vez de ser recusado.
	ft.maxFlows = maxAnsweredUDP
	r := feed(ft, srcN(maxFlows+1), mirror, protoTCP, 30_000, true, tcpSYN)
	if r.dropped || r.conn == nil || r.evicted == nil || r.evicted.l4 != protoUDP {
		t.Fatalf("legit SYN: %+v", r)
	}
}
