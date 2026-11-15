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
		count(t, db, "SELECT count(*) FROM packets") != 6 {
		t.Fatal("refused 5-tuple must store nothing")
	}
}

// TestClockRegistryCap: 100.000 relógios distintos não passam do teto; um relógio recente continua casando.
func TestClockRegistryCap(t *testing.T) {
	var r clockRegistry
	mk := func(i int, ts int64, v uint32) *conn {
		c := &conn{id: fmt.Sprint(i), ana: newAnalysis()}
		c.ana.tsCount = 2
		c.ana.tsFirst = tsSample{t: ts - 1e9, v: v - 1000}
		c.ana.tsLast = tsSample{t: ts, v: v}
		return c
	}
	for i := range 100_000 {
		// relógios de 1000 Hz com deslocamentos sem relação entre si (passo grande, fora da tolerância)
		r.assign(mk(i, base+int64(i)*1e6, uint32(i)*7919), true) //nolint:gosec // teste
		if len(r.entries) > clockMax {
			t.Fatalf("entries %d", len(r.entries))
		}
	}
	last := 99_999
	g := r.assign(mk(-1, base+int64(last)*1e6+5e9, uint32(last)*7919+5000), true) //nolint:gosec // teste
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
