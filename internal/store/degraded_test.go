package store

import (
	"net/netip"
	"testing"
	"time"
)

func newLimitTable() *flowTable {
	return newFlowTable(IngestConfig{TCPIdle: 150 * time.Second, UDPIdle: 30 * time.Second, CloseGrace: 100 * time.Millisecond, MaxOpen: 200, MaxNewPerS: 50})
}

// jitter devolve um desvio determinístico entre -5 e +5 ms.
func jitter(i int) int64 {
	return int64((i*7919)%11-5) * int64(time.Millisecond)
}

// arrivals conta quantas de n conexões novas a period (com jitter de ±5 ms) saem degradadas.
func arrivals(ft *flowTable, n int, period time.Duration, limited bool) int {
	deg := 0
	for i := range n {
		if ft.overloaded(base+int64(i)*period.Nanoseconds()+jitter(i), limited) {
			deg++
		}
	}
	return deg
}

// TestOverloadedProfileWithJitter: o perfil do RNF-01 (50 novas/s em intervalos de 20 ms) com jitter de ±5 ms
// não degrada em 10 min (task 103); a janela fixa de 1 s degradava.
func TestOverloadedProfileWithJitter(t *testing.T) {
	if deg := arrivals(newLimitTable(), 30000, 20*time.Millisecond, true); deg != 0 {
		t.Fatalf("%d of 30000 degraded at 50/s", deg)
	}
}

// TestOverloadedAboveRate: a 60/s sustentados o balde esvazia em ~5 s e o excedente (~10/s) sai degradado.
func TestOverloadedAboveRate(t *testing.T) {
	deg := arrivals(newLimitTable(), 60*30, time.Second/60, true)
	// 30 s: 5 s até esvaziar as 50 fichas, depois ~10 de cada 60 por segundo (~250)
	if deg < 230 || deg > 260 {
		t.Fatalf("%d of 1800 degraded at 60/s, want ~250", deg)
	}
}

// TestOverloadedBurst: uma rajada de até 50 conexões passa; a 51ª no mesmo instante degrada.
func TestOverloadedBurst(t *testing.T) {
	ft := newLimitTable()
	for i := range 50 {
		if ft.overloaded(base, true) {
			t.Fatalf("connection %d of the burst degraded", i+1)
		}
	}
	if !ft.overloaded(base, true) {
		t.Fatal("51st connection in the same instant must degrade")
	}
	// fora de ordem não recarrega
	if !ft.overloaded(base-int64(time.Second), true) {
		t.Fatal("out-of-order packet must not refill the bucket")
	}
	// um segundo depois o balde voltou a encher
	if ft.overloaded(base+int64(time.Second), true) {
		t.Fatal("bucket must refill after 1 s")
	}
}

// TestOverloadedIgnoresPlainUDP: fluxos UDP que não são QUIC (DNS) não gastam fichas nem vagas; a carga TCP
// no perfil continua sem degradar com eles por cima.
func TestOverloadedIgnoresPlainUDP(t *testing.T) {
	ft := newLimitTable()
	deg := 0
	for i := range 3000 {
		ts := base + int64(i)*int64(20*time.Millisecond) + jitter(i)
		if i%10 == 0 {
			ft.overloaded(ts+int64(time.Millisecond), false) // 5 consultas DNS/s
		}
		if ft.overloaded(ts, true) {
			deg++
		}
	}
	if deg != 0 {
		t.Fatalf("%d degraded with DNS on top", deg)
	}
}

// openTCP abre (e, se closed, fecha com FIN dos dois lados) uma conexão TCP pela tabela.
func openTCP(ft *flowTable, cli netip.AddrPort, ts int64, closed bool) *conn {
	steps := []pkt{{0, true, tcpSYN, 0}, {1, false, tcpSYN | tcpACK, 0}, {2, true, tcpACK, 0}}
	if closed {
		steps = append(steps, pkt{3, true, tcpFIN | tcpACK, 0}, pkt{4, false, tcpFIN | tcpACK, 0})
	}
	var c *conn
	for _, p := range steps {
		src, dst := cli, mirror
		if !p.fromCli {
			src, dst = mirror, cli
		}
		r := ft.handle(parseFrame(frame(src, dst, protoTCP, p.flags, 0)), ts+int64(p.ms)*int64(time.Millisecond))
		if c == nil {
			c = r.conn
		}
	}
	return c
}

// TestOverloadedCountsLiveOnly: conexões já fechadas à espera da folga e fluxos DNS na tabela não ocupam vaga;
// 200 conexões vivas ocupam e a próxima degrada.
func TestOverloadedCountsLiveOnly(t *testing.T) {
	ft := newLimitTable()
	ts := base
	step := int64(30 * time.Millisecond) // abaixo de 50/s: só o limite de simultâneas importa
	port := uint16(10000)
	next := func() netip.AddrPort { port++; return netip.AddrPortFrom(client.Addr(), port) }
	for range 199 {
		openTCP(ft, next(), ts, false)
		ts += step
	}
	for range 20 {
		openTCP(ft, next(), ts, true) // fechadas, ainda na tabela pela folga
		ts += step
	}
	for range 30 {
		dns := next()
		ft.handle(parseFrame(frame(dns, netip.AddrPortFrom(mirror.Addr(), 53), protoUDP, 0, 40)), ts)
		ts += step
	}
	if len(ft.conns) != 249 {
		t.Fatalf("table has %d flows", len(ft.conns))
	}
	if c := openTCP(ft, next(), ts, false); c.degraded {
		t.Fatal("200th live connection degraded")
	}
	ts += step
	if c := openTCP(ft, next(), ts, false); !c.degraded {
		t.Fatal("201st live connection must degrade")
	}
}
