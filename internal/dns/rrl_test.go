package dns

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// TestRRLRate: 100 consultas/s do mesmo IP por 10 s → no máximo ~20/s respondidas por completo.
func TestRRLRate(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r := NewRRL(20, clk.now)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	allowedA, allowedB := 0, 0
	for i := range 1000 {
		if r.Allow(a) {
			allowedA++
		}
		// Outro IP a 5/s nunca é limitado.
		if i%20 == 0 && r.Allow(b) {
			allowedB++
		}
		clk.advance(10 * time.Millisecond)
	}
	// 10 s a 20/s mais a rajada inicial de 20.
	if allowedA < 195 || allowedA > 221 {
		t.Fatalf("permitidas %d em 10 s", allowedA)
	}
	if allowedB != 50 {
		t.Fatalf("IP B: %d", allowedB)
	}
	// Balde parado há mais de rrlIdle some da tabela.
	clk.advance(rrlIdle + 2*time.Second)
	r.Allow(netip.MustParseAddr("192.0.2.3"))
	if len(r.buckets) != 1 {
		t.Fatalf("baldes %d", len(r.buckets))
	}
}

func TestRRLDisabled(t *testing.T) {
	var nilRRL *RRL
	if !nilRRL.Allow(netip.MustParseAddr("192.0.2.1")) || !NewRRL(0, nil).Allow(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("RRL desligado deve permitir")
	}
}

// TestRRLFullTable: com a tabela cheia, origens novas dividem o balde de transbordo (sem fail-open) e a tabela
// não passa de rrlMaxEntries+1 entradas; origens com balde próprio seguem com o delas.
func TestRRLFullTable(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r := NewRRL(20, clk.now)
	r.lastPrune = clk.now() // sem limpeza durante o teste
	for i := range rrlMaxEntries {
		r.buckets[netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})] = &bucket{tokens: 20, last: clk.now()}
	}
	allowed := 0
	for i := range 100 {
		if r.Allow(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})) {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("origens novas com a tabela cheia: %d permitidas, quer 20 (transbordo)", allowed)
	}
	if len(r.buckets) != rrlMaxEntries+1 {
		t.Fatalf("baldes %d, quer %d", len(r.buckets), rrlMaxEntries+1)
	}
	if !r.Allow(netip.AddrFrom4([4]byte{10, 0, 0, 1})) {
		t.Fatal("origem com balde próprio não deve usar o transbordo")
	}
	// O transbordo repõe fichas na mesma taxa.
	clk.advance(time.Second)
	allowed = 0
	for i := range 100 {
		if r.Allow(netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)})) {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("transbordo depois de 1 s: %d", allowed)
	}
}

// TestRRLIPv6Prefix: endereços distintos do mesmo /64 dividem um balde; /64 distintos e IPv4 ficam separados, e o
// IPv4 mapeado cai no balde do IPv4.
func TestRRLIPv6Prefix(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r := NewRRL(20, clk.now)
	allowed := 0
	for i := range 100 {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)})
		if r.Allow(a) {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("mesmo /64: %d permitidas", allowed)
	}
	if !r.Allow(netip.MustParseAddr("2001:db8:0:2::1")) {
		t.Fatal("outro /64 deve ter balde próprio")
	}
	if !r.Allow(netip.MustParseAddr("fe80::1%eth0")) || !r.Allow(netip.MustParseAddr("fe80::2%eth1")) {
		t.Fatal("link-local com fichas deve passar")
	}
	if _, ok := r.buckets[netip.MustParseAddr("fe80::")]; !ok {
		t.Fatal("zona deve ser ignorada na chave")
	}
	for range 20 {
		r.Allow(netip.MustParseAddr("192.0.2.7"))
	}
	if r.Allow(netip.MustParseAddr("::ffff:192.0.2.7")) {
		t.Fatal("IPv4 mapeado deve usar o balde do IPv4")
	}
}

// TestServerRRL: 100 consultas UDP em rajada do mesmo IP → exatamente 20 completas e o resto TC=1 sem dados;
// o TCP fica fora do RRL: com o balde UDP esgotado, o mesmo IP recebe a resposta completa em TCP (ADR 0035).
//
// O relógio do RRL fica parado (sem reposição de fichas), então a contagem não depende da velocidade da máquina.
// O Observer roda depois de a resposta sair, por isso a contagem dele é esperada com prazo, e nenhum t.Fatal
// acontece com trava que o Observer precise: antes um Fatalf com a trava presa travava o Close da limpeza
// (serveUDP esperando a trava, Close esperando serveUDP) até o timeout de 10 min do go test.
func TestServerRRL(t *testing.T) {
	z, _ := newTestZone()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	var limitedUDP, limitedTCP, seenTCP atomic.Int64
	_, udp, tcp := startServer(t, z, func(s *Server) {
		s.RRL = NewRRL(20, clk.now)
		s.Observer = func(q *Query) {
			if q.Proto == "tcp" {
				seenTCP.Add(1)
			}
			if !q.RateLimited {
				return
			}
			if q.Proto == "tcp" {
				limitedTCP.Add(1)
			} else {
				limitedUDP.Add(1)
			}
		}
	})
	c := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
	full, tc := 0, 0
	for range 100 {
		r, _, err := c.Exchange(query("abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeA), udp)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case r.Truncated && len(r.Answer) == 0 && len(r.Ns) == 0:
			tc++
		case !r.Truncated && len(r.Answer) == 1:
			full++
		default:
			t.Fatalf("resposta inesperada %v", r)
		}
	}
	if full != 20 || tc != 80 {
		t.Fatalf("completas %d, TC %d", full, tc)
	}
	if got := waitCount(&limitedUDP, int64(tc), 2*time.Second); got != int64(tc) {
		t.Fatalf("observer marcou %d, TC %d", got, tc)
	}

	// TCP do mesmo IP com o balde UDP esgotado: resposta completa, sem rate_limited.
	ct := &mdns.Client{Net: "tcp", Timeout: 2 * time.Second}
	for range 3 {
		r, _, err := ct.ExchangeContext(context.Background(), query("abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeA), tcp)
		if err != nil {
			t.Fatalf("TCP com o balde UDP esgotado: %v", err)
		}
		if r.Truncated || len(r.Answer) != 1 {
			t.Fatalf("resposta TCP incompleta %v", r)
		}
	}
	if got := waitCount(&seenTCP, 3, 2*time.Second); got != 3 {
		t.Fatalf("observer viu %d consultas TCP", got)
	}
	if n := limitedTCP.Load(); n != 0 {
		t.Fatalf("TCP marcado rate_limited %d vezes", n)
	}
	// O UDP continua limitado depois das consultas TCP.
	r, _, err := c.Exchange(query("abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeA), udp)
	if err != nil || !r.Truncated || len(r.Answer) != 0 {
		t.Fatalf("UDP depois do TCP: %v %v", r, err)
	}
}

// waitCount espera, até o prazo, o contador chegar a want e devolve o último valor lido.
func waitCount(n *atomic.Int64, want int64, timeout time.Duration) int64 {
	deadline := time.Now().Add(timeout)
	for {
		got := n.Load()
		if got >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}
