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

func TestRRLDisabledAndFull(t *testing.T) {
	var nilRRL *RRL
	if !nilRRL.Allow(netip.MustParseAddr("192.0.2.1")) || !NewRRL(0, nil).Allow(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("RRL desligado deve permitir")
	}
	r := NewRRL(1, nil)
	for i := range rrlMaxEntries {
		r.buckets[netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})] = &bucket{last: time.Now()}
	}
	if !r.Allow(netip.MustParseAddr("192.0.2.9")) {
		t.Fatal("tabela cheia não limita")
	}
}

// TestServerRRL: 100 consultas UDP em rajada do mesmo IP → exatamente 20 completas e o resto TC=1 sem dados;
// em TCP, acima do limite a conexão é descartada.
//
// O relógio do RRL fica parado (sem reposição de fichas), então a contagem não depende da velocidade da máquina.
// O Observer roda depois de a resposta sair, por isso a contagem dele é esperada com prazo, e nenhum t.Fatal
// acontece com trava que o Observer precise: antes um Fatalf com a trava presa travava o Close da limpeza
// (serveUDP esperando a trava, Close esperando serveUDP) até o timeout de 10 min do go test.
func TestServerRRL(t *testing.T) {
	z, _ := newTestZone()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	var limitedUDP, limitedTCP atomic.Int64
	_, udp, tcp := startServer(t, z, func(s *Server) {
		s.RRL = NewRRL(20, clk.now)
		s.Observer = func(q *Query) {
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

	// TCP do mesmo IP já sem fichas: sem resposta.
	ct := &mdns.Client{Net: "tcp", Timeout: 500 * time.Millisecond}
	if _, _, err := ct.ExchangeContext(context.Background(), query("abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeA), tcp); err == nil {
		t.Fatal("TCP acima do limite devia ser descartado")
	}
	if got := waitCount(&limitedTCP, 1, 2*time.Second); got != 1 {
		t.Fatalf("observer TCP marcou %d", got)
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
