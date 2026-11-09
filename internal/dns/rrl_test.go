package dns

import (
	"context"
	"net/netip"
	"sync"
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

// TestServerRRL: 100 consultas UDP em rajada do mesmo IP → ~20 completas e o resto TC=1 sem dados;
// em TCP, acima do limite a conexão é descartada.
func TestServerRRL(t *testing.T) {
	z, _ := newTestZone()
	var mu sync.Mutex
	limited := 0
	_, udp, tcp := startServer(t, z, func(s *Server) {
		s.RRL = NewRRL(20, nil)
		s.Observer = func(q *Query) {
			if q.RateLimited {
				mu.Lock()
				limited++
				mu.Unlock()
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
	// A rajada leva ~20 respostas completas; a reposição durante o laço acrescenta poucas.
	if full < 20 || full > 30 || full+tc != 100 {
		t.Fatalf("completas %d, TC %d", full, tc)
	}
	mu.Lock()
	if limited != tc {
		t.Fatalf("observer marcou %d, TC %d", limited, tc)
	}
	mu.Unlock()

	// TCP do mesmo IP já sem fichas: sem resposta.
	ct := &mdns.Client{Net: "tcp", Timeout: 500 * time.Millisecond}
	if _, _, err := ct.ExchangeContext(context.Background(), query("abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeA), tcp); err == nil {
		t.Fatal("TCP acima do limite devia ser descartado")
	}
}
