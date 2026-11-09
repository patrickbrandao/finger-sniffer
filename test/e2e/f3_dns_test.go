//go:build e2e

package e2e

// Caso 10 da matriz da spec 017 no caminho direto: consultas ao autoritativo de dns-monitor direto na vps602 e
// por resolvedores públicos (8.8.8.8, 1.1.1.1), com e sem ECS; A/AAAA/HTTPS, rótulos de controle, caixa
// original (0x20), REFUSED fora da zona, TCP. O registro mostra quem consultou (o resolvedor).

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// query manda uma consulta e devolve a resposta (falha no teste em erro de rede).
func query(t *testing.T, server, proto, name string, qtype uint16, ecs *net.IPNet, rd bool) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = rd
	m.Question[0].Name = name // SetQuestion não mexe na caixa, mas fica explícito: 0x20 preservado
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetUDPSize(1232)
	if ecs != nil {
		ones, _ := ecs.Mask.Size()
		o.Option = append(o.Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: uint8(ones), Address: ecs.IP.To4()})
	}
	m.Extra = append(m.Extra, o)
	c := &dns.Client{Net: proto, Timeout: 5 * time.Second}
	var r *dns.Msg
	var err error
	for range 3 { // UDP pela internet: até 3 tentativas
		if r, _, err = c.Exchange(m, server); err == nil {
			return r
		}
	}
	t.Fatalf("%s %s %s @%s: %v", proto, name, dns.TypeToString[qtype], server, err)
	return nil
}

// mixedCase troca a caixa de letras alternadas (teste do 0x20).
func mixedCase(s string) string {
	b := []byte(s)
	for i := range b {
		if i%2 == 0 && b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

// TestCase10DNSDirect: consultas direto ao vps602 (o resolvedor registrado é esta máquina).
func TestCase10DNSDirect(t *testing.T) {
	t.Parallel()
	mac := macIPv4(t)
	srv := vps4 + ":53"
	id := newID(t)
	base := id + "." + zone + "."
	mixed := mixedCase(id) + "." + zone + "."
	_, ecsNet, _ := net.ParseCIDR("200.1.2.0/24")

	type exp struct {
		name    string
		qtype   uint16
		proto   string
		ecs     *net.IPNet
		rcode   int
		answers int // -1 = pelo menos um
		check   func(*dns.Msg) error
	}
	cases := []exp{
		{name: mixed, qtype: dns.TypeA, proto: "udp", rcode: dns.RcodeSuccess, answers: 1, check: func(m *dns.Msg) error {
			a, ok := m.Answer[0].(*dns.A)
			if !ok || a.A.String() != vps4 || a.Hdr.Ttl != 5 || m.Answer[0].Header().Name != mixed || m.Authoritative == false || m.RecursionAvailable {
				return fmt.Errorf("A: %v (aa=%v ra=%v)", m.Answer, m.Authoritative, m.RecursionAvailable)
			}
			return nil
		}},
		{name: base, qtype: dns.TypeAAAA, proto: "udp", rcode: dns.RcodeSuccess, answers: 1},
		{name: base, qtype: dns.TypeHTTPS, proto: "udp", rcode: dns.RcodeSuccess, answers: 1, check: func(m *dns.Msg) error {
			h, ok := m.Answer[0].(*dns.HTTPS)
			if !ok || !strings.Contains(h.String(), `alpn="h3,h2"`) || !strings.Contains(h.String(), `ipv4hint="`+vps4) {
				return fmt.Errorf("HTTPS: %v", m.Answer)
			}
			return nil
		}},
		{name: id + ".noh3." + zone + ".", qtype: dns.TypeHTTPS, proto: "udp", rcode: dns.RcodeSuccess, answers: 0},
		{name: id + ".v4." + zone + ".", qtype: dns.TypeAAAA, proto: "udp", rcode: dns.RcodeSuccess, answers: 0},
		{name: id + ".v4." + zone + ".", qtype: dns.TypeA, proto: "udp", rcode: dns.RcodeSuccess, answers: 1},
		{name: id + ".v6." + zone + ".", qtype: dns.TypeA, proto: "udp", rcode: dns.RcodeSuccess, answers: 0},
		{name: id + ".nodata." + zone + ".", qtype: dns.TypeA, proto: "udp", rcode: dns.RcodeSuccess, answers: 0},
		{name: id + ".nx." + zone + ".", qtype: dns.TypeA, proto: "udp", rcode: dns.RcodeNameError, answers: 0},
		{name: base, qtype: dns.TypeA, proto: "udp", ecs: ecsNet, rcode: dns.RcodeSuccess, answers: 1},
		{name: base, qtype: dns.TypeA, proto: "tcp", rcode: dns.RcodeSuccess, answers: 1},
	}
	for _, c := range cases {
		m := query(t, srv, c.proto, c.name, c.qtype, c.ecs, false)
		if m.Rcode != c.rcode || (c.answers >= 0 && len(m.Answer) != c.answers) {
			t.Errorf("%s %s (%s): rcode=%s answers=%d, esperado %s/%d", c.name, dns.TypeToString[c.qtype], c.proto,
				dns.RcodeToString[m.Rcode], len(m.Answer), dns.RcodeToString[c.rcode], c.answers)
			continue
		}
		if c.check != nil {
			if err := c.check(m); err != nil {
				t.Error(err)
			}
		}
		time.Sleep(60 * time.Millisecond) // longe do RRL de 20/s
	}
	// fora da zona: REFUSED, sem recursão
	if m := query(t, srv, "udp", "example.com.", dns.TypeA, nil, true); m.Rcode != dns.RcodeRefused || m.RecursionAvailable {
		t.Errorf("example.com: rcode=%s ra=%v, esperado REFUSED sem RA", dns.RcodeToString[m.Rcode], m.RecursionAvailable)
	}

	p := waitProbe(t, id, func(p *probeResp) bool { return len(p.DNS) >= len(cases) && len(p.conns(53)) >= 1 })
	ecsSeen, tcpSeen, mixedSeen := false, false, false
	for _, q := range p.DNS {
		if q.Resolver.IP != mac {
			t.Errorf("%s: resolvedor %s, esperado esta máquina (%s)", q.Qname, q.Resolver.IP, mac)
		}
		if ptr2(q.ProbeID) != id {
			t.Errorf("%s: probe_id %v", q.Qname, ptr(q.ProbeID))
		}
		if q.Qname == mixed {
			mixedSeen = true
		}
		if q.EDNS != nil && q.EDNS.ECS != nil {
			ecsSeen = true
			if q.EDNS.ECS.Family != 1 || q.EDNS.ECS.SourcePrefix != 24 || q.EDNS.ECS.Address != "200.1.2.0" {
				t.Errorf("ECS registrado = %+v, esperado 1/24/200.1.2.0", *q.EDNS.ECS)
			}
		}
		if q.Proto == "tcp" {
			tcpSeen = true
		}
		if strings.Contains(q.Qname, ".nx.") && q.Response.Rcode != "NXDOMAIN" {
			t.Errorf("%s: rcode registrado %s", q.Qname, q.Response.Rcode)
		}
	}
	if !ecsSeen || !tcpSeen || !mixedSeen {
		t.Errorf("registro sem ECS (%v), TCP (%v) ou qname com a caixa original %q (%v)", ecsSeen, tcpSeen, mixed, mixedSeen)
	}
	if c := p.conns(53)[0]; c.Proto != "dns" {
		t.Errorf("conexão TCP 53: proto = %q, esperado dns", c.Proto)
	}
	addLive("dns-list-example.json", get(t, "/dns?probe="+id, nil))
}

// TestCase10DNSPublicResolvers: a mesma consulta por 8.8.8.8 e 1.1.1.1, com e sem ECS: o registro mostra o IP
// do resolvedor (não esta máquina). Se o resolvedor repassa o ECS é comportamento dele: só registrado no log.
func TestCase10DNSPublicResolvers(t *testing.T) {
	t.Parallel()
	mac := macIPv4(t)
	_, ecsNet, _ := net.ParseCIDR("200.1.2.0/24")
	for _, res := range []string{"8.8.8.8", "1.1.1.1"} {
		for _, withECS := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ecs=%v", res, withECS), func(t *testing.T) {
				t.Parallel()
				id := newID(t)
				var ecs *net.IPNet
				if withECS {
					ecs = ecsNet
				}
				for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS} {
					m := query(t, res+":53", "udp", id+"."+zone+".", qt, ecs, true)
					if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 {
						t.Errorf("%s via %s: rcode=%s answers=%v", dns.TypeToString[qt], res, dns.RcodeToString[m.Rcode], m.Answer)
					}
				}
				p := waitProbe(t, id, func(p *probeResp) bool {
					seen := map[string]bool{}
					for _, q := range p.DNS {
						seen[q.Qtype] = true
					}
					return seen["A"] && seen["AAAA"] && seen["HTTPS"]
				})
				for _, q := range p.DNS {
					if q.Resolver.IP == mac || net.ParseIP(q.Resolver.IP) == nil {
						t.Errorf("%s %s: resolvedor registrado %s (esta máquina é %s)", q.Qname, q.Qtype, q.Resolver.IP, mac)
					}
					ecsS := "sem ECS"
					if q.EDNS != nil && q.EDNS.ECS != nil {
						ecsS = fmt.Sprintf("ECS %s/%d", q.EDNS.ECS.Address, q.EDNS.ECS.SourcePrefix)
					}
					t.Logf("via %s: %s %s de %s (%s), %s", res, q.Qname, q.Qtype, q.Resolver.IP, q.Proto, ecsS)
				}
			})
		}
	}
}
