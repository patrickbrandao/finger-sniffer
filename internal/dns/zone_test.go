package dns

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// fakeClock é um relógio injetável (e seguro entre goroutines) para os testes de expiração.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func testConfig() Config {
	return Config{
		Zone: "dns-monitor.tmsoft.com.br.", NS: DefaultNS, TTL: 5 * time.Second,
		IPv4: netip.MustParseAddr("127.0.0.1"), Port: 0, RRLPerIP: 20, ACMETTL: ACMEValueTTL,
	}
}

func newTestZone() (*Zone, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)}
	return NewZone(testConfig(), clk.now), clk
}

func query(name string, qtype uint16) *mdns.Msg {
	m := new(mdns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	return m
}

func TestZoneApexSOAandNS(t *testing.T) {
	z, _ := newTestZone()
	r := z.Answer(query("dns-monitor.tmsoft.com.br.", mdns.TypeSOA))
	if r.Rcode != mdns.RcodeSuccess || !r.Authoritative || r.RecursionAvailable || len(r.Answer) != 1 {
		t.Fatalf("SOA: %v", r)
	}
	soa := r.Answer[0].(*mdns.SOA)
	if soa.Ns != DefaultNS || soa.Mbox != "hostmaster.dns-monitor.tmsoft.com.br." || soa.Minttl != 5 || soa.Hdr.Ttl != 5 {
		t.Fatalf("SOA fields: %v", soa)
	}
	if soa.Serial != uint32(time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC).Unix()) {
		t.Fatalf("serial %d", soa.Serial)
	}

	r = z.Answer(query("DNS-Monitor.TMSoft.com.br.", mdns.TypeNS))
	if r.Rcode != mdns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 1 {
		t.Fatalf("NS: %v", r)
	}
	ns := r.Answer[0].(*mdns.NS)
	if ns.Ns != "vps602.tmsoft.com.br." || ns.Hdr.Name != "DNS-Monitor.TMSoft.com.br." {
		t.Fatalf("NS: %v (a caixa da pergunta deve ser preservada)", ns)
	}
	if !r.RecursionDesired {
		t.Fatal("RD deve ser copiado")
	}

	r = z.Answer(query("dns-monitor.tmsoft.com.br.", mdns.TypeANY))
	// SOA, NS, A e HTTPS (a zona de teste não tem IPv6).
	if len(r.Answer) != 4 {
		t.Fatalf("ANY apex: %v", r)
	}
}

func TestZoneNoData(t *testing.T) {
	z, _ := newTestZone()
	cases := []struct {
		name  string
		qtype uint16
	}{
		{"dns-monitor.tmsoft.com.br.", mdns.TypeCAA},
		{"abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeCAA},
		{"x.y.dns-monitor.tmsoft.com.br.", mdns.TypeMX},
		{"abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeNS},
		{"_acme-challenge.dns-monitor.tmsoft.com.br.", mdns.TypeTXT},
		{"abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeSOA},
	}
	for _, c := range cases {
		r := z.Answer(query(c.name, c.qtype))
		if r.Rcode != mdns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 0 || len(r.Ns) != 1 {
			t.Fatalf("%s %s: %v", c.name, mdns.TypeToString[c.qtype], r)
		}
		if _, ok := r.Ns[0].(*mdns.SOA); !ok {
			t.Fatalf("%s: autoridade sem SOA", c.name)
		}
	}
}

func TestZoneRefused(t *testing.T) {
	z, _ := newTestZone()
	for _, n := range []string{"example.com.", "tmsoft.com.br.", "xdns-monitor.tmsoft.com.br.", "."} {
		r := z.Answer(query(n, mdns.TypeA))
		if r.Rcode != mdns.RcodeRefused || r.Authoritative || r.RecursionAvailable || len(r.Answer) != 0 {
			t.Fatalf("%s: %v", n, r)
		}
	}
	// Classe CHAOS e transferência de zona também são recusadas.
	q := query("dns-monitor.tmsoft.com.br.", mdns.TypeTXT)
	q.Question[0].Qclass = mdns.ClassCHAOS
	if r := z.Answer(q); r.Rcode != mdns.RcodeRefused {
		t.Fatalf("CH: %v", r)
	}
	if r := z.Answer(query("dns-monitor.tmsoft.com.br.", mdns.TypeAXFR)); r.Rcode != mdns.RcodeRefused {
		t.Fatalf("AXFR: %v", r)
	}
}

func TestZoneOpcodeAndQuestions(t *testing.T) {
	z, _ := newTestZone()
	q := query("dns-monitor.tmsoft.com.br.", mdns.TypeSOA)
	q.Opcode = mdns.OpcodeUpdate
	if r := z.Answer(q); r.Rcode != mdns.RcodeNotImplemented {
		t.Fatalf("UPDATE: %v", r)
	}
	q = query("dns-monitor.tmsoft.com.br.", mdns.TypeSOA)
	q.Question = nil
	if r := z.Answer(q); r.Rcode != mdns.RcodeFormatError {
		t.Fatalf("sem pergunta: %v", r)
	}
}

func TestZoneACMESetClearExpire(t *testing.T) {
	z, clk := newTestZone()
	const name = "_acme-challenge.dns-monitor.tmsoft.com.br."
	if err := z.SetACME(name, "valueA"); err != nil {
		t.Fatal(err)
	}
	clk.advance(4 * time.Minute)
	// Mesmo nome sem ponto final e com outra caixa; set repetido é idempotente.
	if err := z.SetACME("_ACME-Challenge.dns-monitor.tmsoft.com.br", "valueB"); err != nil {
		t.Fatal(err)
	}
	if err := z.SetACME(name, "valueB"); err != nil {
		t.Fatal(err)
	}
	if got := z.ACMEValues(name); !slices.Equal(got, []string{"valueA", "valueB"}) {
		t.Fatalf("valores %v", got)
	}

	r := z.Answer(query("_Acme-Challenge.dns-monitor.tmsoft.com.br.", mdns.TypeTXT))
	if len(r.Answer) != 2 || r.Answer[0].Header().Ttl != 5 || len(r.Ns) != 0 {
		t.Fatalf("TXT: %v", r)
	}

	// valueA expira 10 min após o set; valueB continua.
	clk.advance(6 * time.Minute)
	if got := z.ACMEValues(name); !slices.Equal(got, []string{"valueB"}) {
		t.Fatalf("após expirar A: %v", got)
	}
	clk.advance(4 * time.Minute)
	if got := z.ACMEValues(name); len(got) != 0 {
		t.Fatalf("após expirar B: %v", got)
	}

	// clear remove só o valor pedido.
	_ = z.SetACME(name, "v1")
	_ = z.SetACME(name, "v2")
	if err := z.ClearACME(name, "v1"); err != nil {
		t.Fatal(err)
	}
	if got := z.ACMEValues(name); !slices.Equal(got, []string{"v2"}) {
		t.Fatalf("após clear: %v", got)
	}
	if err := z.ClearACME(name, "missing"); err != nil {
		t.Fatal(err)
	}
	if err := z.ClearACME(name, "v2"); err != nil || len(z.acme) != 0 {
		t.Fatalf("conjunto vazio deve sumir: %v %v", err, z.acme)
	}

	// Subdomínio do curinga também é aceito.
	if err := z.SetACME("_acme-challenge.abcdefgh.dns-monitor.tmsoft.com.br.", "x"); err != nil {
		t.Fatal(err)
	}
}

func TestZoneACMEInvalid(t *testing.T) {
	z, _ := newTestZone()
	for _, n := range []string{
		"_acme-challenge.example.com.", "dns-monitor.tmsoft.com.br.", "foo.dns-monitor.tmsoft.com.br.",
		"x._acme-challenge.dns-monitor.tmsoft.com.br.", "", "bad..name.dns-monitor.tmsoft.com.br.",
	} {
		if err := z.SetACME(n, "v"); err == nil {
			t.Fatalf("set %q devia falhar", n)
		}
		if err := z.ClearACME(n, "v"); err == nil {
			t.Fatalf("clear %q devia falhar", n)
		}
	}
	const name = "_acme-challenge.dns-monitor.tmsoft.com.br."
	if err := z.SetACME(name, ""); err == nil {
		t.Fatal("valor vazio")
	}
	if err := z.SetACME(name, string(make([]byte, 256))); err == nil {
		t.Fatal("valor longo")
	}
}

func TestConfigHelpers(t *testing.T) {
	c := testConfig()
	c.IPv6 = netip.MustParseAddr("::1")
	c.Port = 53
	if got := c.listenAddrs(); !slices.Equal(got, []string{"127.0.0.1:53", "[::1]:53"}) {
		t.Fatalf("addrs %v", got)
	}
	c.TTL = -1
	if c.ttlSeconds() != 0 {
		t.Fatal("ttl negativo")
	}
}

func TestLoadConfig(t *testing.T) {
	t.Setenv("FS_DNS_ZONE", "Dns-Monitor.TMSoft.com.br")
	t.Setenv("FS_DNS_TTL", "7s")
	t.Setenv("FS_DNS_RRL_PER_IP", "30")
	t.Setenv("FS_LISTEN_IPV4", "192.0.2.1")
	t.Setenv("FS_LISTEN_IPV6", "2001:db8::1")
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.Zone != "dns-monitor.tmsoft.com.br." || c.TTL != 7*time.Second || c.RRLPerIP != 30 || c.Port != 53 ||
		c.IPv4.String() != "192.0.2.1" || c.IPv6.String() != "2001:db8::1" || c.NS != DefaultNS || c.ACMETTL != 10*time.Minute {
		t.Fatalf("%+v", c)
	}

	bad := map[string]string{
		"FS_LISTEN_IPV4":    "2001:db8::1",
		"FS_LISTEN_IPV6":    "192.0.2.1",
		"FS_DNS_TTL":        "five",
		"FS_DNS_RRL_PER_IP": "x",
		"FS_DNS_ZONE":       "bad..zone",
	}
	for k, v := range bad {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := LoadConfig(); err == nil {
				t.Fatalf("%s=%s devia falhar", k, v)
			}
		})
	}
	t.Run("no-ip", func(t *testing.T) {
		t.Setenv("FS_LISTEN_IPV4", "")
		t.Setenv("FS_LISTEN_IPV6", "")
		if _, err := LoadConfig(); err == nil {
			t.Fatal("sem IP devia falhar")
		}
	})
}

func newDualZone() *Zone {
	cfg := testConfig()
	cfg.IPv4 = netip.MustParseAddr("172.233.24.85")
	cfg.IPv6 = netip.MustParseAddr("2600:3c0d::f03c:93ff:fe26:8fd9")
	return NewZone(cfg, nil)
}

// rrTypes devolve "TIPO dados" de cada RR da resposta, para comparar.
func rrTypes(rrs []mdns.RR) []string {
	var out []string
	for _, rr := range rrs {
		h := rr.Header()
		out = append(out, mdns.TypeToString[h.Rrtype]+" "+strings.TrimPrefix(rr.String(), h.String()))
	}
	return out
}

func TestZoneAddressRecords(t *testing.T) {
	z := newDualZone()
	const v4, v6 = "172.233.24.85", "2600:3c0d::f03c:93ff:fe26:8fd9"
	const https = `1 . alpn="h3,h2" ipv4hint="` + v4 + `" ipv6hint="` + v6 + `"`
	cases := []struct {
		name  string
		qtype uint16
		want  []string
		rcode int
	}{
		{"dns-monitor.tmsoft.com.br.", mdns.TypeA, []string{"A " + v4}, mdns.RcodeSuccess},
		{"AbCdEfGh.dns-monitor.tmsoft.com.br.", mdns.TypeA, []string{"A " + v4}, mdns.RcodeSuccess},
		{"x.y.z.dns-monitor.tmsoft.com.br.", mdns.TypeAAAA, []string{"AAAA " + v6}, mdns.RcodeSuccess},
		{"abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeHTTPS, []string{"HTTPS " + https}, mdns.RcodeSuccess},
		{"dns-monitor.tmsoft.com.br.", mdns.TypeHTTPS, []string{"HTTPS " + https}, mdns.RcodeSuccess},
		// Rótulos de controle à direita do probe, em qualquer posição.
		{"abcdefgh.noh3.dns-monitor.tmsoft.com.br.", mdns.TypeHTTPS, nil, mdns.RcodeSuccess},
		{"abcdefgh.noh3.dns-monitor.tmsoft.com.br.", mdns.TypeA, []string{"A " + v4}, mdns.RcodeSuccess},
		{"abcdefgh.v4.dns-monitor.tmsoft.com.br.", mdns.TypeAAAA, nil, mdns.RcodeSuccess},
		{"abcdefgh.x.V4.dns-monitor.tmsoft.com.br.", mdns.TypeA, []string{"A " + v4}, mdns.RcodeSuccess},
		{"abcdefgh.v4.dns-monitor.tmsoft.com.br.", mdns.TypeHTTPS, []string{`HTTPS 1 . alpn="h3,h2" ipv4hint="` + v4 + `"`}, mdns.RcodeSuccess},
		{"abcdefgh.v6.dns-monitor.tmsoft.com.br.", mdns.TypeA, nil, mdns.RcodeSuccess},
		{"abcdefgh.v6.dns-monitor.tmsoft.com.br.", mdns.TypeAAAA, []string{"AAAA " + v6}, mdns.RcodeSuccess},
		{"abcdefgh.nodata.dns-monitor.tmsoft.com.br.", mdns.TypeA, nil, mdns.RcodeSuccess},
		{"abcdefgh.nx.dns-monitor.tmsoft.com.br.", mdns.TypeA, nil, mdns.RcodeNameError},
		{"nx.dns-monitor.tmsoft.com.br.", mdns.TypeAAAA, nil, mdns.RcodeNameError},
		{"abcdefgh.noh3.v6.dns-monitor.tmsoft.com.br.", mdns.TypeANY, []string{"AAAA " + v6}, mdns.RcodeSuccess},
	}
	for _, c := range cases {
		r := z.Answer(query(c.name, c.qtype))
		got := rrTypes(r.Answer)
		if r.Rcode != c.rcode || !r.Authoritative || !slices.Equal(got, c.want) {
			t.Errorf("%s %s: rcode %d %v, want %d %v", c.name, mdns.TypeToString[c.qtype], r.Rcode, got, c.rcode, c.want)
			continue
		}
		for _, rr := range r.Answer {
			if rr.Header().Ttl != 5 || rr.Header().Name != c.name {
				t.Errorf("%s: header %v", c.name, rr.Header())
			}
		}
		if len(r.Answer) == 0 && (len(r.Ns) != 1 || r.Ns[0].Header().Rrtype != mdns.TypeSOA) {
			t.Errorf("%s: sem SOA na autoridade", c.name)
		}
	}
	if z.ProbeID("AbCdEfGh.v4.dns-monitor.tmsoft.com.br.") != "abcdefgh" || z.ProbeID("dns-monitor.tmsoft.com.br.") != "" {
		t.Fatal("ProbeID")
	}
}

// TestZoneNoIPv6: sem FS_LISTEN_IPV6 o AAAA é NODATA e o HTTPS não leva ipv6hint.
func TestZoneNoIPv6(t *testing.T) {
	z, _ := newTestZone()
	if r := z.Answer(query("abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeAAAA)); len(r.Answer) != 0 {
		t.Fatal(r)
	}
	r := z.Answer(query("abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeHTTPS))
	if got := rrTypes(r.Answer); !slices.Equal(got, []string{`HTTPS 1 . alpn="h3,h2" ipv4hint="127.0.0.1"`}) {
		t.Fatal(got)
	}
	// v6 sem IPv6 configurado: nada de endereço, nem HTTPS.
	if r := z.Answer(query("abcdefgh.v6.dns-monitor.tmsoft.com.br.", mdns.TypeHTTPS)); len(r.Answer) != 0 {
		t.Fatal(r)
	}
}
