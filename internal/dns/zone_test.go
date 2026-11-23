package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
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
		Zone: "finger-west-01.badblock.net.br.", NS: DefaultNS, TTL: 5 * time.Second,
		IPv4: netip.MustParseAddr("127.0.0.1"), Port: 0, RRLPerIP: 20, ACMETTL: ACMEValueTTL,
		// 443 nas duas listas: o nome sem prefixo tem HTTPS com h3 (regra antiga, ainda válida com 443).
		WebTCPPorts: []int{443, 8080, 8443}, WebUDPPorts: []int{443, 8443},
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
	r := z.Answer(query("finger-west-01.badblock.net.br.", mdns.TypeSOA))
	if r.Rcode != mdns.RcodeSuccess || !r.Authoritative || r.RecursionAvailable || len(r.Answer) != 1 {
		t.Fatalf("SOA: %v", r)
	}
	soa := r.Answer[0].(*mdns.SOA)
	if soa.Ns != DefaultNS || soa.Mbox != "hostmaster.finger-west-01.badblock.net.br." || soa.Minttl != 5 || soa.Hdr.Ttl != 5 {
		t.Fatalf("SOA fields: %v", soa)
	}
	if soa.Serial != uint32(time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC).Unix()) {
		t.Fatalf("serial %d", soa.Serial)
	}

	r = z.Answer(query("Finger-West-01.BadBlock.net.br.", mdns.TypeNS))
	if r.Rcode != mdns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 1 {
		t.Fatalf("NS: %v", r)
	}
	ns := r.Answer[0].(*mdns.NS)
	if ns.Ns != "finger-01.badblock.net.br." || ns.Hdr.Name != "Finger-West-01.BadBlock.net.br." {
		t.Fatalf("NS: %v (a caixa da pergunta deve ser preservada)", ns)
	}
	if !r.RecursionDesired {
		t.Fatal("RD deve ser copiado")
	}

	r = z.Answer(query("finger-west-01.badblock.net.br.", mdns.TypeANY))
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
		{"finger-west-01.badblock.net.br.", mdns.TypeCAA},
		{"abcdefgh.finger-west-01.badblock.net.br.", mdns.TypeCAA},
		{"x.y.finger-west-01.badblock.net.br.", mdns.TypeMX},
		{"abcdefgh.finger-west-01.badblock.net.br.", mdns.TypeNS},
		{"_acme-challenge.finger-west-01.badblock.net.br.", mdns.TypeTXT},
		{"abcdefgh.finger-west-01.badblock.net.br.", mdns.TypeSOA},
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
	for _, n := range []string{"example.com.", "badblock.net.br.", "xfinger-west-01.badblock.net.br.", "."} {
		r := z.Answer(query(n, mdns.TypeA))
		if r.Rcode != mdns.RcodeRefused || r.Authoritative || r.RecursionAvailable || len(r.Answer) != 0 {
			t.Fatalf("%s: %v", n, r)
		}
	}
	// Classe CHAOS e transferência de zona também são recusadas.
	q := query("finger-west-01.badblock.net.br.", mdns.TypeTXT)
	q.Question[0].Qclass = mdns.ClassCHAOS
	if r := z.Answer(q); r.Rcode != mdns.RcodeRefused {
		t.Fatalf("CH: %v", r)
	}
	if r := z.Answer(query("finger-west-01.badblock.net.br.", mdns.TypeAXFR)); r.Rcode != mdns.RcodeRefused {
		t.Fatalf("AXFR: %v", r)
	}
}

func TestZoneOpcodeAndQuestions(t *testing.T) {
	z, _ := newTestZone()
	q := query("finger-west-01.badblock.net.br.", mdns.TypeSOA)
	q.Opcode = mdns.OpcodeUpdate
	if r := z.Answer(q); r.Rcode != mdns.RcodeNotImplemented {
		t.Fatalf("UPDATE: %v", r)
	}
	q = query("finger-west-01.badblock.net.br.", mdns.TypeSOA)
	q.Question = nil
	if r := z.Answer(q); r.Rcode != mdns.RcodeFormatError {
		t.Fatalf("sem pergunta: %v", r)
	}
}

func TestZoneACMESetClearExpire(t *testing.T) {
	z, clk := newTestZone()
	const name = "_acme-challenge.finger-west-01.badblock.net.br."
	if err := z.SetACME(name, "valueA"); err != nil {
		t.Fatal(err)
	}
	clk.advance(4 * time.Minute)
	// Mesmo nome sem ponto final e com outra caixa; set repetido é idempotente.
	if err := z.SetACME("_ACME-Challenge.finger-west-01.badblock.net.br", "valueB"); err != nil {
		t.Fatal(err)
	}
	if err := z.SetACME(name, "valueB"); err != nil {
		t.Fatal(err)
	}
	if got := z.ACMEValues(name); !slices.Equal(got, []string{"valueA", "valueB"}) {
		t.Fatalf("valores %v", got)
	}

	r := z.Answer(query("_Acme-Challenge.finger-west-01.badblock.net.br.", mdns.TypeTXT))
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
	if err := z.SetACME("_acme-challenge.abcdefgh.finger-west-01.badblock.net.br.", "x"); err != nil {
		t.Fatal(err)
	}
}

func TestZoneACMEInvalid(t *testing.T) {
	z, _ := newTestZone()
	for _, n := range []string{
		"_acme-challenge.example.com.", "finger-west-01.badblock.net.br.", "foo.finger-west-01.badblock.net.br.",
		"x._acme-challenge.finger-west-01.badblock.net.br.", "", "bad..name.finger-west-01.badblock.net.br.",
	} {
		if err := z.SetACME(n, "v"); err == nil {
			t.Fatalf("set %q devia falhar", n)
		}
		if err := z.ClearACME(n, "v"); err == nil {
			t.Fatalf("clear %q devia falhar", n)
		}
	}
	const name = "_acme-challenge.finger-west-01.badblock.net.br."
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
	t.Setenv("FS_DNS_ZONE", "Finger-West-01.BadBlock.net.br")
	t.Setenv("FS_DNS_TTL", "7s")
	t.Setenv("FS_DNS_RRL_PER_IP", "30")
	t.Setenv("FS_LISTEN_IPV4", "192.0.2.1")
	t.Setenv("FS_LISTEN_IPV6", "2001:db8::1")
	// Ausente (não só vazio): t.Setenv registra a restauração e o Unsetenv tira a chave do ambiente.
	for _, k := range []string{"FS_WEB_TCP_PORTS", "FS_WEB_UDP_PORTS"} {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.WebTCPPorts, []int{8080, 8443}) || !slices.Equal(c.WebUDPPorts, []int{8443}) {
		t.Fatalf("portas ausentes deviam valer os padrões do web: %v %v", c.WebTCPPorts, c.WebUDPPorts)
	}
	if c.Zone != "finger-west-01.badblock.net.br." || c.TTL != 7*time.Second || c.RRLPerIP != 30 || c.Port != 53 ||
		c.IPv4.String() != "192.0.2.1" || c.IPv6.String() != "2001:db8::1" || c.NS != DefaultNS || c.ACMETTL != 10*time.Minute {
		t.Fatalf("%+v", c)
	}

	bad := map[string]string{
		"FS_LISTEN_IPV4":    "2001:db8::1",
		"FS_LISTEN_IPV6":    "192.0.2.1",
		"FS_DNS_TTL":        "five",
		"FS_DNS_RRL_PER_IP": "x",
		"FS_DNS_ZONE":       "bad..zone",
		"FS_WEB_UDP_PORTS":  "443,abc",
		"FS_WEB_TCP_PORTS":  "8080,70000",
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
		{"finger-west-01.badblock.net.br.", mdns.TypeA, []string{"A " + v4}, mdns.RcodeSuccess},
		{"AbCdEfGh.finger-west-01.badblock.net.br.", mdns.TypeA, []string{"A " + v4}, mdns.RcodeSuccess},
		{"x.y.z.finger-west-01.badblock.net.br.", mdns.TypeAAAA, []string{"AAAA " + v6}, mdns.RcodeSuccess},
		{"abcdefgh.finger-west-01.badblock.net.br.", mdns.TypeHTTPS, []string{"HTTPS " + https}, mdns.RcodeSuccess},
		{"finger-west-01.badblock.net.br.", mdns.TypeHTTPS, []string{"HTTPS " + https}, mdns.RcodeSuccess},
		// Rótulos de controle à direita do probe, em qualquer posição.
		{"abcdefgh.noh3.finger-west-01.badblock.net.br.", mdns.TypeHTTPS, nil, mdns.RcodeSuccess},
		{"abcdefgh.noh3.finger-west-01.badblock.net.br.", mdns.TypeA, []string{"A " + v4}, mdns.RcodeSuccess},
		{"abcdefgh.v4.finger-west-01.badblock.net.br.", mdns.TypeAAAA, nil, mdns.RcodeSuccess},
		{"abcdefgh.x.V4.finger-west-01.badblock.net.br.", mdns.TypeA, []string{"A " + v4}, mdns.RcodeSuccess},
		{"abcdefgh.v4.finger-west-01.badblock.net.br.", mdns.TypeHTTPS, []string{`HTTPS 1 . alpn="h3,h2" ipv4hint="` + v4 + `"`}, mdns.RcodeSuccess},
		{"abcdefgh.v6.finger-west-01.badblock.net.br.", mdns.TypeA, nil, mdns.RcodeSuccess},
		{"abcdefgh.v6.finger-west-01.badblock.net.br.", mdns.TypeAAAA, []string{"AAAA " + v6}, mdns.RcodeSuccess},
		{"abcdefgh.nodata.finger-west-01.badblock.net.br.", mdns.TypeA, nil, mdns.RcodeSuccess},
		{"abcdefgh.nx.finger-west-01.badblock.net.br.", mdns.TypeA, nil, mdns.RcodeNameError},
		{"nx.finger-west-01.badblock.net.br.", mdns.TypeAAAA, nil, mdns.RcodeNameError},
		{"abcdefgh.noh3.v6.finger-west-01.badblock.net.br.", mdns.TypeANY, []string{"AAAA " + v6}, mdns.RcodeSuccess},
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
	if z.ProbeID("AbCdEfGh.v4.finger-west-01.badblock.net.br.") != "abcdefgh" || z.ProbeID("finger-west-01.badblock.net.br.") != "" {
		t.Fatal("ProbeID")
	}
}

// TestZoneNoIPv6: sem FS_LISTEN_IPV6 o AAAA é NODATA e o HTTPS não leva ipv6hint.
func TestZoneNoIPv6(t *testing.T) {
	z, _ := newTestZone()
	if r := z.Answer(query("abcdefgh.finger-west-01.badblock.net.br.", mdns.TypeAAAA)); len(r.Answer) != 0 {
		t.Fatal(r)
	}
	r := z.Answer(query("abcdefgh.finger-west-01.badblock.net.br.", mdns.TypeHTTPS))
	if got := rrTypes(r.Answer); !slices.Equal(got, []string{`HTTPS 1 . alpn="h3,h2" ipv4hint="127.0.0.1"`}) {
		t.Fatal(got)
	}
	// v6 sem IPv6 configurado: nada de endereço, nem HTTPS.
	if r := z.Answer(query("abcdefgh.v6.finger-west-01.badblock.net.br.", mdns.TypeHTTPS)); len(r.Answer) != 0 {
		t.Fatal(r)
	}
}

// TestLoadConfigWebPorts: as listas do env compartilhado com o web (vazio = nenhuma, sem repetição, ordenadas).
func TestLoadConfigWebPorts(t *testing.T) {
	t.Setenv("FS_LISTEN_IPV4", "192.0.2.1")
	t.Setenv("FS_LISTEN_IPV6", "")
	cases := map[string][]int{"": {}, "8443": {8443}, " 8443 , 443 ,8443": {443, 8443}, ",": {}}
	for v, want := range cases {
		t.Run("v="+v, func(t *testing.T) {
			t.Setenv("FS_WEB_TCP_PORTS", v)
			t.Setenv("FS_WEB_UDP_PORTS", v)
			c, err := LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(c.WebTCPPorts, want) || !slices.Equal(c.WebUDPPorts, want) {
				t.Fatalf("%v %v, want %v", c.WebTCPPorts, c.WebUDPPorts, want)
			}
		})
	}
}

// finger01Zone é a zona com os padrões do finger-01: TCP 8080,8443 e UDP 8443, dupla pilha (ADR 0038).
func finger01Zone(t *testing.T) *Zone {
	t.Helper()
	for _, k := range []string{"FS_WEB_TCP_PORTS", "FS_WEB_UDP_PORTS", "FS_DNS_ZONE"} {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("FS_LISTEN_IPV4", "170.247.40.86")
	t.Setenv("FS_LISTEN_IPV6", "2804:231c:e500:cafe::86")
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return NewZone(c, nil)
}

// TestZoneHTTPSPortPrefix: HTTPS RR em _<P>._https.<nome> (RFC 9460 §2.3, spec 007 RF-02, ADR 0038).
func TestZoneHTTPSPortPrefix(t *testing.T) {
	z := finger01Zone(t)
	const v4, v6 = "170.247.40.86", "2804:231c:e500:cafe::86"
	const hints = ` ipv4hint="` + v4 + `" ipv6hint="` + v6 + `"`
	const zone = "finger-west-01.badblock.net.br."
	cases := []struct {
		name  string
		qtype uint16
		want  []string
		rcode int
	}{
		{"_8443._https.abcdefgh." + zone, mdns.TypeHTTPS, []string{`HTTPS 1 abcdefgh.` + zone + ` alpn="h3,h2"` + hints}, mdns.RcodeSuccess},
		{"_8443._HTTPS.AbCdEfGh." + zone, mdns.TypeHTTPS, []string{`HTTPS 1 abcdefgh.` + zone + ` alpn="h3,h2"` + hints}, mdns.RcodeSuccess},
		{"_8080._https.abcdefgh." + zone, mdns.TypeHTTPS, []string{`HTTPS 1 abcdefgh.` + zone + ` alpn="h2"` + hints}, mdns.RcodeSuccess},
		{"_8443._https." + zone, mdns.TypeHTTPS, []string{`HTTPS 1 ` + zone + ` alpn="h3,h2"` + hints}, mdns.RcodeSuccess},
		{"_8443._https.abcdefgh." + zone, mdns.TypeANY, []string{`HTTPS 1 abcdefgh.` + zone + ` alpn="h3,h2"` + hints}, mdns.RcodeSuccess},
		// Sem prefixo é a origem da 443 (do traefik no finger-01): NODATA.
		{"abcdefgh." + zone, mdns.TypeHTTPS, nil, mdns.RcodeSuccess},
		{zone, mdns.TypeHTTPS, nil, mdns.RcodeSuccess},
		{"abcdefgh." + zone, mdns.TypeANY, []string{"A " + v4, "AAAA " + v6}, mdns.RcodeSuccess},
		// Porta fora da lista, porta não canônica e outros rótulos "_": NODATA.
		{"_9999._https.abcdefgh." + zone, mdns.TypeHTTPS, nil, mdns.RcodeSuccess},
		{"_08443._https.abcdefgh." + zone, mdns.TypeHTTPS, nil, mdns.RcodeSuccess},
		{"_8443._tcp.abcdefgh." + zone, mdns.TypeHTTPS, nil, mdns.RcodeSuccess},
		{"_8443._https.abcdefgh." + zone, mdns.TypeA, nil, mdns.RcodeSuccess},
		{"_foo.abcdefgh." + zone, mdns.TypeA, nil, mdns.RcodeSuccess},
		{"x._8443._https.abcdefgh." + zone, mdns.TypeHTTPS, nil, mdns.RcodeSuccess},
		{"_8443._https.x._y." + zone, mdns.TypeHTTPS, nil, mdns.RcodeSuccess},
		{"_acme-challenge.abcdefgh." + zone, mdns.TypeA, nil, mdns.RcodeSuccess},
		// Controles à direita do probe valem para o nome com prefixo.
		{"_8443._https.abcdefgh.noh3." + zone, mdns.TypeHTTPS, nil, mdns.RcodeSuccess},
		{"_8443._https.abcdefgh.v4." + zone, mdns.TypeHTTPS, []string{`HTTPS 1 abcdefgh.v4.` + zone + ` alpn="h3,h2" ipv4hint="` + v4 + `"`}, mdns.RcodeSuccess},
		{"_8443._https.abcdefgh.v6." + zone, mdns.TypeHTTPS, []string{`HTTPS 1 abcdefgh.v6.` + zone + ` alpn="h3,h2" ipv6hint="` + v6 + `"`}, mdns.RcodeSuccess},
		{"_8443._https.abcdefgh.nodata." + zone, mdns.TypeHTTPS, nil, mdns.RcodeSuccess},
		{"_8443._https.abcdefgh.nx." + zone, mdns.TypeHTTPS, nil, mdns.RcodeNameError},
		// Fora da zona.
		{"_8443._https.abcdefgh.example.com.", mdns.TypeHTTPS, nil, mdns.RcodeRefused},
	}
	for _, c := range cases {
		r := z.Answer(query(c.name, c.qtype))
		got := rrTypes(r.Answer)
		if r.Rcode != c.rcode || !slices.Equal(got, c.want) {
			t.Errorf("%s %s: rcode %d %v, want %d %v", c.name, mdns.TypeToString[c.qtype], r.Rcode, got, c.rcode, c.want)
			continue
		}
		if c.rcode == mdns.RcodeSuccess && len(r.Answer) == 0 && (len(r.Ns) != 1 || r.Ns[0].Header().Rrtype != mdns.TypeSOA) {
			t.Errorf("%s: sem SOA na autoridade", c.name)
		}
	}
	// Probe = primeiro rótulo depois dos "_" à esquerda.
	for n, want := range map[string]string{
		"_8443._https.AbCdEfGh." + zone:    "abcdefgh",
		"_acme-challenge.abcdefgh." + zone: "abcdefgh",
		"_9999._https.abcdefgh.v4." + zone: "abcdefgh",
		"_8443._https." + zone:             "",
		"_8443._https.abcdefgh.example.":   "",
	} {
		if got := z.ProbeID(n); got != want {
			t.Errorf("ProbeID(%s) = %q, want %q", n, got, want)
		}
	}
	// SOA e NS do apex em finger-01.badblock.net.br.
	r := z.Answer(query(zone, mdns.TypeNS))
	if ns, ok := r.Answer[0].(*mdns.NS); !ok || ns.Ns != "finger-01.badblock.net.br." {
		t.Fatal(r.Answer)
	}
	r = z.Answer(query(zone, mdns.TypeSOA))
	if soa, ok := r.Answer[0].(*mdns.SOA); !ok || soa.Ns != "finger-01.badblock.net.br." {
		t.Fatal(r.Answer)
	}
}

// TestZoneHTTPSWithout443: alpn do nome sem prefixo só com 443 na lista TCP, e h3 só com 443 também em UDP.
func TestZoneHTTPSWithout443(t *testing.T) {
	c := testConfig()
	for _, tc := range []struct {
		tcp, udp []int
		want     []string
	}{
		{[]int{443}, []int{443}, []string{`HTTPS 1 . alpn="h3,h2" ipv4hint="127.0.0.1"`}},
		{[]int{443}, []int{8443}, []string{`HTTPS 1 . alpn="h2" ipv4hint="127.0.0.1"`}},
		{[]int{443}, []int{}, []string{`HTTPS 1 . alpn="h2" ipv4hint="127.0.0.1"`}},
		{[]int{8443}, []int{443, 8443}, nil},
		{[]int{}, []int{}, nil},
	} {
		c.WebTCPPorts, c.WebUDPPorts = tc.tcp, tc.udp
		r := NewZone(c, nil).Answer(query("abcdefgh.finger-west-01.badblock.net.br.", mdns.TypeHTTPS))
		if got := rrTypes(r.Answer); !slices.Equal(got, tc.want) {
			t.Errorf("tcp %v udp %v: %v, want %v", tc.tcp, tc.udp, got, tc.want)
		}
	}
}

// acmeTestName devolve o i-ésimo nome _acme-challenge distinto dentro da zona de teste.
func acmeTestName(i int) string {
	return fmt.Sprintf("_acme-challenge.n%02d.finger-west-01.badblock.net.br.", i)
}

func TestZoneACMELimits(t *testing.T) {
	t.Run("per name", func(t *testing.T) {
		z, clk := newTestZone()
		name := acmeTestName(0)
		for i := range maxACMEValuesPerName {
			if err := z.SetACME(name, fmt.Sprintf("v%d", i)); err != nil {
				t.Fatalf("valor %d: %v", i, err)
			}
		}
		// 9º valor no mesmo nome: recusado, nada guardado.
		if err := z.SetACME(name, "extra"); !errors.Is(err, errACMELimit) {
			t.Fatalf("9º valor: %v", err)
		}
		if got := z.ACMEValues(name); len(got) != maxACMEValuesPerName || slices.Contains(got, "extra") {
			t.Fatalf("valores %v", got)
		}
		// Repetir um valor existente com o teto cheio só renova a expiração.
		clk.advance(5 * time.Minute)
		if err := z.SetACME(name, "v0"); err != nil {
			t.Fatalf("repetir valor: %v", err)
		}
		// Outros nomes continuam aceitos.
		if err := z.SetACME(acmeTestName(1), "x"); err != nil {
			t.Fatal(err)
		}
		// Depois da expiração dos outros, v0 (renovado) segue e cabem valores novos.
		clk.advance(5 * time.Minute)
		if got := z.ACMEValues(name); !slices.Equal(got, []string{"v0"}) {
			t.Fatalf("após expirar: %v", got)
		}
		if err := z.SetACME(name, "extra"); err != nil {
			t.Fatalf("após expirar: %v", err)
		}
	})

	t.Run("names", func(t *testing.T) {
		z, clk := newTestZone()
		for i := range maxACMENames {
			if err := z.SetACME(acmeTestName(i), "v"); err != nil {
				t.Fatalf("nome %d: %v", i, err)
			}
		}
		// 17º nome: recusado.
		if err := z.SetACME(acmeTestName(maxACMENames), "v"); !errors.Is(err, errACMELimit) {
			t.Fatalf("17º nome: %v", err)
		}
		if len(z.acme) != maxACMENames {
			t.Fatalf("nomes %d", len(z.acme))
		}
		// Valor novo num nome existente ainda cabe; repetido também.
		if err := z.SetACME(acmeTestName(0), "w"); err != nil {
			t.Fatal(err)
		}
		if err := z.SetACME(acmeTestName(1), "v"); err != nil {
			t.Fatal(err)
		}
		clk.advance(ACMEValueTTL)
		if err := z.SetACME(acmeTestName(maxACMENames), "v"); err != nil {
			t.Fatalf("após expirar: %v", err)
		}
	})

	t.Run("total", func(t *testing.T) {
		z, clk := newTestZone()
		names := maxACMEValues / maxACMEValuesPerName
		for i := range names {
			for j := range maxACMEValuesPerName {
				if err := z.SetACME(acmeTestName(i), fmt.Sprintf("v%d", j)); err != nil {
					t.Fatalf("nome %d valor %d: %v", i, j, err)
				}
			}
		}
		// 65º valor num nome novo (abaixo do teto de nomes): recusado.
		if err := z.SetACME(acmeTestName(names), "v"); !errors.Is(err, errACMELimit) {
			t.Fatalf("65º valor: %v", err)
		}
		if _, ok := z.acme[mdns.CanonicalName(acmeTestName(names))]; ok {
			t.Fatal("nome recusado não pode ficar guardado")
		}
		// Repetir um valor existente com o total cheio é aceito.
		if err := z.SetACME(acmeTestName(0), "v0"); err != nil {
			t.Fatalf("repetir valor: %v", err)
		}
		// Liberar um valor abre espaço.
		if err := z.ClearACME(acmeTestName(0), "v1"); err != nil {
			t.Fatal(err)
		}
		if err := z.SetACME(acmeTestName(names), "v"); err != nil {
			t.Fatalf("após clear: %v", err)
		}
		clk.advance(ACMEValueTTL)
		if err := z.SetACME(acmeTestName(names+1), "v"); err != nil {
			t.Fatalf("após expirar: %v", err)
		}
	})
}
