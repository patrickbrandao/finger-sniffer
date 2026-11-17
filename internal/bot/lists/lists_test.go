package lists

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A base própria embutida passa na validação, a versão é o SHA-256 do arquivo e as consultas por família
// funcionam.
func TestKnownClientsEmbedded(t *testing.T) {
	k, err := LoadKnownClients()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(knownClientsJSON)
	if k.Version != hex.EncodeToString(sum[:]) {
		t.Errorf("version %s", k.Version)
	}
	if k.Entries() == 0 || !slices.Contains(k.Families(), "chrome") || !slices.Contains(k.Families(), "curl") {
		t.Fatalf("families %v", k.Families())
	}
	for _, m := range k.Measured {
		f := k.Family(m.Client)
		if f == nil || !f.JA4[m.JA4] {
			t.Fatalf("%s sem o JA4 %s", m.Client, m.JA4)
		}
		if m.Akamai != nil && !f.Akamai[*m.Akamai] {
			t.Errorf("%s sem o Akamai", m.Client)
		}
		if len(k.ByJA4(m.JA4)) == 0 {
			t.Errorf("ByJA4(%s) vazio", m.JA4)
		}
		o := Observed{JA4: m.JA4}
		if m.Akamai != nil {
			o.Akamai = *m.Akamai
		}
		if m.JA4T != nil {
			o.JA4T = *m.JA4T
		}
		if got, ok := k.Coherent(m.Client, o); !ok || got.JA4 != m.JA4 {
			t.Errorf("Coherent(%s, %+v) = %v", m.Client, o, ok)
		}
	}
	if k.Family("nao-medido") != nil {
		t.Error("família inexistente")
	}
}

// Coerência: Akamai ou JA4T divergente, ou outra família, não casa.
func TestKnownClientsCoherent(t *testing.T) {
	k, err := LoadKnownClients()
	if err != nil {
		t.Fatal(err)
	}
	var h2 KnownClient
	for _, m := range k.Measured {
		if m.Proto == "h2" && m.JA4T != nil {
			h2 = m
			break
		}
	}
	if h2.Client == "" {
		t.Fatal("base sem medida h2")
	}
	if _, ok := k.Coherent(h2.Client, Observed{JA4: h2.JA4, Akamai: "1:1|0|0|m,a,s,p"}); ok {
		t.Error("Akamai divergente casou")
	}
	if _, ok := k.Coherent(h2.Client, Observed{JA4: h2.JA4, JA4T: "1_2_3_4"}); ok {
		t.Error("JA4T divergente casou")
	}
	if _, ok := k.Coherent("outro", Observed{JA4: h2.JA4}); ok {
		t.Error("outra família casou")
	}
	if _, ok := k.Coherent(h2.Client, Observed{JA4: "t13d0000h2_000000000000_000000000000"}); ok {
		t.Error("JA4 desconhecido casou")
	}
}

// JA4T sem MSS (rules v1.2, ADR 0058 item 4): igual menos o MSS casa a base; janela, opções ou escala diferentes não.
func TestKnownClientsCoherentJA4TWithoutMSS(t *testing.T) {
	k, err := LoadKnownClients()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range k.Measured {
		if m.JA4T == nil || (m.Client != "chrome" && m.Client != "firefox") {
			continue
		}
		p := strings.Split(*m.JA4T, "_")
		if len(p) != 4 {
			t.Fatalf("JA4T medido fora do formato: %q", *m.JA4T)
		}
		o := Observed{JA4: m.JA4}
		if m.Akamai != nil {
			o.Akamai = *m.Akamai
		}
		for _, tc := range []struct {
			ja4t string
			want bool
		}{
			{*m.JA4T, true},
			{p[0] + "_" + p[1] + "_1460_" + p[3], true},        // MSS cheio (sem grampo no caminho)
			{p[0] + "_" + p[1] + "_1380_" + p[3], true},        // MSS mais grampeado
			{"64240_" + p[1] + "_" + p[2] + "_" + p[3], false}, // outra janela
			{p[0] + "_2-4-8-1-3_" + p[2] + "_" + p[3], false},  // outras opções
			{p[0] + "_" + p[1] + "_" + p[2] + "_7", false},     // outra escala
			{"1_2_3", false}, // fora do formato
		} {
			o.JA4T = tc.ja4t
			if _, ok := k.Coherent(m.Client, o); ok != tc.want {
				t.Errorf("%s %s: Coherent(JA4T %q) = %v, quer %v", m.Client, m.Proto, tc.ja4t, ok, tc.want)
			}
		}
	}
	if got := JA4TWithoutMSS("65535_2-1-3-1-1-8-4-0-0_1432_6"); got != "65535_2-1-3-1-1-8-4-0-0_6" {
		t.Errorf("JA4TWithoutMSS = %q", got)
	}
	if got := JA4TWithoutMSS("x_y"); got != "x_y" {
		t.Errorf("fora do formato: %q", got)
	}
}

// Formato errado da base própria é rejeitado.
func TestParseKnownClientsInvalid(t *testing.T) {
	good := `{"client":"curl","client_version":"8","os":"linux","proto":"h1","ja4":"t13d3012h1_1d37bd780c83_581742d1f3c4","ja4_r":"x","akamai":null,"ja4h_ab":null,"ja4t":null,"p0f_os":null,"ttl_initial":64,"alpn":["http/1.1"],"measured_at":"2026-11-16T17:18:37Z","commit":"abc"}`
	if _, err := ParseKnownClients([]byte(`{"version":1,"measured":[` + good + `]}`)); err != nil {
		t.Fatalf("válida rejeitada: %v", err)
	}
	cases := map[string]string{
		"versão":        `{"version":2,"measured":[` + good + `]}`,
		"vazia":         `{"version":1,"measured":[]}`,
		"campo extra":   `{"version":1,"measured":[` + strings.Replace(good, `"commit"`, `"x":1,"commit"`, 1) + `]}`,
		"ja4":           `{"version":1,"measured":[` + strings.Replace(good, "t13d3012h1", "zz", 1) + `]}`,
		"proto":         `{"version":1,"measured":[` + strings.Replace(good, `"h1"`, `"h9"`, 1) + `]}`,
		"h2 sem akamai": `{"version":1,"measured":[` + strings.Replace(good, `"proto":"h1"`, `"proto":"h2"`, 1) + `]}`,
		"data":          `{"version":1,"measured":[` + strings.Replace(good, "2026-11-16T17:18:37Z", "ontem", 1) + `]}`,
		"json":          `{`,
	}
	for name, doc := range cases {
		if _, err := ParseKnownClients([]byte(doc)); err == nil {
			t.Errorf("%s: aceita", name)
		}
	}
}

// Um parser por formato, sobre as amostras de testdata.
func TestParsers(t *testing.T) {
	cases := []struct {
		format, file string
		entries      int
		in, out      []string
	}{
		{FormatGoogle, "google.json", 3, []string{"192.0.2.31", "2001:db8:4801:10::1", "198.51.100.127"}, []string{"192.0.2.32"}},
		{FormatAWS, "aws.json", 3, []string{"203.0.113.1", "2001:db8:aa12::1"}, []string{"203.0.114.1"}},
		{FormatAzure, "azure.json", 2, []string{"198.19.255.255", "2001:db8:a2::5"}, []string{"100.64.0.1"}},
		{FormatOracle, "oracle.json", 3, []string{"192.0.2.200", "2001:db8:c1::1", "198.51.100.1"}, []string{"192.0.2.1"}},
		{FormatCSV, "digitalocean.csv", 3, []string{"5.101.100.1", "2a03:b0c0:1::1"}, []string{"5.101.104.1"}},
		{FormatCloudflare, "cloudflare.json", 3, []string{"104.17.0.1", "2400:cb00::1"}, []string{"1.1.1.1"}},
	}
	for _, c := range cases {
		p, err := parse(c.format, readTestdata(t, c.file))
		if err != nil {
			t.Fatalf("%s: %v", c.format, err)
		}
		if p.entries != c.entries {
			t.Errorf("%s: entries %d, quer %d", c.format, p.entries, c.entries)
		}
		b := NewTreeBuilder()
		b.Add(c.format, p.prefixes)
		tr := b.Build()
		for _, ip := range c.in {
			if got := tr.Lookup(netip.MustParseAddr(ip)); len(got) != 1 {
				t.Errorf("%s: %s fora", c.format, ip)
			}
		}
		for _, ip := range c.out {
			if got := tr.Lookup(netip.MustParseAddr(ip)); len(got) != 0 {
				t.Errorf("%s: %s dentro", c.format, ip)
			}
		}
	}
}

// Formato errado é erro, não lista vazia.
func TestParsersInvalid(t *testing.T) {
	cases := map[string]string{
		FormatGoogle:     `{"prefixes":[{"ipv4Prefix":"999.0.0.0/8"}]}`,
		FormatAWS:        `{"syncToken":"1"}`,
		FormatAzure:      `<html>sem link</html>`,
		FormatOracle:     `{"regions":[{"cidrs":[{"cidr":"x"}]}]}`,
		FormatCSV:        "não,é,prefixo\n",
		FormatCloudflare: `{"success":false,"result":null}`,
		FormatJA4DB:      `{"não":"array"}`,
		"desconhecido":   `{}`,
	}
	for format, doc := range cases {
		if _, err := parse(format, []byte(doc)); err == nil {
			t.Errorf("%s: aceito", format)
		}
	}
	if _, err := parse(FormatGoogle, []byte(`{"creationTime":"x"}`)); err == nil {
		t.Error("google sem prefixes aceito")
	}
}

// Rótulos da ja4db sintética: navegador, biblioteca e aplicação; registro sem JA4 ignorado; repetido uma vez.
func TestParseJA4DB(t *testing.T) {
	p, err := parse(FormatJA4DB, readTestdata(t, "ja4db.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.entries != 4 {
		t.Errorf("entries %d", p.entries)
	}
	want := map[string]string{
		"t13d1516h2_8daaf6152771_02713d6af862": "browser",
		"t13d1812h1_85036bcba153_375ca2c5e164": "library",
		"t13d190900_9dc949149365_97f8aa674fd9": "application",
	}
	for ja4, kind := range want {
		ls := p.ja4[ja4]
		if len(ls) != 1 || ls[0].Kind != kind {
			t.Errorf("%s: %+v", ja4, ls)
		}
	}
}

// Link do JSON semanal na página de download da Azure.
func TestAzureLink(t *testing.T) {
	link, ok := azureLink(readTestdata(t, "azure_page.html"))
	if !ok || !strings.HasSuffix(link, "/ServiceTags_Public_20261109.json") {
		t.Fatalf("link %q %v", link, ok)
	}
	if _, ok := azureLink(readTestdata(t, "azure.json")); ok {
		t.Error("JSON tratado como página")
	}
}

// Árvore com IPv4, IPv6, IPv4 mapeado, prefixos aninhados e várias listas.
func TestTreeLookup(t *testing.T) {
	b := NewTreeBuilder()
	b.Add("a", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")})
	b.Add("b", []netip.Prefix{netip.MustParsePrefix("10.1.2.0/24"), netip.MustParsePrefix("::ffff:192.0.2.0/120")})
	b.Add("c", []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("2001:db8:1::5/128")})
	tr := b.Build()
	cases := map[string][]string{
		"10.1.2.3":          {"a", "b", "c"},
		"::ffff:10.1.2.3":   {"a", "b", "c"},
		"10.9.9.9":          {"a", "c"},
		"192.0.2.77":        {"b", "c"},
		"::ffff:192.0.2.77": {"b", "c"},
		"2001:db8:1::5":     {"a", "c"},
		"2001:db8:1::6":     {"a"},
		"2001:db9::1":       nil,
		"fe80::1%eth0":      nil,
		"2001:db8::1%eth0":  {"a"},
		"203.0.113.1":       {"c"},
	}
	for ip, want := range cases {
		got := tr.Lookup(netip.MustParseAddr(ip))
		if !slices.Equal(got, want) {
			t.Errorf("%s: %v, quer %v", ip, got, want)
		}
	}
	var nilTree *Tree
	if nilTree.Lookup(netip.MustParseAddr("10.0.0.1")) != nil {
		t.Error("árvore nil")
	}
	full := NewTreeBuilder()
	for i := range maxTreeLists {
		if !full.Add(string(rune('a'+i%26)), nil) {
			t.Fatal("teto cedo")
		}
	}
	if full.Add("extra", nil) {
		t.Error("passou do teto de listas")
	}
}

// O catálogo é só HTTPS, nomes únicos, robôs com nome e a ja4db fora do catálogo de IP.
func TestCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Catalog {
		if seen[s.Name] || checkURL(s.URL) != nil || (s.Kind == KindGoodBot) != (s.Robot != "") {
			t.Errorf("fonte inválida: %+v", s)
		}
		seen[s.Name] = true
		if !strings.HasPrefix(EnvKey(s.Name), "FS_BOT_LIST_") {
			t.Error(EnvKey(s.Name))
		}
	}
	if seen[JA4DBName] {
		t.Error("ja4db no catálogo de IP")
	}
	if len(Robots()) < 6 {
		t.Errorf("robôs %v", Robots())
	}
}
