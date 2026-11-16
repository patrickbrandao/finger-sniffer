package rules

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// knownClientsPath é a base própria do tester (spec 018), lida pelo teste sem cópia.
var knownClientsPath = filepath.Join("..", "lists", "known_clients.json")

// knownEntry é uma medida de known_clients.json (formato da spec 018).
type knownEntry struct {
	Client        string   `json:"client"`
	ClientVersion string   `json:"client_version"`
	OS            string   `json:"os"`
	Proto         string   `json:"proto"`
	JA4           *string  `json:"ja4"`
	JA4R          *string  `json:"ja4_r"`
	Akamai        *string  `json:"akamai"`
	JA4HAB        *string  `json:"ja4h_ab"`
	JA4T          *string  `json:"ja4t"`
	P0fOS         *string  `json:"p0f_os"`
	TTLInitial    *int     `json:"ttl_initial"`
	ALPN          []string `json:"alpn"`
}

type knownFile struct {
	Version  int          `json:"version"`
	Measured []knownEntry `json:"measured"`
}

func loadKnownClients(t testing.TB) knownFile {
	t.Helper()
	raw, err := os.ReadFile(knownClientsPath)
	if err != nil {
		t.Fatal(err)
	}
	var f knownFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || len(f.Measured) == 0 {
		t.Fatalf("known_clients.json: versão %d com %d medidas", f.Version, len(f.Measured))
	}
	return f
}

// entry devolve a medida do cliente e protocolo.
func (f knownFile) entry(t testing.TB, client, proto string) knownEntry {
	t.Helper()
	for _, e := range f.Measured {
		if e.Client == client && e.Proto == proto {
			return e
		}
	}
	t.Fatalf("known_clients.json sem %s/%s", client, proto)
	return knownEntry{}
}

// fakeKnown implementa KnownClients sobre as medidas (a implementação real é da task 278).
type fakeKnown struct{ entries []knownEntry }

func fieldOf(e knownEntry, kind FPKind) string {
	var p *string
	switch kind {
	case KindJA4:
		p = e.JA4
	case KindAkamai:
		p = e.Akamai
	case KindJA4HAB:
		p = e.JA4HAB
	case KindJA4T:
		p = e.JA4T
	}
	if p == nil {
		return ""
	}
	return *p
}

func addUnique(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

func (k fakeKnown) Families(kind FPKind, value string) []string {
	var out []string
	for _, e := range k.entries {
		if value != "" && fieldOf(e, kind) == value {
			out = addUnique(out, e.Client)
		}
	}
	return out
}

func (k fakeKnown) Measured(family string, kind FPKind) bool {
	for _, e := range k.entries {
		if e.Client == family && fieldOf(e, kind) != "" {
			return true
		}
	}
	return false
}

func (k fakeKnown) Coherent(ja4, akamai, ja4t string) []string {
	var out []string
	for _, e := range k.entries {
		if (ja4 == "" || fieldOf(e, KindJA4) == ja4) && (akamai == "" || fieldOf(e, KindAkamai) == akamai) &&
			(ja4t == "" || fieldOf(e, KindJA4T) == ja4t) {
			out = addUnique(out, e.Client)
		}
	}
	return out
}

// fakeIPs implementa IPLists com prefixos fixos.
type fakeIPs struct {
	cloud   map[netip.Prefix]string
	crawler map[netip.Prefix]string
}

func lookup(m map[netip.Prefix]string, ip netip.Addr) (string, bool) {
	for p, v := range m {
		if p.Contains(ip) {
			return v, true
		}
	}
	return "", false
}

func (f fakeIPs) Cloud(ip netip.Addr) (string, bool)   { return lookup(f.cloud, ip) }
func (f fakeIPs) Crawler(ip netip.Addr) (string, bool) { return lookup(f.crawler, ip) }

// fakeVerifier devolve um resultado fixo por IP (VerifyUnknown para os outros).
type fakeVerifier map[netip.Addr]Verification

func (f fakeVerifier) Verified(ip netip.Addr, _ string) Verification { return f[ip] }

// fakeJA4DB lê a amostra sintética de testdata (nunca a ja4db real, ADR 0050 item 2).
type fakeJA4DB map[string]JA4DBLabel

func (f fakeJA4DB) Label(ja4 string) (JA4DBLabel, bool) {
	l, ok := f[ja4]
	return l, ok
}

func loadJA4DBSample(t testing.TB) fakeJA4DB {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "ja4db_sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		JA4  string `json:"ja4"`
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	db := fakeJA4DB{}
	for _, r := range rows {
		db[r.JA4] = JA4DBLabel{Name: r.Name, Kind: r.Kind}
	}
	return db
}

// Endereços de documentação (RFC 5737) e uma faixa publicada do Googlebot para as listas falsas.
var (
	ipResidential = netip.MustParseAddr("192.0.2.10")
	ipCloud       = netip.MustParseAddr("203.0.113.40")
	ipFakeGoogle  = netip.MustParseAddr("198.51.100.23")
	ipGooglebot   = netip.MustParseAddr("66.249.66.1")
	ipBingbot     = netip.MustParseAddr("157.55.39.10")
)

func testIPs() fakeIPs {
	return fakeIPs{
		cloud: map[netip.Prefix]string{netip.MustParsePrefix("203.0.113.0/24"): "aws"},
		crawler: map[netip.Prefix]string{
			netip.MustParsePrefix("66.249.64.0/19"): OperatorGoogle,
			netip.MustParsePrefix("157.55.39.0/24"): OperatorBing,
		},
	}
}

func testVerifier() fakeVerifier {
	return fakeVerifier{ipGooglebot: VerifyPassed, ipBingbot: VerifyFailed, ipFakeGoogle: VerifyFailed}
}
