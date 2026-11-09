package certs

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestSlotFor(t *testing.T) {
	s := &Store{cfg: testConfig("")}
	for sni, want := range map[string]string{
		"dns-monitor.tmsoft.com.br":               SlotDNS01,
		"x.dns-monitor.tmsoft.com.br":             SlotDNS01,
		"ABCDEFGH.DNS-MONITOR.tmsoft.com.br.":     SlotDNS01,
		"abcdefgh.noh3.dns-monitor.tmsoft.com.br": SlotDNS01,
		"vps602.tmsoft.com.br":                    SlotHTTP01,
		"unknown.example":                         SlotHTTP01,
		"xdns-monitor.tmsoft.com.br":              SlotHTTP01,
		"":                                        SlotHTTP01,
	} {
		if got := s.SlotFor(sni); got != want {
			t.Errorf("SlotFor(%q) = %s, quer %s", sni, got, want)
		}
	}
}

func writeBoth(t *testing.T, dir string, notAfter time.Time) {
	t.Helper()
	crt, key := genPair(t, "cert-A", []string{"dns-monitor.tmsoft.com.br", "*.dns-monitor.tmsoft.com.br"}, notAfter)
	if err := WritePair(dir, SlotDNS01, crt, key); err != nil {
		t.Fatal(err)
	}
	crt, key = genPair(t, "cert-B", SplitNames(DefaultNamesHTTP01), notAfter)
	if err := WritePair(dir, SlotHTTP01, crt, key); err != nil {
		t.Fatal(err)
	}
}

func TestSNISelection(t *testing.T) {
	dir := t.TempDir()
	writeBoth(t, dir, time.Now().Add(60*24*time.Hour))
	s := openStore(t, testConfig(dir))
	addr := echoServer(t, s.TLSConfig())
	for sni, want := range map[string]string{
		"x.dns-monitor.tmsoft.com.br": "cert-A",
		"dns-monitor.tmsoft.com.br":   "cert-A",
		"vps602.tmsoft.com.br":        "cert-B",
		"desconhecido.example":        "cert-B",
		"":                            "cert-B",
	} {
		c, cn := dial(t, addr, sni, nil)
		_ = c.Close()
		if cn != want {
			t.Errorf("sni %q: %s, quer %s", sni, cn, want)
		}
	}
	if r := s.Reasons(time.Now()); len(r) != 0 {
		t.Errorf("Reasons = %v", r)
	}
	st := s.State()
	if len(st) != 2 || st[0].Issuer != "cert-A" || st[1].Issuer != "cert-B" || st[0].SelfSigned ||
		!slices.Contains(st[0].Names, "*.dns-monitor.tmsoft.com.br") {
		t.Fatalf("State = %+v", st)
	}
}

func TestSelfSignedWhenMissing(t *testing.T) {
	cfg := testConfig(filepath.Join(t.TempDir(), "nao-existe"))
	s := openStore(t, cfg)
	addr := echoServer(t, s.TLSConfig())
	for _, sni := range []string{"x.dns-monitor.tmsoft.com.br", "vps602.tmsoft.com.br", ""} {
		c, cn := dial(t, addr, sni, nil)
		_ = c.Close()
		if cn != SelfSignedIssuer {
			t.Errorf("sni %q: %s", sni, cn)
		}
	}
	st := s.State()
	if len(st) != 1 || !st[0].SelfSigned || st[0].Issuer != SelfSignedIssuer {
		t.Fatalf("State = %+v", st)
	}
	all := append(append([]string(nil), cfg.NamesDNS01...), cfg.NamesHTTP01...)
	if !slices.Equal(st[0].Names, all) {
		t.Errorf("nomes do autoassinado: %v", st[0].Names)
	}
	if r := s.Reasons(time.Now()); !slices.Equal(r, []string{ReasonSelfSigned}) {
		t.Errorf("Reasons = %v", r)
	}
}

// TestPartialMissing: só o B existe → A é o autoassinado; só falta a chave do A → idem.
func TestPartialMissing(t *testing.T) {
	dir := t.TempDir()
	writeBoth(t, dir, time.Now().Add(60*24*time.Hour))
	if err := os.Remove(filepath.Join(dir, "dns01.key")); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, testConfig(dir))
	st := s.State()
	if len(st) != 2 || !st[0].SelfSigned || st[1].SelfSigned || st[1].Issuer != "cert-B" {
		t.Fatalf("State = %+v", st)
	}
}

func TestReasonsExpiring(t *testing.T) {
	dir := t.TempDir()
	writeBoth(t, dir, time.Now().Add(10*24*time.Hour))
	s := openStore(t, testConfig(dir))
	if r := s.Reasons(time.Now()); !slices.Equal(r, []string{ReasonExpiring}) {
		t.Errorf("Reasons = %v", r)
	}
	if r := s.Reasons(time.Now().Add(-30 * 24 * time.Hour)); len(r) != 0 {
		t.Errorf("Reasons no passado = %v", r)
	}
}

// waitCN espera até um novo handshake receber o CN esperado.
func waitCN(t *testing.T, addr, sni, want string, limit time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	for {
		c, cn := dial(t, addr, sni, nil)
		_ = c.Close()
		if cn == want {
			return time.Since(start)
		}
		if time.Since(start) > limit {
			t.Fatalf("depois de %v ainda recebo %s, quer %s", limit, cn, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestHotReload: trocar http01.{crt,key} vale para novos handshakes em ≤ 2 s sem derrubar conexão aberta.
func TestHotReload(t *testing.T) {
	dir := t.TempDir()
	writeBoth(t, dir, time.Now().Add(60*24*time.Hour))
	s := openStore(t, testConfig(dir))
	addr := echoServer(t, s.TLSConfig())

	old, cn := dial(t, addr, "vps602.tmsoft.com.br", nil)
	defer func() { _ = old.Close() }()
	if cn != "cert-B" {
		t.Fatalf("inicial: %s", cn)
	}
	echo(t, old, "antes")

	crt, key := genPair(t, "cert-B2", SplitNames(DefaultNamesHTTP01), time.Now().Add(80*24*time.Hour))
	if err := WritePair(dir, SlotHTTP01, crt, key); err != nil {
		t.Fatal(err)
	}
	took := waitCN(t, addr, "vps602.tmsoft.com.br", "cert-B2", 2*time.Second)
	t.Logf("troca refletida em %v", took)
	echo(t, old, "depois") // a conexão antiga segue viva
	if st := s.State(); st[1].Issuer != "cert-B2" {
		t.Fatalf("State = %+v", st)
	}

	// Remover o par volta ao autoassinado; recolocar volta ao arquivo.
	_ = os.Remove(filepath.Join(dir, "http01.crt"))
	waitCN(t, addr, "", SelfSignedIssuer, 2*time.Second)
	if err := WritePair(dir, SlotHTTP01, crt, key); err != nil {
		t.Fatal(err)
	}
	waitCN(t, addr, "", "cert-B2", 2*time.Second)
}

// TestInconsistentPair: chave nova com certificado velho (troca em momentos diferentes) mantém o anterior até o
// par ficar consistente.
func TestInconsistentPair(t *testing.T) {
	dir := t.TempDir()
	writeBoth(t, dir, time.Now().Add(60*24*time.Hour))
	s := openStore(t, testConfig(dir))
	addr := echoServer(t, s.TLSConfig())

	crt, key := genPair(t, "cert-B3", SplitNames(DefaultNamesHTTP01), time.Now().Add(80*24*time.Hour))
	if err := writeAtomic(dir, "http01.key", key, 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * debounce)
	if _, err := s.Reload(); err == nil {
		t.Fatal("par inconsistente aceito")
	}
	if c, cn := dial(t, addr, "", nil); cn != "cert-B" {
		_ = c.Close()
		t.Fatalf("durante a troca: %s", cn)
	} else {
		_ = c.Close()
	}
	if err := writeAtomic(dir, "http01.crt", crt, 0o644); err != nil {
		t.Fatal(err)
	}
	waitCN(t, addr, "", "cert-B3", 2*time.Second)
}

// TestInvalidAtStart: par inválido na primeira leitura serve o autoassinado e relê quando o par é corrigido.
func TestInvalidAtStart(t *testing.T) {
	dir := t.TempDir()
	if err := WritePair(dir, SlotHTTP01, []byte("lixo"), []byte("lixo")); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, testConfig(dir))
	addr := echoServer(t, s.TLSConfig())
	if c, cn := dial(t, addr, "", nil); cn != SelfSignedIssuer {
		t.Fatalf("inicial: %s", cn)
	} else {
		_ = c.Close()
	}
	crt, key := genPair(t, "cert-B", SplitNames(DefaultNamesHTTP01), time.Now().Add(80*24*time.Hour))
	if err := WritePair(dir, SlotHTTP01, crt, key); err != nil {
		t.Fatal(err)
	}
	waitCN(t, addr, "", "cert-B", 2*time.Second)
}

func TestGetCertificateEmpty(t *testing.T) {
	s := &Store{cfg: testConfig(""), entries: map[string]*entry{}}
	if _, err := s.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("sem certificado deveria falhar")
	}
	if err := (&Store{stop: make(chan struct{})}).Close(); err != nil {
		t.Fatal(err)
	}
}
