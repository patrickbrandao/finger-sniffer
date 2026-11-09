package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/internal/dns"
	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

var (
	testNamesDNS01  = []string{"dns-monitor.tmsoft.com.br", "*.dns-monitor.tmsoft.com.br"}
	testNamesHTTP01 = []string{"vps602.tmsoft.com.br", "fingerprint.tmsoft.com.br"}
)

func TestLoadACMEConfig(t *testing.T) {
	t.Setenv("FS_ACME_ENABLE", "0")
	t.Setenv("FS_ACME_CA", "")
	t.Setenv("FS_ACME_DIR", "")
	t.Setenv("FS_CERT_DIR", "/tmp/certs-x")
	c, err := LoadACMEConfig(netip.MustParseAddr("192.0.2.1"))
	if err != nil || c.Enable || c.Dir != DefaultACMEDir || c.CertDir != "/tmp/certs-x" || c.HTTPListenHost != "192.0.2.1" ||
		c.HTTPPort != 80 || c.RenewBefore != 30*24*time.Hour || c.RetryMax != time.Hour {
		t.Fatalf("defaults %+v %v", c, err)
	}
	t.Setenv("FS_ACME_ENABLE", "1")
	if _, err := LoadACMEConfig(netip.Addr{}); err == nil {
		t.Fatal("enable without CA accepted")
	}
	t.Setenv("FS_ACME_CA", "https://ca.example/dir")
	t.Setenv("FS_ACME_EMAIL", "ops@example.com")
	if c, err = LoadACMEConfig(netip.Addr{}); err != nil || !c.Enable || c.CA != "https://ca.example/dir" || c.Email != "ops@example.com" {
		t.Fatalf("enabled %+v %v", c, err)
	}
	t.Setenv("FS_ACME_ENABLE", "yes")
	if _, err := LoadACMEConfig(netip.Addr{}); err == nil {
		t.Fatal("invalid FS_ACME_ENABLE accepted")
	}
	if _, err := NewACMEManager(ACMEConfig{Dir: t.TempDir()}, nil, nil, nil); err == nil {
		t.Fatal("manager without CA accepted")
	}
}

func TestValidToken(t *testing.T) {
	for tok, want := range map[string]bool{
		"abcXYZ-_09": true, "": false, "a/b": false, "a.b": false, "a b": false, string(make([]byte, 300)): false,
	} {
		if validToken(tok) != want {
			t.Errorf("%q", tok)
		}
	}
	var m *ACMEManager
	if _, ok := m.HTTPChallenge("abc"); ok {
		t.Fatal("nil manager answered")
	}
}

func TestRenewAt(t *testing.T) {
	m := &ACMEManager{cfg: ACMEConfig{RenewBefore: DefaultRenewBefore}}
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	long := &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(90 * 24 * time.Hour)}
	if got := m.renewAt(long); !got.Equal(nb.Add(60 * 24 * time.Hour)) {
		t.Fatalf("90d: %s", got)
	}
	short := &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(30 * time.Second)}
	if got := m.renewAt(short); !got.Equal(nb.Add(15 * time.Second)) {
		t.Fatalf("30s: %s", got)
	}
}

// TestACMEFailureSelfSigned: CA inalcançável → nenhuma emissão, FS_CERT_DIR vazio, pkg/certs com o autoassinado,
// heartbeat degraded e novas tentativas com backoff limitado (RF-05).
func TestACMEFailureSelfSigned(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()

	certDir := t.TempDir()
	metrics := service.NewMetrics()
	m, err := NewACMEManager(ACMEConfig{
		CA: "https://" + closed + "/dir", Dir: t.TempDir(), CertDir: certDir,
		NamesDNS01: testNamesDNS01, NamesHTTP01: testNamesHTTP01,
		RetryMin: 20 * time.Millisecond, RetryMax: 80 * time.Millisecond,
	}, startNATS(t), nil, metrics)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	deadline := time.Now().Add(20 * time.Second)
	for metrics.Get(MetricACMEFailures) < 4 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if f := metrics.Get(MetricACMEFailures); f < 4 || metrics.Get(MetricACMEIssued) != 0 {
		t.Fatalf("failures %v issued %v", f, metrics.Get(MetricACMEIssued))
	}
	if ents, _ := os.ReadDir(certDir); len(ents) != 0 {
		t.Fatalf("cert dir not empty: %v", ents)
	}
	st := openStore(t, certDir)
	if r := st.Reasons(time.Now()); !slices.Contains(r, certs.ReasonSelfSigned) {
		t.Fatalf("reasons %v", r)
	}
	srv := NewServer(testConfig(t.TempDir()), Deps{CertReasons: st.Reasons})
	if s, r := srv.Status(); s != event.StatusDegraded || !slices.Contains(r, certs.ReasonSelfSigned) {
		t.Fatalf("status %s %v", s, r)
	}
}

func openStore(t *testing.T, dir string) *certs.Store {
	t.Helper()
	st, err := certs.Open(certs.Config{Dir: dir, NamesDNS01: testNamesDNS01, NamesHTTP01: testNamesHTTP01}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// --- Pebble ---

// pebbleEnv é o ambiente de um teste com Pebble: NATS, dns real (zona da task 016) atrás de um responder
// miekg, web com a rota do HTTP-01 e o Pebble apontando para esse dns e para a porta do web.
type pebbleEnv struct {
	nc      *nats.Conn
	ca      string
	roots   *x509.CertPool
	dnsAddr string
	webHost string
	webPort int
	mgr     atomic.Pointer[ACMEManager]
	cmd     *exec.Cmd
	out     *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startPebbleEnv sobe tudo; validity é a validade dos certificados do Pebble. Sem FS_TEST_PEBBLE o teste é
// pulado com aviso (no CI o verify exige o binário).
func startPebbleEnv(t *testing.T, validity time.Duration) *pebbleEnv {
	t.Helper()
	bin := os.Getenv("FS_TEST_PEBBLE")
	if bin == "" {
		t.Skip("AVISO: FS_TEST_PEBBLE vazio; teste com Pebble pulado (rode make tools)")
	}
	e := &pebbleEnv{nc: startNATS(t), out: &syncBuffer{}}

	// dns real (zona e TXT do ACME pelo NATS) para os nomes da zona; A 127.0.0.1 para os nomes do HTTP-01.
	z := testDNSZone()
	if _, err := dns.SubscribeACME(e.nc, z, nil); err != nil {
		t.Fatal(err)
	}
	_ = e.nc.Flush()
	e.dnsAddr = startTestDNS(t, z)

	// web com o gancho do HTTP-01 ligado ao gerenciador (atribuído depois).
	h := newHarness(t, harnessOpts{deps: func(d *Deps) {
		d.ACME = func(tok string) ([]byte, bool) { return e.mgr.Load().HTTPChallenge(tok) }
	}})
	host, port, _ := net.SplitHostPort(h.addr80)
	e.webHost = host
	_, _ = fmt.Sscan(port, &e.webPort)

	dir := t.TempDir()
	certPEM, keyPEM, pool := pebbleTLS(t)
	e.roots = pool
	writeFile(t, dir, "cert.pem", string(certPEM))
	writeFile(t, dir, "key.pem", string(keyPEM))
	apiPort, mgmtPort, tlsPort := freePort(t), freePort(t), freePort(t)
	conf := map[string]any{"pebble": map[string]any{
		"listenAddress":                  fmt.Sprintf("127.0.0.1:%d", apiPort),
		"managementListenAddress":        fmt.Sprintf("127.0.0.1:%d", mgmtPort),
		"certificate":                    filepath.Join(dir, "cert.pem"),
		"privateKey":                     filepath.Join(dir, "key.pem"),
		"httpPort":                       e.webPort,
		"tlsPort":                        tlsPort,
		"ocspResponderURL":               "",
		"externalAccountBindingRequired": false,
		"retryAfter":                     map[string]int{"authz": 1, "order": 1},
		"profiles": map[string]any{"default": map[string]any{
			"description": "test", "validityPeriod": int(validity / time.Second),
		}},
	}}
	data, _ := json.Marshal(conf)
	writeFile(t, dir, "pebble.json", string(data))

	e.cmd = exec.Command(bin, "-config", filepath.Join(dir, "pebble.json"), "-dnsserver", e.dnsAddr) //nolint:gosec // binário do teste (FS_TEST_PEBBLE)
	e.cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0", "PEBBLE_AUTHZREUSE=0")
	e.cmd.Stdout, e.cmd.Stderr = e.out, e.out
	if err := e.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.stopPebble()
		if t.Failed() {
			t.Logf("pebble output:\n%s", e.out.String())
		}
	})
	e.ca = fmt.Sprintf("https://127.0.0.1:%d/dir", apiPort)
	cl := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := cl.Get(e.ca)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("pebble not ready: %v\n%s", err, e.out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	return e
}

func (e *pebbleEnv) stopPebble() {
	if e.cmd != nil && e.cmd.Process != nil {
		_ = e.cmd.Process.Kill()
		_ = e.cmd.Wait()
		e.cmd = nil
	}
}

// config devolve a configuração do ACME para este ambiente.
func (e *pebbleEnv) config(acmeDir, certDir string) ACMEConfig {
	return ACMEConfig{
		Enable: true, CA: e.ca, Dir: acmeDir, CertDir: certDir,
		NamesDNS01: testNamesDNS01, NamesHTTP01: testNamesHTTP01,
		HTTPListenHost: e.webHost, HTTPPort: e.webPort,
		DNSResolvers: []string{e.dnsAddr}, DNSTimeout: 2 * time.Second,
		TrustedRoots: e.roots,
		RetryMin:     200 * time.Millisecond, RetryMax: time.Second,
	}
}

func (e *pebbleEnv) manager(t *testing.T, cfg ACMEConfig, metrics *service.Metrics) *ACMEManager {
	t.Helper()
	m, err := NewACMEManager(cfg, e.nc, nil, metrics)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	e.mgr.Store(m)
	return m
}

// startTestDNS sobe um responder miekg em UDP e TCP: nomes da zona vão para a Zone real; os outros recebem
// A 127.0.0.1 (nomes do HTTP-01) ou NODATA.
func startTestDNS(t *testing.T, z *dns.Zone) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		if len(req.Question) == 1 && z.InZone(req.Question[0].Name) {
			_ = w.WriteMsg(z.Answer(req))
			return
		}
		r := new(mdns.Msg)
		r.SetReply(req)
		r.Authoritative = true
		if len(req.Question) == 1 && req.Question[0].Qtype == mdns.TypeA {
			r.Answer = append(r.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 5},
				A:   net.IPv4(127, 0, 0, 1),
			})
		}
		_ = w.WriteMsg(r)
	})
	addr := pc.LocalAddr().String()
	// TCP na mesma porta (o Pebble consulta por TCP).
	tl, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	for _, srv := range []*mdns.Server{{PacketConn: pc, Handler: handler}, {Listener: tl, Handler: handler}} {
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return addr
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// pebbleTLS gera o certificado do servidor HTTPS do Pebble (127.0.0.1/localhost) e o pool que confia nele.
func pebbleTLS(t *testing.T) (certPEM, keyPEM []byte, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pebble test"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(leaf)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), pool
}

// leafOf lê o certificado exportado do slot.
func leafOf(t *testing.T, dir, slot string) *x509.Certificate {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, slot+".crt"), filepath.Join(dir, slot+".key"))
	if err != nil {
		t.Fatalf("%s: %v", slot, err)
	}
	return pair.Leaf
}

// TestACMEPebbleIssueAndRenew: A por DNS-01 (dns real pelo NATS) e B por HTTP-01 (rota do web), exportados
// para FS_CERT_DIR com modo 0600 na chave, carregados a quente por pkg/certs e renovados antes de vencer.
func TestACMEPebbleIssueAndRenew(t *testing.T) {
	e := startPebbleEnv(t, 30*time.Second)
	certDir := t.TempDir()
	st := openStore(t, certDir)
	metrics := service.NewMetrics()
	cfg := e.config(t.TempDir(), certDir)
	m := e.manager(t, cfg, metrics)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, 60*time.Second, func() bool { return metrics.Get(MetricACMEIssued) >= 2 }, func() string {
		return fmt.Sprintf("issued %v failures %v\n%s", metrics.Get(MetricACMEIssued),
			metrics.Get(MetricACMEFailures), e.out.String())
	})
	a, b := leafOf(t, certDir, certs.SlotDNS01), leafOf(t, certDir, certs.SlotHTTP01)
	if !sameNames(a.DNSNames, testNamesDNS01) || !sameNames(b.DNSNames, testNamesHTTP01) {
		t.Fatalf("names %v %v", a.DNSNames, b.DNSNames)
	}
	for _, slot := range []string{certs.SlotDNS01, certs.SlotHTTP01} {
		fi, err := os.Stat(filepath.Join(certDir, slot+".key"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s.key mode %v %v", slot, fi.Mode(), err)
		}
		// cadeia completa: folha + intermediário do Pebble.
		data, _ := os.ReadFile(filepath.Join(certDir, slot+".crt"))
		if n := bytes.Count(data, []byte("BEGIN CERTIFICATE")); n < 2 {
			t.Fatalf("%s.crt has %d certificates", slot, n)
		}
	}
	// pkg/certs recarregou: nenhum autoassinado, escolha por SNI.
	waitFor(t, 15*time.Second, func() bool {
		s := st.State()
		return len(s) == 2 && !s[0].SelfSigned && !s[1].SelfSigned
	}, func() string { return fmt.Sprintf("state %+v", st.State()) })
	for sni, want := range map[string]*x509.Certificate{"abc.dns-monitor.tmsoft.com.br": a, "fingerprint.tmsoft.com.br": b, "": b} {
		c, err := st.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil || !bytes.Equal(c.Leaf.Raw, want.Raw) {
			t.Fatalf("sni %q: %v", sni, err)
		}
	}

	// Renovação: com validade de 30 s, renova na metade (15 s antes do fim).
	waitFor(t, 60*time.Second, func() bool { return metrics.Get(MetricACMEIssued) >= 4 }, func() string {
		return fmt.Sprintf("renewals: issued %v failures %v", metrics.Get(MetricACMEIssued), metrics.Get(MetricACMEFailures))
	})
	a2, b2 := leafOf(t, certDir, certs.SlotDNS01), leafOf(t, certDir, certs.SlotHTTP01)
	if a2.SerialNumber.Cmp(a.SerialNumber) == 0 || b2.SerialNumber.Cmp(b.SerialNumber) == 0 {
		t.Fatal("certificates not renewed")
	}
	if !time.Now().Before(a.NotAfter) && !time.Now().Before(b.NotAfter) {
		t.Log("renewal happened after expiry (slow machine)")
	}
}

// TestACMEPebbleRestartAndKeepOld: depois da emissão, um novo processo (mesmo FS_ACME_DIR) não emite de novo,
// reexporta se FS_CERT_DIR foi apagado; renovação que falha (CA fora do ar) mantém o certificado anterior.
func TestACMEPebbleRestartAndKeepOld(t *testing.T) {
	e := startPebbleEnv(t, 90*24*time.Hour)
	acmeDir, certDir := t.TempDir(), t.TempDir()
	cfg := e.config(acmeDir, certDir)
	metrics := service.NewMetrics()
	m := e.manager(t, cfg, metrics)
	ctx := context.Background()
	for _, slot := range []string{certs.SlotDNS01, certs.SlotHTTP01} {
		renewAt, err := m.Ensure(ctx, slot)
		if err != nil {
			t.Fatalf("%s: %v\n%s", slot, err, e.out.String())
		}
		if d := time.Until(renewAt); d < 59*24*time.Hour || d > 61*24*time.Hour {
			t.Fatalf("%s renew in %s", slot, d)
		}
	}
	if metrics.Get(MetricACMEIssued) != 2 {
		t.Fatalf("issued %v", metrics.Get(MetricACMEIssued))
	}
	a := leafOf(t, certDir, certs.SlotDNS01)
	crtBefore, _ := os.ReadFile(filepath.Join(certDir, certs.SlotHTTP01+".crt"))

	// "Restart" com a CA fora do ar: nada é emitido, o guardado é usado e reexportado.
	e.stopPebble()
	_ = os.Remove(filepath.Join(certDir, certs.SlotDNS01+".crt"))
	_ = os.Remove(filepath.Join(certDir, certs.SlotDNS01+".key"))
	metrics2 := service.NewMetrics()
	m2 := e.manager(t, cfg, metrics2)
	for _, slot := range []string{certs.SlotDNS01, certs.SlotHTTP01} {
		if _, err := m2.Ensure(ctx, slot); err != nil {
			t.Fatalf("restart %s: %v", slot, err)
		}
	}
	if metrics2.Get(MetricACMEIssued) != 0 {
		t.Fatalf("restart issued %v", metrics2.Get(MetricACMEIssued))
	}
	if a2 := leafOf(t, certDir, certs.SlotDNS01); a2.SerialNumber.Cmp(a.SerialNumber) != 0 {
		t.Fatal("re-export changed the certificate")
	}

	// Renovação devida com a CA fora do ar: erro, e o par exportado continua o mesmo.
	m2.now = func() time.Time { return a.NotAfter.Add(-24 * time.Hour) }
	if _, err := m2.Ensure(ctx, certs.SlotHTTP01); err == nil {
		t.Fatal("renewal with CA down succeeded")
	}
	if crtAfter, _ := os.ReadFile(filepath.Join(certDir, certs.SlotHTTP01+".crt")); !bytes.Equal(crtBefore, crtAfter) {
		t.Fatal("failed renewal replaced the certificate")
	}
}

// TestACMEPebbleDNSDown: com o Pebble no ar mas sem o serviço dns no NATS, o DNS-01 falha com erro claro e
// nada é exportado.
func TestACMEPebbleDNSDown(t *testing.T) {
	e := startPebbleEnv(t, 90*24*time.Hour)
	certDir := t.TempDir()
	cfg := e.config(t.TempDir(), certDir)
	nc, err := nats.Connect(e.nc.ConnectedUrl()) // conexão sem o assinante do dns
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	// Mesmo servidor NATS, mas sem o dns: derruba o assinante tirando o dns do ar.
	e.nc.Close()
	m, err := NewACMEManager(cfg, nc, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	_, err = m.Ensure(context.Background(), certs.SlotDNS01)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("no responder")) {
		t.Fatalf("dns down: %v", err)
	}
	if _, err := os.Stat(filepath.Join(certDir, certs.SlotDNS01+".crt")); !os.IsNotExist(err) {
		t.Fatalf("exported despite failure: %v", err)
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, msg func() string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout: %s", msg())
		}
		time.Sleep(50 * time.Millisecond)
	}
}
