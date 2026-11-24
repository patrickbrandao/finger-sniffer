package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// fakeIssuer emite certificados de uma CA própria do teste (nenhuma CA ACME é contatada) e conta as chamadas.
type fakeIssuer struct {
	t     *testing.T
	calls atomic.Int32
	caKey *ecdsa.PrivateKey
	ca    *x509.Certificate
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake acme ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &fakeIssuer{t: t, caKey: key, ca: ca}
}

func (f *fakeIssuer) IssuerKey() string { return "fake-ca" }

func (f *fakeIssuer) Issue(_ context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	n := f.calls.Add(1)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(100 + n)), DNSNames: csr.DNSNames,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca, csr.PublicKey, f.caKey)
	if err != nil {
		return nil, err
	}
	return &certmagic.IssuedCertificate{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// flakyStorage é um FS_ACME_DIR em memória cujo Store falha (como com o disco cheio) enquanto fail estiver ligado.
type flakyStorage struct {
	mu   sync.Mutex
	data map[string][]byte
	fail atomic.Bool
}

func newFlakyStorage() *flakyStorage { return &flakyStorage{data: map[string][]byte{}} }

func (s *flakyStorage) Load(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return slices.Clone(v), nil
}

func (s *flakyStorage) Store(_ context.Context, key string, value []byte) error {
	if s.fail.Load() {
		return errors.New("write: no space left on device")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = slices.Clone(value)
	return nil
}

func (s *flakyStorage) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data[key]
	return ok
}

// fakeACMEManager monta um gerenciador só com o certificado A, o emissor falso e o armazenamento em memória.
// ca só decide produção ou teste (isProductionCA): nenhuma chamada de rede é feita.
func fakeACMEManager(t *testing.T, ca string, iss *fakeIssuer, st *flakyStorage, metrics *service.Metrics) *ACMEManager {
	t.Helper()
	m, err := NewACMEManager(ACMEConfig{
		CA: ca, Dir: t.TempDir(), CertDir: t.TempDir(), NamesDNS01: testNamesDNS01,
		RetryMin: 20 * time.Millisecond, RetryMax: 40 * time.Millisecond,
	}, nil, nil, metrics)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	m.pairs = st
	for _, s := range m.slots {
		s.issuer = iss
	}
	return m
}

// TestACMEStoreFailureKeepsIssuedPair: emitido e não guardado (FS_ACME_DIR cheio), o par é exportado para
// FS_CERT_DIR e as rodadas seguintes do runSlot não emitem de novo; quando o Store volta, o par é guardado
// (task 351).
func TestACMEStoreFailureKeepsIssuedPair(t *testing.T) {
	iss, st, metrics := newFakeIssuer(t), newFlakyStorage(), service.NewMetrics()
	st.fail.Store(true)
	m := fakeACMEManager(t, "https://127.0.0.1:1/dir", iss, st, metrics)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, 10*time.Second, func() bool { return metrics.Get(MetricACMEFailures) >= 3 }, func() string {
		return fmt.Sprintf("failures %v", metrics.Get(MetricACMEFailures))
	})
	if n := iss.calls.Load(); n != 1 {
		t.Fatalf("Issue called %d times with Store failing, want 1", n)
	}
	exported := leafOf(t, m.cfg.CertDir, certs.SlotDNS01)
	if exported.SerialNumber.Int64() != 101 {
		t.Fatalf("exported serial %v", exported.SerialNumber)
	}

	st.fail.Store(false)
	s := m.slot(certs.SlotDNS01)
	waitFor(t, 10*time.Second, func() bool {
		return st.has(m.storageKey(s, ".crt")) && st.has(m.storageKey(s, ".key"))
	}, func() string { return "pair not stored after Store recovered" })
	crt, _ := st.Load(ctx, m.storageKey(s, ".crt"))
	if data, _ := os.ReadFile(filepath.Join(m.cfg.CertDir, certs.SlotDNS01+".crt")); string(data) != string(crt) {
		t.Fatal("stored pair differs from the exported one")
	}
	time.Sleep(200 * time.Millisecond) // mais rodadas, já com o par guardado
	if n := iss.calls.Load(); n != 1 {
		t.Fatalf("Issue called %d times, want 1", n)
	}
	if metrics.Get(MetricACMEIssued) != 1 {
		t.Fatalf("issued metric %v", metrics.Get(MetricACMEIssued))
	}
}

// TestACMEProductionIssueCap: com CA de produção, a 4ª emissão em 7 dias não chama Issue, conta a métrica e
// registra o motivo; o registro guardado vale para um novo processo; passada a janela, emite de novo. CA de
// teste não tem teto (task 351, spec 015 RF-06).
func TestACMEProductionIssueCap(t *testing.T) {
	// Endereço que nunca resolve: classificado como produção, sem rede (o emissor é o falso).
	const prodCA = "https://acme.example.invalid/directory"
	iss, st, metrics := newFakeIssuer(t), newFlakyStorage(), service.NewMetrics()
	m := fakeACMEManager(t, prodCA, iss, st, metrics)
	if !m.production {
		t.Fatal("CA not taken as production")
	}
	clock := time.Now()
	m.now = func() time.Time { return clock }
	ctx := context.Background()
	s := m.slot(certs.SlotDNS01)
	for i := range acmeProdIssueLimit {
		if _, err := m.issue(ctx, s); err != nil {
			t.Fatalf("issue %d: %v", i+1, err)
		}
		clock = clock.Add(time.Hour)
	}
	_, err := m.issue(ctx, s)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("4th issuance: %v", err)
	}
	if n := iss.calls.Load(); n != acmeProdIssueLimit {
		t.Fatalf("Issue called %d times, want %d", n, acmeProdIssueLimit)
	}
	if metrics.Get(MetricACMECapped) != 1 || !slices.Equal(m.Reasons(), []string{ReasonACMECapped + ":" + certs.SlotDNS01}) {
		t.Fatalf("capped metric %v reasons %v", metrics.Get(MetricACMECapped), m.Reasons())
	}
	// O motivo chega ao heartbeat do web como degraded (task 420).
	srv := NewServer(testConfig(t.TempDir()), Deps{ACMEReasons: m.Reasons})
	if st, r := srv.Status(); st != event.StatusDegraded || !slices.Contains(r, ReasonACMECapped+":"+certs.SlotDNS01) {
		t.Fatalf("status %q reasons %v", st, r)
	}

	// Novo processo, mesmo FS_ACME_DIR: o registro guardado mantém o teto.
	m2 := fakeACMEManager(t, prodCA, iss, st, service.NewMetrics())
	m2.now = func() time.Time { return clock }
	if _, err := m2.issue(ctx, m2.slot(certs.SlotDNS01)); err == nil {
		t.Fatal("restart ignored the issuance record")
	}
	if n := iss.calls.Load(); n != acmeProdIssueLimit {
		t.Fatalf("Issue called %d times after restart", n)
	}

	// Passados 7 dias da primeira emissão, uma nova é permitida e o motivo some.
	clock = clock.Add(acmeProdIssueWindow - 2*time.Hour)
	if _, err := m.issue(ctx, s); err != nil {
		t.Fatalf("after the window: %v", err)
	}
	if len(m.Reasons()) != 0 {
		t.Fatalf("reasons %v", m.Reasons())
	}
	if st, r := srv.Status(); st != event.StatusOK {
		t.Fatalf("status after the window %q reasons %v", st, r)
	}

	// CA de teste (loopback): sem teto.
	iss2 := newFakeIssuer(t)
	mt := fakeACMEManager(t, "https://127.0.0.1:14000/dir", iss2, newFlakyStorage(), nil)
	for i := range acmeProdIssueLimit + 2 {
		if _, err := mt.issue(ctx, mt.slot(certs.SlotDNS01)); err != nil {
			t.Fatalf("test CA issue %d: %v", i+1, err)
		}
	}
}

func TestIsProductionCA(t *testing.T) {
	for ca, want := range map[string]bool{
		"https://acme-v02.api.letsencrypt.org/directory":         true,
		"https://acme-staging-v02.api.letsencrypt.org/directory": false,
		"https://127.0.0.1:14000/dir":                            false,
		"https://[::1]:14000/dir":                                false,
		"https://localhost:14000/dir":                            false,
		"https://pebble.localhost/dir":                           false,
		"https://acme.zerossl.com/v2/DV90":                       true,
		"::not a url":                                            true,
		"":                                                       true,
	} {
		if got := isProductionCA(ca); got != want {
			t.Errorf("%q: %v, want %v", ca, got, want)
		}
	}
}
