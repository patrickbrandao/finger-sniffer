package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Padrões do ACME (spec 015).
const (
	DefaultACMEDir = "/finger-sniffer/var/acme"
	// DefaultRenewBefore é a antecedência da renovação (RF-05: 30 dias antes).
	DefaultRenewBefore = 30 * 24 * time.Hour
	// DefaultACMERetryMin e DefaultACMERetryMax são o backoff das falhas (RF-05: até 1 h). O mínimo de 5 min
	// deixa no máximo ~5 tentativas na primeira hora, abaixo do limite de validações falhas do Let's Encrypt.
	DefaultACMERetryMin = 5 * time.Minute
	DefaultACMERetryMax = time.Hour
	// DefaultACMEStartDelay espera os listeners do web abrirem (a porta 80 serve o HTTP-01) antes da primeira
	// emissão.
	DefaultACMEStartDelay = 5 * time.Second
	// acmeRSABits é o tamanho da chave dos certificados: RSA para que as cifras legadas com troca de chaves RSA
	// continuem negociáveis com clientes antigos (spec 008 RF-06), como no autoassinado de pkg/certs.
	acmeRSABits = 2048
	// acmeStoragePrefix é a pasta, dentro de FS_ACME_DIR, dos certificados A e B emitidos (por CA).
	acmeStoragePrefix = "finger-sniffer"
)

// Métricas do ACME.
const (
	MetricACMEIssued   = "web_acme_issued_total"
	MetricACMEFailures = "web_acme_failures_total"
)

// ACMEConfig é a configuração do ACME do web (spec 015).
type ACMEConfig struct {
	// Enable liga o ACME (FS_ACME_ENABLE=1, RF-01). Desligado, o web usa só FS_CERT_DIR ou o autoassinado.
	Enable bool
	// Dir é o estado do certmagic: conta, chaves e certificados (FS_ACME_DIR, RF-04).
	Dir string
	// CA é o diretório ACME (FS_ACME_CA); obrigatório quando Enable (nunca há CA padrão no código).
	CA string
	// Email é o contato da conta (FS_ACME_EMAIL, opcional).
	Email string
	// CertDir é para onde os certificados são exportados (FS_CERT_DIR).
	CertDir string
	// NamesDNS01 e NamesHTTP01 são os nomes dos certificados A e B (FS_CERT_NAMES_DNS01/HTTP01).
	NamesDNS01  []string
	NamesHTTP01 []string
	// HTTPListenHost e HTTPPort são onde o HTTP-01 é atendido: o IP e a porta 80 do próprio web. O certmagic
	// tenta abrir esse endereço; como o web já o ocupa, ele conclui que outro servidor responde o desafio.
	HTTPListenHost string
	HTTPPort       int
	// DNSResolvers são os resolvedores usados pelo certmagic no DNS-01 para achar a zona (SOA); vazio = os do
	// sistema.
	DNSResolvers []string
	// DNSTimeout é a espera pela resposta do dns a cada set/clear.
	DNSTimeout time.Duration
	// TrustedRoots são as raízes aceitas no TLS com a CA (testes com Pebble); nil = as do sistema.
	TrustedRoots *x509.CertPool
	// RenewBefore, RetryMin, RetryMax e StartDelay são os tempos de renovação, backoff e partida.
	RenewBefore time.Duration
	RetryMin    time.Duration
	RetryMax    time.Duration
	StartDelay  time.Duration
}

// LoadACMEConfig lê FS_ACME_* e os nomes/pasta de pkg/certs. listen é o IP público do web (para o HTTP-01).
func LoadACMEConfig(listen netip.Addr) (ACMEConfig, error) {
	cc := certs.LoadConfig()
	c := ACMEConfig{
		Dir:         service.Env("FS_ACME_DIR", DefaultACMEDir),
		CA:          strings.TrimSpace(service.Env("FS_ACME_CA", "")),
		Email:       strings.TrimSpace(service.Env("FS_ACME_EMAIL", "")),
		CertDir:     cc.Dir,
		NamesDNS01:  cc.NamesDNS01,
		NamesHTTP01: cc.NamesHTTP01,
		HTTPPort:    80,
		DNSTimeout:  DefaultACMEDNSTimeout,
		RenewBefore: DefaultRenewBefore,
		RetryMin:    DefaultACMERetryMin,
		RetryMax:    DefaultACMERetryMax,
		StartDelay:  DefaultACMEStartDelay,
	}
	if listen.IsValid() {
		c.HTTPListenHost = listen.String()
	}
	switch v := strings.TrimSpace(service.Env("FS_ACME_ENABLE", "0")); v {
	case "0", "false", "":
	case "1", "true":
		c.Enable = true
	default:
		return c, fmt.Errorf("web: FS_ACME_ENABLE must be 0 or 1, got %q", v)
	}
	if c.Enable && c.CA == "" {
		return c, errors.New("web: FS_ACME_ENABLE=1 needs FS_ACME_CA")
	}
	return c, nil
}

// acmeSlot é um dos dois certificados gerenciados.
type acmeSlot struct {
	name   string // certs.SlotDNS01 ou certs.SlotHTTP01
	names  []string
	issuer *certmagic.ACMEIssuer
}

// ACMEManager emite e renova os certificados A (DNS-01) e B (HTTP-01) com o certmagic e os exporta para
// FS_CERT_DIR (spec 015 RF-02..RF-05).
//
// O certmagic gerencia um certificado por nome; a spec quer um certificado por grupo de nomes (A com o apex e o
// curinga, B com os quatro nomes), com arquivos fixos. Por isso usamos dele a conta, o armazenamento, os solvers
// e a emissão (ACMEIssuer.Issue com um CSR de vários nomes), e o ciclo de renovação é nosso: renova
// RenewBefore antes de vencer (no máximo um terço da validade, para certificados curtos), mantém o anterior em
// falha e tenta de novo com backoff até RetryMax.
type ACMEManager struct {
	cfg     ACMEConfig
	log     *slog.Logger
	metrics *service.Metrics
	now     func() time.Time

	storage *certmagic.FileStorage
	cache   *certmagic.Cache
	slots   []*acmeSlot

	// issueMu serializa as emissões (A e B dividem a mesma conta ACME).
	issueMu sync.Mutex
}

// NewACMEManager prepara o certmagic. nc é a conexão NATS usada pelo provedor DNS-01.
func NewACMEManager(cfg ACMEConfig, nc natsRequester, log *slog.Logger, metrics *service.Metrics) (*ACMEManager, error) {
	if cfg.CA == "" {
		// O certmagic cairia no Let's Encrypt de produção: aqui a CA é sempre explícita (RF-06).
		return nil, errors.New("web: acme: CA is empty")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if metrics == nil {
		metrics = service.NewMetrics()
	}
	if cfg.RenewBefore <= 0 {
		cfg.RenewBefore = DefaultRenewBefore
	}
	if cfg.RetryMin <= 0 {
		cfg.RetryMin = DefaultACMERetryMin
	}
	if cfg.RetryMax < cfg.RetryMin {
		cfg.RetryMax = max(cfg.RetryMin, DefaultACMERetryMax)
	}
	if cfg.HTTPPort <= 0 {
		cfg.HTTPPort = 80
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("web: acme: %w", err)
	}
	m := &ACMEManager{
		cfg: cfg, log: log, metrics: metrics, now: time.Now,
		storage: &certmagic.FileStorage{Path: cfg.Dir},
	}

	var cmCfg *certmagic.Config
	m.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return cmCfg, nil },
	})
	cmCfg = certmagic.New(m.cache, certmagic.Config{Storage: m.storage})

	base := certmagic.ACMEIssuer{
		CA:                      cfg.CA,
		TestCA:                  cfg.CA, // sem troca automática para outra CA em novas tentativas
		Email:                   cfg.Email,
		Agreed:                  true,
		DisableTLSALPNChallenge: true,
		// O desafio fica só na memória deste processo (um único web atende a porta 80).
		DisableDistributedSolvers: true,
		TrustedRoots:              cfg.TrustedRoots,
	}

	dnsTmpl := base
	dnsTmpl.DisableHTTPChallenge = true
	dnsTmpl.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
		DNSProvider: &natsDNSProvider{nc: nc, timeout: cfg.DNSTimeout},
		Resolvers:   cfg.DNSResolvers,
		// Sem conferência de propagação: o nosso dns é o único autoritativo da zona e só responde ok ao set
		// depois de o TXT estar no ar. A conferência do certmagic resolveria o NS pelo resolvedor do sistema
		// (e pelo /etc/hosts), o que pode apontar para outro IP e só atrasaria a validação.
		PropagationTimeout: -1,
	}}
	dnsIssuer := certmagic.NewACMEIssuer(cmCfg, dnsTmpl)

	httpTmpl := base
	httpTmpl.ListenHost = cfg.HTTPListenHost
	httpTmpl.AltHTTPPort = cfg.HTTPPort
	httpIssuer := certmagic.NewACMEIssuer(cmCfg, httpTmpl)

	// Só os nossos emissores: nada do certmagic cai no emissor padrão (Let's Encrypt de produção).
	cmCfg.Issuers = []certmagic.Issuer{dnsIssuer, httpIssuer}

	if len(cfg.NamesDNS01) > 0 {
		m.slots = append(m.slots, &acmeSlot{name: certs.SlotDNS01, names: cfg.NamesDNS01, issuer: dnsIssuer})
	}
	if len(cfg.NamesHTTP01) > 0 {
		m.slots = append(m.slots, &acmeSlot{name: certs.SlotHTTP01, names: cfg.NamesHTTP01, issuer: httpIssuer})
	}
	return m, nil
}

// Close para o cache do certmagic.
func (m *ACMEManager) Close() {
	m.cache.Stop()
}

// Run cuida dos dois certificados até ctx acabar.
func (m *ACMEManager) Run(ctx context.Context) {
	m.log.Info("acme enabled", "ca", m.cfg.CA, "dir", m.cfg.Dir, "dns01", m.cfg.NamesDNS01,
		"http01", m.cfg.NamesHTTP01)
	var wg sync.WaitGroup
	for _, s := range m.slots {
		wg.Go(func() { m.runSlot(ctx, s) })
	}
	wg.Wait()
}

// runSlot é o ciclo de um certificado: garante, dorme até a renovação (no máximo RetryMax entre conferências)
// e, em falha, tenta de novo com backoff exponencial de RetryMin até RetryMax.
func (m *ACMEManager) runSlot(ctx context.Context, s *acmeSlot) {
	delay := m.cfg.StartDelay
	backoff := time.Duration(0)
	for {
		if !sleepCtx(ctx, delay) {
			return
		}
		renewAt, err := m.Ensure(ctx, s.name)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			m.metrics.Add(MetricACMEFailures, 1)
			if backoff == 0 {
				backoff = m.cfg.RetryMin
			} else {
				backoff = min(backoff*2, m.cfg.RetryMax)
			}
			m.log.Error("acme failed, keeping the previous certificate", "slot", s.name, "names", s.names,
				"retry_in", backoff.String(), "err", err)
			delay = backoff
			continue
		}
		backoff = 0
		delay = min(max(renewAt.Sub(m.now()), time.Second), m.cfg.RetryMax)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Ensure garante o certificado do slot: usa o guardado em FS_ACME_DIR enquanto ele cobre os nomes e não chegou
// a hora de renovar (exportando-o para FS_CERT_DIR se lá estiver diferente); senão emite um novo. Devolve quando
// renovar.
func (m *ACMEManager) Ensure(ctx context.Context, slot string) (time.Time, error) {
	s := m.slot(slot)
	if s == nil {
		return time.Time{}, fmt.Errorf("web: acme: unknown slot %q", slot)
	}
	crtPEM, keyPEM, leaf, err := m.loadStored(ctx, s)
	if err == nil {
		renewAt := m.renewAt(leaf)
		if m.now().Before(renewAt) {
			if err := m.export(s, crtPEM, keyPEM); err != nil {
				return time.Time{}, err
			}
			return renewAt, nil
		}
		m.log.Info("acme renewal due", "slot", s.name, "not_after", leaf.NotAfter)
	} else if !errors.Is(err, fs.ErrNotExist) {
		m.log.Warn("acme stored certificate unusable, issuing a new one", "slot", s.name, "err", err)
	}
	return m.issue(ctx, s)
}

func (m *ACMEManager) slot(name string) *acmeSlot {
	for _, s := range m.slots {
		if s.name == name {
			return s
		}
	}
	return nil
}

// renewAt é NotAfter menos RenewBefore, limitado a um terço da validade (certificados curtos).
func (m *ACMEManager) renewAt(leaf *x509.Certificate) time.Time {
	before := min(m.cfg.RenewBefore, leaf.NotAfter.Sub(leaf.NotBefore)/3)
	return leaf.NotAfter.Add(-before)
}

// storageKey é a chave do arquivo do slot no armazenamento do certmagic, separada por CA.
func (m *ACMEManager) storageKey(s *acmeSlot, ext string) string {
	return acmeStoragePrefix + "/" + s.issuer.IssuerKey() + "/" + s.name + ext
}

// loadStored lê o par guardado; fs.ErrNotExist quando não há.
func (m *ACMEManager) loadStored(ctx context.Context, s *acmeSlot) (crtPEM, keyPEM []byte, leaf *x509.Certificate, err error) {
	if crtPEM, err = m.storage.Load(ctx, m.storageKey(s, ".crt")); err != nil {
		return nil, nil, nil, err
	}
	if keyPEM, err = m.storage.Load(ctx, m.storageKey(s, ".key")); err != nil {
		return nil, nil, nil, err
	}
	pair, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("stored pair: %w", err)
	}
	leaf = pair.Leaf
	if !sameNames(leaf.DNSNames, s.names) {
		return nil, nil, nil, fmt.Errorf("stored names %v differ from %v", leaf.DNSNames, s.names)
	}
	if !m.now().Before(leaf.NotAfter) {
		return nil, nil, nil, fmt.Errorf("stored certificate expired at %s", leaf.NotAfter)
	}
	return crtPEM, keyPEM, leaf, nil
}

func sameNames(a, b []string) bool {
	x := make([]string, 0, len(a))
	for _, n := range a {
		x = append(x, strings.ToLower(n))
	}
	y := make([]string, 0, len(b))
	for _, n := range b {
		y = append(y, strings.ToLower(n))
	}
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// issue emite um certificado novo para o slot, guarda no FS_ACME_DIR e exporta para FS_CERT_DIR.
func (m *ACMEManager) issue(ctx context.Context, s *acmeSlot) (time.Time, error) {
	m.issueMu.Lock()
	defer m.issueMu.Unlock()
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	m.log.Info("acme issuing", "slot", s.name, "names", s.names, "ca", m.cfg.CA)
	key, err := rsa.GenerateKey(rand.Reader, acmeRSABits)
	if err != nil {
		return time.Time{}, fmt.Errorf("web: acme: key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: s.names}, key)
	if err != nil {
		return time.Time{}, fmt.Errorf("web: acme: csr: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return time.Time{}, fmt.Errorf("web: acme: csr: %w", err)
	}
	ic, err := s.issuer.Issue(ctx, csr)
	if err != nil {
		return time.Time{}, fmt.Errorf("web: acme: issue %s: %w", s.name, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return time.Time{}, fmt.Errorf("web: acme: key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	crtPEM := ic.Certificate
	pair, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return time.Time{}, fmt.Errorf("web: acme: issued pair: %w", err)
	}
	// A chave antes do certificado: um .crt novo nunca fica guardado ao lado de uma chave velha.
	if err := m.storage.Store(ctx, m.storageKey(s, ".key"), keyPEM); err != nil {
		return time.Time{}, fmt.Errorf("web: acme: store: %w", err)
	}
	if err := m.storage.Store(ctx, m.storageKey(s, ".crt"), crtPEM); err != nil {
		return time.Time{}, fmt.Errorf("web: acme: store: %w", err)
	}
	if err := m.export(s, crtPEM, keyPEM); err != nil {
		return time.Time{}, err
	}
	m.metrics.Add(MetricACMEIssued, 1)
	leaf := pair.Leaf
	m.log.Info("acme certificate obtained", "slot", s.name, "names", leaf.DNSNames,
		"issuer", leaf.Issuer.CommonName, "serial", leaf.SerialNumber.Text(16), "not_after", leaf.NotAfter)
	return m.renewAt(leaf), nil
}

// export grava o par em FS_CERT_DIR (dns01.* ou http01.*) se lá estiver diferente; pkg/certs recarrega a quente.
func (m *ACMEManager) export(s *acmeSlot, crtPEM, keyPEM []byte) error {
	curCrt, err1 := os.ReadFile(filepath.Join(m.cfg.CertDir, s.name+".crt"))
	curKey, err2 := os.ReadFile(filepath.Join(m.cfg.CertDir, s.name+".key"))
	if err1 == nil && err2 == nil && bytes.Equal(curCrt, crtPEM) && bytes.Equal(curKey, keyPEM) {
		return nil
	}
	if err := certs.WritePair(m.cfg.CertDir, s.name, crtPEM, keyPEM); err != nil {
		return fmt.Errorf("web: acme: export: %w", err)
	}
	m.log.Info("acme certificate exported", "slot", s.name, "dir", m.cfg.CertDir)
	return nil
}
