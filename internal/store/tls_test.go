package store

import (
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
	"net/http"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// genCertPair gera um par PEM ECDSA (CN = emissor, autoassinado em X.509) com os nomes e a validade dados.
func genCertPair(t *testing.T, cn string, names []string, notAfter time.Time) (certPEM, keyPEM []byte, leaf *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(der)
	kder, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), leaf
}

func certsConfig(dir string) certs.Config {
	return certs.Config{Dir: dir, NamesDNS01: certs.SplitNames(certs.DefaultNamesDNS01), NamesHTTP01: certs.SplitNames(certs.DefaultNamesHTTP01)}
}

// httpsClient confia só no certificado dado e usa o SNI pedido.
func httpsClient(leaf *x509.Certificate, sni string) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: sni, MinVersion: tls.VersionTLS12},
	}}
}

// TestHTTPSAPI: a 9000 responde com o certificado de FS_CERT_DIR, sem /metrics; troca a quente; health com
// os certificados.
func TestHTTPSAPI(t *testing.T) {
	ns := startNATS(t, 0)
	defer ns.Shutdown()
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_LOG_LEVEL", "error")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir := t.TempDir()
	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	crt, key, leaf := genCertPair(t, "Test CA 1", []string{"vps602.tmsoft.com.br"}, notAfter)
	if err := certs.WritePair(dir, certs.SlotHTTP01, crt, key); err != nil {
		t.Fatal(err)
	}

	svc, err := service.New(event.ServiceStore)
	if err != nil {
		t.Fatal(err)
	}
	_, path := testDB(t)
	httpPort, httpsPort := freePort(t), freePort(t)
	cfg := Config{
		DBPath: path, HTTPAddr: fmt.Sprintf("127.0.0.1:%d", httpPort), HTTPSAddr: fmt.Sprintf("127.0.0.1:%d", httpsPort),
		Certs: certsConfig(dir), Retention: "10m", MaxBytes: 1 << 30, DownAfter: time.Minute, Host: hostFixture(t, false),
		RetentionDur: 10 * time.Minute,
		Ingest:       IngestConfig{PcapMax: 16 << 20, TCPIdle: time.Minute, UDPIdle: 30 * time.Second, CloseGrace: time.Second, MaxOpen: 200, MaxNewPerS: 50, Snaplen: 65535},
	}
	st, err := New(ctx, svc, cfg, []byte("openapi: 3.1.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = st.Run(ctx) }()

	base := fmt.Sprintf("https://127.0.0.1:%d", httpsPort)
	cli := httpsClient(leaf, "vps602.tmsoft.com.br")
	var h Health
	eventually(t, 5*time.Second, func() bool {
		resp, err := cli.Get(base + "/api/v1/health") //nolint:noctx // teste
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == 200 && json.NewDecoder(resp.Body).Decode(&h) == nil
	}, "https health never answered")
	if h.Host == nil || h.Host.TLSServer == nil || h.Host.TLSServer.MinVersion != "TLS 1.0" || len(h.Host.Certificates) == 0 {
		t.Fatalf("host %+v", h.Host)
	}
	var found bool
	for _, c := range h.Host.Certificates {
		if len(c.Names) == 1 && c.Names[0] == "vps602.tmsoft.com.br" && c.Issuer == "Test CA 1" && !c.SelfSigned &&
			c.NotAfter == event.FormatTime(notAfter) {
			found = true
		}
	}
	if !found {
		t.Fatalf("certificates %+v", h.Host.Certificates)
	}

	// /metrics só na 9001.
	resp, err := cli.Get(base + "/metrics") //nolint:noctx // teste
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/metrics on 9000: %d", resp.StatusCode)
	}
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", httpPort)) //nolint:noctx,gosec // teste
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics on 9001: %d", resp.StatusCode)
	}

	// Troca a quente: o próximo handshake usa o certificado novo.
	crt2, key2, leaf2 := genCertPair(t, "Test CA 2", []string{"vps602.tmsoft.com.br"}, notAfter.Add(24*time.Hour))
	if err := certs.WritePair(dir, certs.SlotHTTP01, crt2, key2); err != nil {
		t.Fatal(err)
	}
	cli2 := httpsClient(leaf2, "vps602.tmsoft.com.br")
	eventually(t, 10*time.Second, func() bool {
		cli2.CloseIdleConnections()
		resp, err := cli2.Get(base + "/api/v1/health") //nolint:noctx // teste
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == 200
	}, "new certificate never served")
}

func TestCertificatesJSON(t *testing.T) {
	at := time.Date(2027, 2, 5, 0, 0, 0, 0, time.UTC)
	got := certificatesJSON([]certs.CertInfo{{Issuer: "x", NotAfter: at, SelfSigned: true}})
	if len(got) != 1 || got[0].Names == nil || got[0].NotAfter != "2027-02-05T00:00:00.000000000Z" || !got[0].SelfSigned {
		t.Fatalf("%+v", got)
	}
}
