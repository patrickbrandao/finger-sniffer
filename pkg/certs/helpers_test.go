package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// genPair gera um par PEM ECDSA com os nomes, emissor (CN, autoassinado) e validade dados.
func genPair(t *testing.T, cn string, names []string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

func testConfig(dir string) Config {
	return Config{
		Dir:         dir,
		NamesDNS01:  SplitNames(DefaultNamesDNS01),
		NamesHTTP01: SplitNames(DefaultNamesHTTP01),
	}
}

func openStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	s, err := Open(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// echoServer aceita conexões TLS com cfg e ecoa o que recebe.
func echoServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// dial conecta sem validar a cadeia e devolve a conexão e o CN do certificado recebido.
func dial(t *testing.T, addr, sni string, cc *tls.Config) (*tls.Conn, string) {
	t.Helper()
	if cc == nil {
		cc = &tls.Config{}
	}
	cc = cc.Clone()
	cc.ServerName = sni
	cc.InsecureSkipVerify = true //nolint:gosec // teste: só olhamos qual certificado veio
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cc)
	if err != nil {
		t.Fatalf("dial sni=%q: %v", sni, err)
	}
	return c, c.ConnectionState().PeerCertificates[0].Subject.CommonName
}

func echo(t *testing.T, c *tls.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("eco = %q, quer %q", buf, msg)
	}
}
