package certs

import (
	"crypto/tls"
	"slices"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	t.Setenv("FS_CERT_DIR", "")
	t.Setenv("FS_CERT_NAMES_DNS01", "")
	t.Setenv("FS_CERT_NAMES_HTTP01", "")
	c := LoadConfig()
	if c.Dir != DefaultDir || len(c.NamesDNS01) != 2 || len(c.NamesHTTP01) != 4 {
		t.Fatalf("padrões: %+v", c)
	}
	t.Setenv("FS_CERT_DIR", "/x/certs")
	t.Setenv("FS_CERT_NAMES_DNS01", " A.Example.  , *.a.example ,,")
	t.Setenv("FS_CERT_NAMES_HTTP01", "b.example")
	c = LoadConfig()
	if c.Dir != "/x/certs" || !slices.Equal(c.NamesDNS01, []string{"a.example", "*.a.example"}) ||
		!slices.Equal(c.NamesHTTP01, []string{"b.example"}) {
		t.Fatalf("env: %+v", c)
	}
}

func TestServerConfigFixed(t *testing.T) {
	c := ServerConfig()
	if c.MinVersion != tls.VersionTLS10 || c.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("versões %x..%x", c.MinVersion, c.MaxVersion)
	}
	for _, id := range []uint16{
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	} {
		if !slices.Contains(c.CipherSuites, id) {
			t.Errorf("falta %s", tls.CipherSuiteName(id))
		}
	}
	if slices.Contains(c.CipherSuites, tls.TLS_RSA_WITH_RC4_128_SHA) {
		t.Error("RC4 não deveria estar na lista")
	}
	// Cópia independente: mexer numa não afeta a próxima.
	c.CipherSuites[0] = 0
	if ServerConfig().CipherSuites[0] == 0 {
		t.Error("ServerConfig compartilha a lista")
	}
}

func TestDescribe(t *testing.T) {
	d := Describe()
	if d.MinVersion != "TLS 1.0" || d.MaxVersion != "TLS 1.3" {
		t.Fatalf("versões: %+v", d)
	}
	if len(d.CipherSuites) != len(cipherSuites)+3 || d.CipherSuites[0] != "TLS_AES_128_GCM_SHA256" ||
		!slices.Contains(d.CipherSuites, "TLS_RSA_WITH_3DES_EDE_CBC_SHA") {
		t.Fatalf("cifras: %v", d.CipherSuites)
	}
}

// TestHandshakeVersions: clientes Go presos a cada versão completam o handshake com ServerConfig, com o
// autoassinado RSA (cifras de troca RSA e 3DES) e com um certificado ECDSA.
func TestHandshakeVersions(t *testing.T) {
	rsaStore := openStore(t, testConfig(t.TempDir()))
	ecDir := t.TempDir()
	crt, key := genPair(t, "ec", []string{"vps602.tmsoft.com.br"}, time.Now().Add(90*24*time.Hour))
	if err := WritePair(ecDir, SlotHTTP01, crt, key); err != nil {
		t.Fatal(err)
	}
	ecStore := openStore(t, testConfig(ecDir))

	cases := []struct {
		name    string
		store   *Store
		version uint16
		suite   uint16 // 0 = deixa o cliente escolher
	}{
		{"tls10-rsa-3des", rsaStore, tls.VersionTLS10, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
		{"tls10-rsa-kex", rsaStore, tls.VersionTLS10, tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		{"tls10-ecdhe-rsa", rsaStore, tls.VersionTLS10, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		{"tls10-ecdhe-ecdsa", ecStore, tls.VersionTLS10, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		{"tls11", rsaStore, tls.VersionTLS11, 0},
		{"tls12-cbc-sha256", rsaStore, tls.VersionTLS12, tls.TLS_RSA_WITH_AES_128_CBC_SHA256},
		{"tls12", ecStore, tls.VersionTLS12, 0},
		{"tls13-rsa", rsaStore, tls.VersionTLS13, 0},
		{"tls13-ecdsa", ecStore, tls.VersionTLS13, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := echoServer(t, tc.store.TLSConfig())
			cc := &tls.Config{MinVersion: tc.version, MaxVersion: tc.version}
			if tc.suite != 0 {
				cc.CipherSuites = []uint16{tc.suite}
			}
			c, _ := dial(t, addr, "vps602.tmsoft.com.br", cc)
			defer func() { _ = c.Close() }()
			st := c.ConnectionState()
			if st.Version != tc.version {
				t.Fatalf("versão %s", tls.VersionName(st.Version))
			}
			if tc.suite != 0 && st.CipherSuite != tc.suite {
				t.Fatalf("cifra %s", tls.CipherSuiteName(st.CipherSuite))
			}
			echo(t, c, "ping")
		})
	}
}
