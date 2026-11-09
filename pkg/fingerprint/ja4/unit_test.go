package ja4

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

func ext(typ uint16, data ...byte) tlsparse.Extension {
	return tlsparse.Extension{Type: typ, Data: data}
}

// base é o ClientHello do exemplo da especificação JA4 da FoxIO (technical_details/JA4.md).
func base() *tlsparse.ClientHello {
	return &tlsparse.ClientHello{
		HandshakeVersion: 0x0303,
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
			0x009d, 0x002f, 0x0035,
		},
		Extensions: []tlsparse.Extension{
			ext(0x001b), ext(0x0000), ext(0x0033), ext(0x0010), ext(0x4469), ext(0x0017), ext(0x002d),
			ext(0x000d, 0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1),
			ext(0x0005), ext(0x0023), ext(0x0012), ext(0x002b), ext(0xff01), ext(0x000b), ext(0x000a), ext(0x0015),
		},
		ALPN:              []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{0x0304, 0x0303},
	}
}

func TestSpecExample(t *testing.T) {
	f := Compute(base(), TCP)
	if f.JA4 != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("JA4 = %s", f.JA4)
	}
	want := "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_" +
		"0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
	if f.JA4R != want {
		t.Fatalf("JA4_r = %s", f.JA4R)
	}
	if q := Compute(base(), QUIC); !strings.HasPrefix(q.JA4, "q13d1516h2_") {
		t.Fatalf("QUIC: %s", q.JA4)
	}
	if !strings.HasPrefix(f.JA4RO, "t13d1516h2_1301,1302,1303,c02b") || !strings.Contains(f.JA4RO, "_001b,0000,0033,0010,") {
		t.Fatalf("JA4_ro = %s", f.JA4RO)
	}
	// sem padding/session_ticket/pre_shared_key o stable conta 14 extensões
	if !strings.HasPrefix(f.Stable, "t13d1514h2_8daaf6152771_") || f.Stable == f.JA4 {
		t.Fatalf("stable = %s", f.Stable)
	}
	info := &tlsparse.Info{}
	Fill(info, base(), TCP)
	if info.JA4 != f.JA4 || info.JA4R != f.JA4R || info.JA4O != f.JA4O || info.JA4Stable != f.Stable {
		t.Fatal("Fill")
	}
}

func TestEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*tlsparse.ClientHello)
		want string
	}{
		{"sem cifras nem extensões", func(c *tlsparse.ClientHello) {
			c.CipherSuites, c.Extensions, c.ALPN = []uint16{0x0a0a}, nil, nil
		}, "t12i000000_000000000000_000000000000"},
		{"só assinaturas", func(c *tlsparse.ClientHello) {
			c.Extensions = []tlsparse.Extension{ext(0x000d, 0, 2, 4, 3)}
			c.ALPN = nil
		}, "t12i150100_8daaf6152771_" + hash12("000d_0403")},
		{"ALPN de 1 caractere", func(c *tlsparse.ClientHello) { c.ALPN = []string{"x"} }, "t13d1516xx_"},
		{"ALPN vazio", func(c *tlsparse.ClientHello) { c.ALPN = []string{""} }, "t13d151600_"},
		{"ALPN fora do ASCII", func(c *tlsparse.ClientHello) { c.ALPN = []string{"\xab\xcd"} }, "t13d151699_"},
		{"ALPN UTF-8 de 1 caractere", func(c *tlsparse.ClientHello) { c.ALPN = []string{"é"} }, "t13d151699_"},
		{"ALPN misto", func(c *tlsparse.ClientHello) { c.ALPN = []string{"a\xff"} }, "t13d1516a9_"},
		{"só GREASE no supported_versions", func(c *tlsparse.ClientHello) { c.SupportedVersions = []uint16{0x1a1a} }, "t00d1516h2_"},
		{"SSL 3.0", func(c *tlsparse.ClientHello) { c.HandshakeVersion, c.Extensions = 0x0300, nil }, "ts3i1500h2_"},
		{"assinaturas com GREASE e tamanho maior que os dados", func(c *tlsparse.ClientHello) {
			c.Extensions = []tlsparse.Extension{ext(0x000d, 0, 9, 0x2a, 0x2a, 4, 3)}
		}, "t12i1501h2_8daaf6152771_" + hash12("000d_0403")},
		{"assinaturas malformadas", func(c *tlsparse.ClientHello) {
			c.Extensions = []tlsparse.Extension{ext(0x000d, 0)}
		}, "t12i1501h2_8daaf6152771_" + hash12("000d")},
		{"mais de 99 cifras", func(c *tlsparse.ClientHello) {
			c.CipherSuites = make([]uint16, 120)
			for i := range c.CipherSuites {
				c.CipherSuites[i] = uint16(i + 1)
			}
		}, "t13d9916h2_"},
	}
	for _, c := range cases {
		ch := base()
		c.mod(ch)
		got := Compute(ch, TCP).JA4
		if !strings.HasPrefix(got, c.want) {
			t.Errorf("%s: %s, esperado prefixo %s", c.name, got, c.want)
		}
	}
	for v, want := range map[uint16]string{
		0x0301: "10", 0x0302: "11", 0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3", 0x7f17: "00",
	} {
		ch := &tlsparse.ClientHello{HandshakeVersion: v}
		if got := Compute(ch, DTLS).JA4[1:3]; got != want {
			t.Errorf("versão 0x%04x: %s", v, got)
		}
	}
}

func TestStableIgnoresEphemeral(t *testing.T) {
	b := Compute(base(), TCP)
	for _, e := range []uint16{0x0015, 0x0023, 0x0029} {
		// tira a extensão se o exemplo tem, põe se não tem
		ch := base()
		var exts []tlsparse.Extension
		for _, x := range ch.Extensions {
			if x.Type != e {
				exts = append(exts, x)
			}
		}
		if len(exts) == len(ch.Extensions) {
			exts = append(exts, ext(e))
		}
		ch.Extensions = exts
		f := Compute(ch, TCP)
		if f.JA4 == b.JA4 {
			t.Fatalf("0x%04x: JA4 deveria mudar", e)
		}
		if f.Stable != b.Stable {
			t.Fatalf("0x%04x: stable mudou: %s != %s", e, f.Stable, b.Stable)
		}
	}
	ch := base()
	ch.Extensions = ch.Extensions[1:] // sem compress_certificate, que não é efêmera
	if Compute(ch, TCP).Stable == b.Stable {
		t.Fatal("stable deveria mudar sem uma extensão não efêmera")
	}
}

// TestStableResumption: um cliente Go real em conexão nova e retomada (PSK do TLS 1.3); o JA4 muda e o
// JA4 stable não.
func TestStableResumption(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck // teste
	hellos := make(chan *tlsparse.ClientHello, 2)
	// a mesma configuração nas duas conexões: as chaves de ticket são da tls.Config
	srvCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	go func() {
		for range 2 {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			c := tlsparse.NewConn(raw)
			s := tls.Server(c, srvCfg)
			_ = s.Handshake()
			buf := make([]byte, 1)
			_, _ = s.Read(buf)
			ch, _ := c.ClientHello()
			hellos <- ch
			_ = s.Close()
		}
	}()
	cache := tls.NewLRUClientSessionCache(4)
	var resumed bool
	for range 2 {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			ServerName: "example.com", InsecureSkipVerify: true, ClientSessionCache: cache, //nolint:gosec // teste
		})
		if err != nil {
			t.Fatal(err)
		}
		// o ticket do TLS 1.3 chega depois do handshake: uma ida e volta garante que foi lido
		_, _ = c.Write([]byte{1})
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = c.Read(make([]byte, 1))
		resumed = c.ConnectionState().DidResume
		_ = c.Close()
	}
	full, again := <-hellos, <-hellos
	if !resumed || !again.PreSharedKey || full.PreSharedKey {
		t.Fatalf("retomada não aconteceu: resumed=%v psk=%v/%v", resumed, full.PreSharedKey, again.PreSharedKey)
	}
	a, b := Compute(full, TCP), Compute(again, TCP)
	if a.JA4 == b.JA4 {
		t.Fatalf("JA4 deveria mudar na retomada: %s", a.JA4)
	}
	if a.Stable != b.Stable {
		t.Fatalf("JA4 stable mudou: %s != %s", a.Stable, b.Stable)
	}
}

func FuzzCompute(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		ch, _ := tlsparse.Parse(data)
		for _, tr := range []Transport{TCP, QUIC} {
			fp := Compute(ch, tr)
			if len(fp.JA4) != 36 || len(fp.Stable) != 36 || len(fp.JA4O) != 36 {
				t.Fatalf("tamanho do JA4: %q", fp.JA4)
			}
		}
	})
}
