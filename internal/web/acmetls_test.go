package web

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// TestACMETLSALPNHandshake: ClientHello com ALPN só "acme-tls/1" e desafio ativo → o web entrega o certificado
// de desafio, negocia "acme-tls/1", registra client_hello e handshake e fecha depois do handshake (RFC 8737);
// "acme-tls/1" junto de outros protocolos, ou sem desafio, segue o handshake normal (spec 005 RF-11).
func TestACMETLSALPNHandshake(t *testing.T) {
	certPEM, keyPEM, _ := pebbleTLS(t)
	chal, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	const name = "finger-01.badblock.net.br"
	asked := 0
	h := newHarness(t, harnessOpts{deps: func(d *Deps) {
		d.ACMETLSALPN = func(hello *tls.ClientHelloInfo) (*tls.Certificate, bool) {
			asked++
			return &chal, hello.ServerName == name
		}
	}})

	c := dial(t, h.addr443)
	tc := tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true, NextProtos: []string{acmeTLS1}}) //nolint:gosec // teste
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	st := tc.ConnectionState()
	if st.NegotiatedProtocol != acmeTLS1 || !bytes.Equal(st.PeerCertificates[0].Raw, chal.Leaf.Raw) {
		t.Fatalf("alpn %q, challenge certificate %v", st.NegotiatedProtocol, bytes.Equal(st.PeerCertificates[0].Raw, chal.Leaf.Raw))
	}
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := tc.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("connection not closed after the handshake: %v", err)
	}
	port := srcPort(c)
	if ch := h.events.wait(t, event.SubjectWebTLSClientHello, port, 1)[0]; ch.Payload["sni"] != name {
		t.Fatalf("client hello %v", ch.Payload)
	}
	hs := h.events.wait(t, event.SubjectWebTLSHandshake, port, 1)[0]
	if neg, _ := hs.Payload["negotiated"].(map[string]any); neg == nil || neg["alpn"] != acmeTLS1 {
		t.Fatalf("handshake %v", hs.Payload)
	}

	// acme-tls/1 com outros protocolos: não é validação, o gancho nem é consultado.
	before := asked
	tc2 := tls.Client(dial(t, h.addr443), &tls.Config{ServerName: name, InsecureSkipVerify: true, NextProtos: []string{acmeTLS1, "http/1.1"}}) //nolint:gosec // teste
	if err := tc2.Handshake(); err != nil {
		t.Fatal(err)
	}
	if tc2.ConnectionState().NegotiatedProtocol != "http/1.1" || asked != before ||
		bytes.Equal(tc2.ConnectionState().PeerCertificates[0].Raw, chal.Leaf.Raw) {
		t.Fatalf("mixed alpn: %q asked %d", tc2.ConnectionState().NegotiatedProtocol, asked-before)
	}

	// Sem desafio para o nome: handshake normal, sem ALPN em comum (o cliente só ofereceu acme-tls/1).
	tc3 := tls.Client(dial(t, h.addr443), &tls.Config{ServerName: "other.example", InsecureSkipVerify: true, NextProtos: []string{acmeTLS1}}) //nolint:gosec // teste
	if err := tc3.Handshake(); err == nil && tc3.ConnectionState().NegotiatedProtocol == acmeTLS1 {
		t.Fatal("acme-tls/1 negotiated without a challenge")
	}
}

// TestTLSALPNChallengeLookup: o gerenciador só responde ClientHello de validação de um nome do B com desafio
// TLS-ALPN-01 ativo.
func TestTLSALPNChallengeLookup(t *testing.T) {
	var nilMgr *ACMEManager
	if _, ok := nilMgr.TLSALPNChallenge(&tls.ClientHelloInfo{ServerName: "x", SupportedProtos: []string{acmeTLS1}}); ok {
		t.Fatal("nil manager answered")
	}
	m, err := NewACMEManager(ACMEConfig{CA: "https://127.0.0.1:1/dir", Dir: t.TempDir(), NamesHTTP01: testNamesHTTP01, TLSALPNPort: 8443}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	for _, hello := range []*tls.ClientHelloInfo{
		{ServerName: testNamesHTTP01[0], SupportedProtos: []string{acmeTLS1}},         // sem desafio ativo
		{ServerName: "abc." + testNamesDNS01[0], SupportedProtos: []string{acmeTLS1}}, // nome fora do B
		{ServerName: testNamesHTTP01[0], SupportedProtos: []string{acmeTLS1, "h2"}},   // não é validação
		{ServerName: "", SupportedProtos: []string{acmeTLS1}},                         // sem SNI
		{ServerName: testNamesHTTP01[0] + ".", SupportedProtos: []string{"http/1.1"}}, // outro ALPN
	} {
		if _, ok := m.TLSALPNChallenge(hello); ok {
			t.Fatalf("answered %+v", hello)
		}
	}
	if !isACMETLSHello(&tls.ClientHelloInfo{ServerName: "a", SupportedProtos: []string{acmeTLS1}}) || isACMETLSHello(nil) {
		t.Fatal("isACMETLSHello")
	}
}
