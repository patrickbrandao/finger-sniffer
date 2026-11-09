package h1

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func head(t *testing.T, s string) *Request {
	t.Helper()
	req, err := NewReader(bufio.NewReader(strings.NewReader(s))).ReadHead()
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func kinds(sigs []ProxySignal) []string {
	out := []string{}
	for _, s := range sigs {
		out = append(out, s.Kind)
	}
	return out
}

func TestProxySignalsDefaults(t *testing.T) {
	req := head(t, "GET http://example.com/ HTTP/1.1\r\n"+
		"Host: Example.COM.\r\n"+
		"via: 1.1 squid\r\n"+
		"X-Forwarded-For: 10.0.0.1\r\n"+
		"X-Cache-Lookup: MISS\r\n"+
		"x-proxy-id: 1\r\n"+
		"Proxy-Authorization: Basic c2VjcmV0\r\n"+
		"User-Agent: curl\r\n"+
		"Max-Forwards: 9\r\n\r\n")
	sigs := DetectProxySignals(req, ProxyContext{Direct: true, SNI: "example.com"})
	got := strings.Join(kinds(sigs), ",")
	want := "via,x-forwarded-for,x-cache-lookup,x-proxy-id,proxy-authorization,max-forwards,absolute-form-direct"
	if got != want {
		t.Fatalf("got %s", got)
	}
	if *sigs[0].Field != "via" || *sigs[0].Detail != "1.1 squid" {
		t.Fatalf("%+v", sigs[0])
	}
	// A credencial não é copiada para o detalhe.
	if strings.Contains(*sigs[4].Detail, "c2VjcmV0") || !strings.Contains(*sigs[4].Detail, "Basic") {
		t.Fatal(*sigs[4].Detail)
	}
	if sigs[6].Field != nil || *sigs[6].Detail != "http://example.com/" {
		t.Fatalf("%+v", sigs[6])
	}
}

func TestProxySignalsHostSNI(t *testing.T) {
	req := head(t, "GET / HTTP/1.1\r\nHost: other.example:443\r\n\r\n")
	sigs := DetectProxySignals(req, ProxyContext{SNI: "abc.dns-monitor.tmsoft.com.br"})
	if len(sigs) != 1 || sigs[0].Kind != SignalHostSNIMismatch || *sigs[0].Field != "Host" {
		t.Fatalf("%+v", sigs)
	}
	for _, h := range []string{"abc.dns-monitor.tmsoft.com.br:443", "ABC.dns-monitor.tmsoft.com.br."} {
		req = head(t, "GET / HTTP/1.1\r\nHost: "+h+"\r\n\r\n")
		if s := DetectProxySignals(req, ProxyContext{SNI: "abc.dns-monitor.tmsoft.com.br"}); len(s) != 0 {
			t.Fatalf("%s: %+v", h, s)
		}
	}
	req = head(t, "GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n")
	if s := DetectProxySignals(req, ProxyContext{SNI: "2001:db8::1"}); len(s) != 0 {
		t.Fatalf("%+v", s)
	}
	// Absolute-form numa conexão que não é direta (porta de proxy) não é sinal.
	req = head(t, "GET http://x/ HTTP/1.1\r\n\r\n")
	if s := DetectProxySignals(req, ProxyContext{}); len(s) != 0 {
		t.Fatal(s)
	}
	// Detalhe longo é cortado.
	long := strings.Repeat("h", 400)
	req = head(t, "GET http://"+long+"/ HTTP/1.1\r\nHost: "+long+"\r\nVia: "+long+"\r\n\r\n")
	for _, s := range DetectProxySignals(req, ProxyContext{Direct: true, SNI: "a"}) {
		if len(*s.Detail) > maxSignalDetail {
			t.Fatalf("%s detail %d", s.Kind, len(*s.Detail))
		}
	}
}

func TestProxyRulesConfigurable(t *testing.T) {
	rules, err := ParseProxyRules(" X-Corp-* , Via ")
	if err != nil {
		t.Fatal(err)
	}
	req := head(t, "GET / HTTP/1.1\r\nX-Forwarded-For: 1\r\nx-corp-id: 7\r\nVIA: a\r\nX-Corp: no\r\n\r\n")
	if got := strings.Join(kinds(DetectProxySignals(req, ProxyContext{Rules: rules})), ","); got != "x-corp-id,via" {
		t.Fatal(got)
	}
	if _, err := ParseProxyRules("Via,,X"); !errors.Is(err, ErrBadProxyRule) {
		t.Fatal(err)
	}
	if _, err := ParseProxyRules("*"); !errors.Is(err, ErrBadProxyRule) {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	MustParseProxyRules("")
}

// TestProxySignalsVendorHeaderNotDefault: cabeçalho de um projeto específico (sem uso de mercado) não é sinal de
// proxy na lista padrão (ADR 0028); quem precisar dele configura a lista.
func TestProxySignalsVendorHeaderNotDefault(t *testing.T) {
	req := head(t, "GET / HTTP/1.1\r\nHost: example.com\r\nX-xproxy-trace: 1\r\n\r\n")
	sigs := DetectProxySignals(req, ProxyContext{Direct: true, SNI: "example.com"})
	if len(sigs) != 0 {
		t.Fatalf("sinais inesperados: %v", kinds(sigs))
	}
}
