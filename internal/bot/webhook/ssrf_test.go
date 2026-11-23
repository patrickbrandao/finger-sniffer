package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestRedirectNotFollowed: o webhook https responde 3xx para um servidor http em loopback; o segundo não recebe
// nada, o envio conta o status do 3xx e não repete (task 372).
func TestRedirectNotFollowed(t *testing.T) {
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer internal.Close()
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusFound, http.StatusSeeOther} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, internal.URL+"/interno", code)
		}))
		d, c, fa, ctx := newDispatcher(t, srv, time.Now)
		d.SetTargets(ctx, []Target{target(srv.URL)})
		d.Publish("bot", "example.com", body("{}"))
		metric := sentMetric(strconv.Itoa(code))
		waitFor(t, func() bool { return c.Get(metric) == 1 })
		time.Sleep(50 * time.Millisecond)
		if n := internalHits.Load(); n != 0 {
			t.Fatalf("%d: servidor interno recebeu %d requisições", code, n)
		}
		if len(fa.Delays()) != 0 {
			t.Fatalf("%d: nova tentativa depois do redirecionamento: %v", code, fa.Delays())
		}
		srv.Close()
	}
}

// trustTLS devolve a configuração TLS que confia no certificado do httptest (válido para example.com).
func trustTLS(srv *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// TestDialRejectsInternal: um nome que resolve para loopback é recusado no dial (o servidor não recebe nada, conta
// code="error" com as novas tentativas); com a política liberada, o mesmo nome conecta ao IP resolvido.
func TestDialRejectsInternal(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
	hookURL := "https://example.com:" + port + "/hook"
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "example.com" {
			t.Errorf("resolveu %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}

	// política padrão: loopback recusado
	cl := NewClient(ClientConfig{Lookup: lookup, TLS: trustTLS(srv)})
	req, _ := http.NewRequest(http.MethodPost, hookURL, nil)
	if _, err := cl.Do(req); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("dial para loopback: %v", err)
	}
	c, fa := newCounter(), &fakeAfter{}
	d := New(Options{Client: cl, After: fa.After, Count: c.Add})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); d.Wait() }()
	d.SetTargets(ctx, []Target{target(hookURL)})
	d.Publish("bot", "example.com", body("{}"))
	waitFor(t, func() bool { return c.Get(`bot_webhook_sent_total{code="error"}`) == 4 })
	if n := hits.Load(); n != 0 {
		t.Fatalf("servidor em loopback recebeu %d envios", n)
	}

	// IP literal interno também é recusado, sem resolver
	req, _ = http.NewRequest(http.MethodPost, srv.URL, nil)
	if _, err := cl.Do(req); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("IP literal em loopback: %v", err)
	}

	// política liberada: conecta ao IP que o resolvedor deu
	open := NewClient(ClientConfig{Lookup: lookup, Blocked: func(netip.Addr) bool { return false }, TLS: trustTLS(srv)})
	req, _ = http.NewRequest(http.MethodPost, hookURL, nil)
	resp, err := open.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || hits.Load() != 1 {
		t.Fatalf("status %d, %d envios", resp.StatusCode, hits.Load())
	}
}

// TestDefaultClientRejectsLoopback: o despachante sem cliente injetado usa NewClient e não chama 127.0.0.1.
func TestDefaultClientRejectsLoopback(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	c, fa := newCounter(), &fakeAfter{}
	d := New(Options{After: fa.After, Count: c.Add})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); d.Wait() }()
	d.SetTargets(ctx, []Target{target(srv.URL)})
	d.Publish("bot", "example.com", body("{}"))
	waitFor(t, func() bool { return c.Get(`bot_webhook_sent_total{code="error"}`) == 4 })
	if n := hits.Load(); n != 0 {
		t.Fatalf("loopback recebeu %d envios", n)
	}
}

// TestBlockedAddr: faixas internas recusadas, endereços públicos aceitos.
func TestBlockedAddr(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "127.8.9.10", "::1", "0.0.0.0", "::", "10.0.0.1", "10.249.0.5", "172.16.0.1", "172.31.255.255",
		"192.168.1.1", "169.254.169.254", "fe80::1", "fc00::1", "fd12:3456::1", "100.64.0.1", "100.127.255.254",
		"224.0.0.1", "239.255.255.250", "ff02::1", "255.255.255.255", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"198.18.0.1", "192.0.0.8",
	} {
		if !BlockedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s aceito", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "100.128.0.1", "172.32.0.1", "2001:4860:4860::8888", "::ffff:8.8.8.8"} {
		if BlockedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s recusado", s)
		}
	}
	if !BlockedAddr(netip.Addr{}) {
		t.Error("endereço inválido aceito")
	}
}
