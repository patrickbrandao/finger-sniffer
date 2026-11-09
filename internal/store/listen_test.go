package store

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// TestListenIPs: a API escuta em 127.0.0.1 e nos IPs públicos do .env, nunca em "*" (ADR 0023).
func TestListenIPs(t *testing.T) {
	t.Setenv("FS_LISTEN_IPV4", "")
	t.Setenv("FS_LISTEN_IPV6", "")
	c, err := LoadConfig()
	if err != nil || len(c.ListenIPs) != 1 || c.ListenIPs[0] != loopbackAPI {
		t.Fatalf("%v %v", c.ListenIPs, err)
	}
	t.Setenv("FS_LISTEN_IPV4", "172.233.24.85")
	t.Setenv("FS_LISTEN_IPV6", "2600:3c0d::f03c:93ff:fe26:8fd9")
	if c, err = LoadConfig(); err != nil {
		t.Fatal(err)
	}
	addrs, err := c.apiAddrs(c.HTTPAddr)
	want := []string{"127.0.0.1:9001", "172.233.24.85:9001", "[2600:3c0d::f03c:93ff:fe26:8fd9]:9001"}
	if err != nil || len(addrs) != len(want) {
		t.Fatalf("%v %v", addrs, err)
	}
	for i := range want {
		if addrs[i] != want[i] {
			t.Fatalf("%v", addrs)
		}
	}
	if addrs, _ = c.apiAddrs(c.HTTPSAddr); addrs[1] != "172.233.24.85:9000" {
		t.Fatalf("%v", addrs)
	}
	for _, bad := range [][2]string{{"2600::1", ""}, {"", "10.0.0.1"}, {"x", ""}} {
		t.Setenv("FS_LISTEN_IPV4", bad[0])
		t.Setenv("FS_LISTEN_IPV6", bad[1])
		if _, err := LoadConfig(); err == nil {
			t.Fatalf("expected error for %v", bad)
		}
	}
	// Sem ListenIPs (testes), o endereço vale como veio.
	if a, _ := (Config{}).apiAddrs("127.0.0.1:0"); len(a) != 1 || a[0] != "127.0.0.1:0" {
		t.Fatalf("%v", a)
	}
}

// TestServeAll: um servidor atende vários listeners e o Shutdown encerra todos sem erro.
func TestServeAll(t *testing.T) {
	c := Config{ListenIPs: []netip.Addr{loopbackAPI, loopbackAPI}}
	addrs, _ := c.apiAddrs("127.0.0.1:0")
	ls, err := listenAll(addrs)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), ReadHeaderTimeout: time.Second}
	errc := serveAll(ls, srv.Serve)
	for _, l := range ls {
		resp, err := http.Get("http://" + l.Addr().String() + "/") //nolint:noctx // teste
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	// Endereço ocupado: listenAll falha e fecha o que já abriu.
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = busy.Close() }()
	if _, err := listenAll([]string{"127.0.0.1:0", busy.Addr().String()}); err == nil {
		t.Fatal("expected bind error")
	}
}
