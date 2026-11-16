package bot

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// TestServe: o serviço sobe a 9002 com TLS (pkg/certs, autoassinado sem certificado em FS_CERT_DIR) e a 9003 em
// HTTP, assina fs.v1.store.connection (publicador falso), põe a conexão no índice, publica as métricas e para
// limpo no cancelamento.
func TestServe(t *testing.T) {
	db, path := testDB(t)
	log := slog.New(slog.DiscardHandler)
	cs, err := certs.Open(certs.Config{Dir: t.TempDir(), NamesDNS01: []string{"localhost"}}, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	var deliver func([]byte)
	subscribed := make(chan string, 1)
	m := service.NewMetrics()
	srv := New(testConfig(path), Deps{
		Log: log, Metrics: m, DB: db, TLS: cs.TLSConfig(), OpenAPI: []byte("openapi: 3.1.0\n"), Version: "test",
		Subscribe: func(subject string, h func([]byte)) (func(), error) {
			deliver = h
			subscribed <- subject
			return func() {}, nil
		},
	})
	listen := func() net.Listener {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	pub, in := listen(), listen()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, []net.Listener{pub}, []net.Listener{in}) }()

	if s := <-subscribed; s != event.SubjectStoreConnection {
		t.Fatalf("assinou %s", s)
	}
	deliver(storeMessage("opened", testStoreConnID, "203.0.113.9", 40000))
	deliver([]byte(`{"lixo":1}`))
	if _, ok := srv.Index().StoreByID(testStoreConnID, time.Now()); !ok {
		t.Fatal("conexão do store fora do índice")
	}

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}, //nolint:gosec // autoassinado do teste
	}}
	get := func(url string) (int, []byte) {
		t.Helper()
		resp, err := client.Get(url) //nolint:noctx // teste
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	code, body := get("https://" + pub.Addr().String() + "/bot/v1/health")
	var h Health
	if err := json.Unmarshal(body, &h); code != 200 || err != nil || h.Version != "test" {
		t.Fatalf("health 9002: %d %s", code, body)
	}
	if code, _ := get("https://" + pub.Addr().String() + "/bot/v1/ip/192.0.2.1"); code != 401 {
		t.Fatalf("9002 sem chave: %d", code)
	}
	if code, _ := get("http://" + in.Addr().String() + "/bot/v1/ip/192.0.2.1"); code != 200 {
		t.Fatalf("9003 sem chave: %d", code)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve não parou")
	}
	srv.updateMetrics()
	if m.Get(metricStoreFeedMessages) != 1 || m.Get(metricDBBytes) <= 0 {
		t.Errorf("métricas: %v", m.Snapshot())
	}
	if st, _ := srv.Status(); st != event.StatusOK {
		t.Errorf("status %s", st)
	}
}

// TestStatusDBSpace: banco acima de 90% do teto deixa o serviço degraded ("db space", spec 018 RF-11).
func TestStatusDBSpace(t *testing.T) {
	db, path := testDB(t)
	cfg := testConfig(path)
	cfg.MaxBytes = 1024
	srv := New(cfg, Deps{DB: db})
	st, reasons := srv.Status()
	if st != event.StatusDegraded || len(reasons) != 1 || reasons[0] != "db space" {
		t.Fatalf("%s %v", st, reasons)
	}
	if h := srv.Health(); h.Status != event.StatusDegraded || h.Lists == nil {
		t.Fatalf("%+v", h)
	}
}
