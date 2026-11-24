package bot

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/agg"
	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// TestServe: o serviço sobe a 9002 com TLS (pkg/certs, autoassinado sem certificado em FS_CERT_DIR) e a 9003 em
// HTTP, assina fs.v1.store.connection e fs.v1.svc.heartbeat (publicador falso), põe a conexão no índice, acompanha
// o heartbeat do store, publica as métricas e para limpo no cancelamento.
func TestServe(t *testing.T) {
	db, path := testDB(t)
	log := slog.New(slog.DiscardHandler)
	cs, err := certs.Open(certs.Config{Dir: t.TempDir(), NamesDNS01: []string{"localhost"}}, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	handlers := map[string]func([]byte){}
	subscribed := make(chan string, 2)
	m := service.NewMetrics()
	srv := New(testConfig(path), Deps{
		Log: log, Metrics: m, DB: db, TLS: cs.TLSConfig(), OpenAPI: []byte("openapi: 3.1.0\n"), Version: "test",
		Subscribe: func(subject string, h func([]byte)) (func(), error) {
			handlers[subject] = h
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

	if s1, s2 := <-subscribed, <-subscribed; s1 != event.SubjectStoreConnection || s2 != event.SubjectHeartbeat {
		t.Fatalf("assinou %s e %s", s1, s2)
	}
	deliver := handlers[event.SubjectStoreConnection]
	handlers[event.SubjectHeartbeat](heartbeatMessage(t, event.ServiceStore, event.StatusOK))
	deliver(storeMessage("opened", testStoreConnID, "203.0.113.9", 40000))
	deliver([]byte(`{"lixo":1}`))
	if _, ok := srv.Index().StoreByID(testStoreConnID, time.Now()); !ok {
		t.Fatal("conexão do store fora do índice")
	}

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
	}}
	get := func(url string) (int, []byte) {
		t.Helper()
		resp, err := client.Get(url)
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
	if !srv.store.okLocked(time.Now()) {
		t.Error("heartbeat do store não acompanhado")
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

// sourceTCPListener troca o endereço remoto de cada conexão aceita pelo próximo da fila (origens diferentes em
// loopback, sem depender de 127.0.0.2 no sistema).
type sourceTCPListener struct {
	net.Listener
	ips chan string
}

func (l *sourceTCPListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	ip := "127.0.0.1"
	select {
	case ip = <-l.ips:
	default:
	}
	return &remoteConn{Conn: c, remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}, nil
}

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteConn) RemoteAddr() net.Addr { return c.remote }

// servePublic sobe o serviço com um listener da 9002 de origens falsas e devolve o endereço, a fila das origens e
// as métricas.
func servePublic(t *testing.T, tune func(*Server)) (*Server, string, chan string, *service.Metrics) {
	t.Helper()
	db, path := testDB(t)
	log := slog.New(slog.DiscardHandler)
	cs, err := certs.Open(certs.Config{Dir: t.TempDir(), NamesDNS01: []string{"localhost"}}, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	m := service.NewMetrics()
	srv := New(testConfig(path), Deps{Log: log, Metrics: m, DB: db, TLS: cs.TLSConfig(), OpenAPI: []byte("openapi: 3.1.0\n"), Version: "test"})
	tune(srv)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	in, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ips := make(chan string, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ctx, []net.Listener{&sourceTCPListener{Listener: l, ips: ips}}, []net.Listener{in})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return srv, l.Addr().String(), ips, m
}

// healthOnce faz um GET /bot/v1/health numa conexão nova, com prazo curto.
func healthOnce(addr string) error {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
	}}
	resp, err := client.Get("https://" + addr + "/bot/v1/health")
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// TestPublicSourceLimit: com teto global 3 e por origem 2, três conexões ociosas da mesma origem não impedem uma
// conexão de outra origem de responder health; a terceira é fechada no accept e contada (task 336, ADR 0073 item
// 1.1). Sem o teto por origem a terceira ocupava a última vaga e o cliente seguinte esperava o prazo do handshake.
func TestPublicSourceLimit(t *testing.T) {
	srv, addr, ips, m := servePublic(t, func(s *Server) { s.publicMax, s.perSource, s.idleHigh = 3, 2, 1000 })
	var idle []net.Conn
	for range 3 {
		ips <- "192.0.2.1"
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	t.Cleanup(func() {
		for _, c := range idle {
			_ = c.Close()
		}
	})
	// a terceira da mesma origem é fechada pelo servidor
	_ = idle[2].SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := idle[2].Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("terceira conexão da origem não foi fechada: %v", err)
	}
	ips <- "198.51.100.1"
	if err := healthOnce(addr); err != nil {
		t.Fatalf("outra origem: %v", err)
	}
	if got := m.Get(publicClosedMetric(closedSource)); got != 1 {
		t.Errorf("source %v", got)
	}
	// duas ociosas + a da outra origem = teto global 3: health degraded com public conns
	if _, reasons := srv.Status(); !slices.Contains(reasons, "public conns") {
		t.Errorf("reasons %v", reasons)
	}
}

// TestPublicIdleTrim: perto do teto (idleHigh), a conexão nova fecha a ociosa mais antiga da 9002 (ADR 0073 item
// 1.3), contada em bot_public_conns_closed_total{reason="idle"}.
func TestPublicIdleTrim(t *testing.T) {
	_, addr, _, m := servePublic(t, func(s *Server) { s.publicMax, s.perSource, s.idleHigh = 10, 10, 3 })
	open := func() (*tls.Conn, *bufio.Reader) {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		br := bufio.NewReader(c)
		if _, err := io.WriteString(c, "GET /bot/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return c, br
	}
	c1, br1 := open()
	time.Sleep(10 * time.Millisecond)
	open()
	if m.Get(publicClosedMetric(closedIdle)) != 0 {
		t.Fatal("fechou com 2 abertas")
	}
	open() // terceira: fecha a ociosa mais antiga (c1)
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br1.ReadByte(); err == nil || isTimeout(err) {
		t.Fatalf("a ociosa mais antiga não foi fechada: %v", err)
	}
	if got := m.Get(publicClosedMetric(closedIdle)); got != 1 {
		t.Errorf("idle %v", got)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// TestServeShutdownWithStreamClient: com um cliente SSE conectado na 9003, cancelar o Serve fecha o feed antes do
// Shutdown e o flush final ainda grava a observação feita 1 s antes (task 400); o Serve volta bem antes de
// shutdownTimeout.
func TestServeShutdownWithStreamClient(t *testing.T) {
	db, path := testDB(t)
	cfg := testConfig(path)
	cfg.FlushInterval = time.Hour // só o flush final grava
	srv := New(cfg, Deps{Log: slog.New(slog.DiscardHandler), Metrics: service.NewMetrics(), DB: db, Version: "test"})
	in, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, nil, []net.Listener{in}) }()

	resp, err := http.Get("http://" + in.Addr().String() + "/bot/v1/stream")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	for srv.hub.Clients() != 1 {
		time.Sleep(5 * time.Millisecond)
	}
	srv.Agg().Observe(agg.Request{
		Time: time.Now().Add(-time.Second), IP: netip.MustParseAddr("192.0.2.40"), Site: "s.com", Path: "/",
		Class: agg.ClassHuman, UAFamily: "curl",
	})
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve não parou")
	}
	if d := time.Since(start); d > shutdownTimeout/2 {
		t.Errorf("Serve levou %s para parar com o cliente SSE", d)
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM ip_hourly").Scan(&n); err != nil || n != 1 {
		t.Fatalf("ip_hourly com %d linhas (%v): flush final perdido", n, err)
	}
}

// TestHubClose: Close encerra o serve dos clientes abertos e recusa os novos.
func TestHubClose(t *testing.T) {
	h := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &streamClient{queue: make(chan *Verdict, 1), cancel: cancel}
	if err := h.add(c); err != nil {
		t.Fatal(err)
	}
	h.Close()
	if ctx.Err() == nil || h.Clients() != 0 {
		t.Fatal("Close não encerrou o cliente")
	}
	if err := h.add(&streamClient{queue: make(chan *Verdict, 1)}); !errors.Is(err, errStreamFull) {
		t.Fatalf("add depois do Close: %v", err)
	}
}
