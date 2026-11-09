package raw

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// loopback é o IP de escuta dos testes (no lugar de FS_LISTEN_IPV4).
var loopback = []netip.Addr{netip.MustParseAddr("127.0.0.1")}

// testEnv é um NATS embutido, o produtor real e o servidor raw em portas efêmeras.
type testEnv struct {
	srv  *Server
	msgs chan *nats.Msg
	addr []string
}

func startEnv(t *testing.T, ports []PortSpec, mutate func(*Config)) *testEnv {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: server.RANDOM_PORT, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	t.Cleanup(ns.Shutdown)
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	env := &testEnv{msgs: make(chan *nats.Msg, 4096)}
	if _, err := nc.ChanSubscribe("fs.v1.>", env.msgs); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		ListenIPs: loopback, Ports: ports, Idle: 5 * time.Second,
		SourceBytes: DefaultSourceBytes, StreamMax: DefaultStreamMax, ProbeWait: time.Second,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	metrics := service.NewMetrics()
	env.srv = New(cfg, service.NewProducer(nc, 30*time.Second, 16<<20, metrics), quietLog(), metrics)
	ctx, cancel := context.WithCancel(context.Background())
	if err := env.srv.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	for _, a := range env.srv.Addrs() {
		env.addr = append(env.addr, a.String())
	}
	done := make(chan error, 1)
	go func() { done <- env.srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Run did not return")
		}
	})
	return env
}

func dial(t *testing.T, addr string) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c.(*net.TCPConn)
}

func readN(t *testing.T, c net.Conn, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read %d: %v (got %q)", n, err, buf)
	}
	return string(buf)
}

// sessionResult junta os eventos de uma sessão: o resumo e os bytes de cada sentido remontados pelo offset.
type sessionResult struct {
	env       event.Envelope
	info      Info
	in, out   []byte
	truncated map[string]bool
	// Eventos TLS publicados pela sessão (envelope com payload cru).
	clientHello, handshake *event.Envelope
}

// waitSession lê eventos até o fs.v1.raw.session.
func (e *testEnv) waitSession(t *testing.T) sessionResult {
	t.Helper()
	res := sessionResult{truncated: map[string]bool{}}
	timeout := time.After(10 * time.Second)
	for {
		select {
		case m := <-e.msgs:
			env, err := event.Decode(m.Data)
			if err != nil {
				t.Fatal(err)
			}
			switch m.Subject {
			case event.SubjectRawRead:
				var ch event.StreamBytes
				if err := json.Unmarshal(env.Payload, &ch); err != nil {
					t.Fatal(err)
				}
				dst := &res.in
				if ch.Dir == event.DirectionOut {
					dst = &res.out
				}
				if int64(len(*dst)) != ch.Offset {
					t.Fatalf("%s offset %d, have %d", ch.Dir, ch.Offset, len(*dst))
				}
				*dst = append(*dst, ch.Data...)
				if ch.Truncated {
					res.truncated[ch.Dir] = true
				}
			case event.SubjectWebTLSClientHello:
				res.clientHello = &env
			case event.SubjectWebTLSHandshake:
				res.handshake = &env
			case event.SubjectRawSession:
				res.env = env
				if err := json.Unmarshal(env.Payload, &res.info); err != nil {
					t.Fatal(err)
				}
				return res
			}
		case <-timeout:
			t.Fatal("no fs.v1.raw.session")
		}
	}
}

func TestHalfCloseNotDelivered(t *testing.T) {
	// RF-05: cliente que chama close() sem shutdown manda FIN e responde RST ao half-close; a escrita foi
	// aceita pelo kernel, mas o registro diz que a mensagem não chegou.
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo", Banner: GenericBanner}}, nil)
	c := dial(t, env.addr[0])
	if _, err := c.Write([]byte("PROBE abcdefgh\r\nx\n")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, c, 2); got != "x\n" {
		t.Fatalf("echo = %q", got)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	r := env.waitSession(t)
	if r.info.HalfClose == nil || r.info.HalfClose.ServerSentAfterClientFIN || r.info.HalfClose.Bytes != len(HalfCloseMessage) {
		t.Errorf("half_close = %+v", r.info.HalfClose)
	}
}

func TestWaitDeliveredWithoutSocket(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	if !waitDelivered(a, time.Millisecond) {
		t.Error("pipe: want true (escrita aceita)")
	}
}

func TestEchoAndHalfClose(t *testing.T) {
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo", Banner: GenericBanner}}, nil)
	c := dial(t, env.addr[0])
	if _, err := c.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, c, 6); got != "hello\n" {
		t.Fatalf("echo = %q", got)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != HalfCloseMessage {
		t.Fatalf("after FIN = %q", rest)
	}

	r := env.waitSession(t)
	if r.info.Mode != "echo" || r.info.TLS || r.info.Banner != nil || r.info.ProbeLine != nil {
		t.Errorf("info = %+v", r.info)
	}
	if r.info.HalfClose == nil || !r.info.HalfClose.ServerSentAfterClientFIN || r.info.HalfClose.Bytes != len(HalfCloseMessage) {
		t.Errorf("half_close = %+v", r.info.HalfClose)
	}
	if string(r.in) != "hello\n" || string(r.out) != "hello\n"+HalfCloseMessage {
		t.Errorf("streams in=%q out=%q", r.in, r.out)
	}
	if len(r.info.ReadsIn) != 1 || r.info.ReadsIn[0][1] != 6 || len(r.info.WritesOut) != 2 {
		t.Errorf("timings in=%v out=%v", r.info.ReadsIn, r.info.WritesOut)
	}
	if r.info.ReadsIn[0][0] <= 0 || r.info.WritesOut[1][0] < r.info.ReadsIn[0][0] {
		t.Errorf("times in=%v out=%v", r.info.ReadsIn, r.info.WritesOut)
	}
	// 5-tupla do ponto de vista do cliente.
	local := c.LocalAddr().(*net.TCPAddr)
	remote := c.RemoteAddr().(*net.TCPAddr)
	f := r.env.Flow
	if f == nil || f.L4 != "tcp" || f.SrcIP != "127.0.0.1" || f.SrcPort != local.Port || f.DstPort != remote.Port {
		t.Errorf("flow = %+v", f)
	}
	if r.env.Service != event.ServiceRaw || r.env.ProbeID != nil {
		t.Errorf("envelope = %+v", r.env)
	}
}

func TestBannerFirstThenSink(t *testing.T) {
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "banner", Banner: BannerFor(25)}}, nil)
	c := dial(t, env.addr[0])
	// O servidor fala primeiro, antes de o cliente mandar qualquer coisa.
	if got := readN(t, c, len(BannerFor(25))); got != "220 finger-sniffer ESMTP ready\r\n" {
		t.Fatalf("banner = %q", got)
	}
	if _, err := c.Write([]byte("EHLO x\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.CloseWrite()
	rest, _ := io.ReadAll(c)
	if string(rest) != HalfCloseMessage {
		t.Fatalf("sink answered %q", rest)
	}
	r := env.waitSession(t)
	if r.info.Mode != "banner" || r.info.Banner == nil || *r.info.Banner != BannerFor(25) || string(r.in) != "EHLO x\r\n" {
		t.Errorf("info = %+v in=%q", r.info, r.in)
	}
}

func TestProbeSourceAfterBanner(t *testing.T) {
	// Critério da spec 006: na porta 21, PROBE mode=source n=1000 recebe exatamente 1000 bytes após o banner.
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "banner", Banner: BannerFor(21)}}, nil)
	c := dial(t, env.addr[0])
	if got := readN(t, c, len(BannerFor(21))); got != BannerFor(21) {
		t.Fatalf("banner = %q", got)
	}
	line := "PROBE abcdefgh mode=source n=1000\r\n"
	if _, err := c.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(data) != 1000 || !bytes.Equal(data, sourceBlock[:1000]) {
		t.Fatalf("source got %d bytes", len(data))
	}
	r := env.waitSession(t)
	if r.env.ProbeID == nil || *r.env.ProbeID != "abcdefgh" {
		t.Errorf("probe_id = %v", r.env.ProbeID)
	}
	if r.info.Mode != "source" || r.info.ProbeLine == nil || *r.info.ProbeLine != line || r.info.HalfClose != nil {
		t.Errorf("info = %+v", r.info)
	}
	if string(r.in) != line || len(r.out) != len(BannerFor(21))+1000 {
		t.Errorf("streams in=%q out=%d", r.in, len(r.out))
	}
}

func TestProbeLineNotEchoed(t *testing.T) {
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo", Banner: GenericBanner}}, nil)
	c := dial(t, env.addr[0])
	// A linha chega em pedaços; ela não é ecoada e o resto segue em echo.
	for _, p := range []string{"PRO", "BE abcdefgh", "\r\nping\n"} {
		if _, err := c.Write([]byte(p)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := readN(t, c, 5); got != "ping\n" {
		t.Fatalf("echo = %q", got)
	}
	_ = c.CloseWrite()
	_, _ = io.ReadAll(c)
	r := env.waitSession(t)
	if r.env.ProbeID == nil || *r.env.ProbeID != "abcdefgh" || r.info.Mode != "echo" {
		t.Errorf("env=%+v info=%+v", r.env, r.info)
	}
}

func TestProbeSwitchToBanner(t *testing.T) {
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "sink", Banner: GenericBanner}}, nil)
	c := dial(t, env.addr[0])
	if _, err := c.Write([]byte("PROBE abcdefgh mode=banner\n")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, c, len(GenericBanner)); got != GenericBanner {
		t.Fatalf("banner = %q", got)
	}
	_ = c.CloseWrite()
	_, _ = io.ReadAll(c)
	if r := env.waitSession(t); r.info.Mode != "banner" || r.info.Banner == nil {
		t.Errorf("info = %+v", r.info)
	}
}

func TestSourcePortWithoutProbe(t *testing.T) {
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "source"}}, func(c *Config) {
		c.ProbeWait = 100 * time.Millisecond
		c.SourceBytes = 100_000
	})
	c := dial(t, env.addr[0])
	data, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(data) != 100_000 {
		t.Fatalf("got %d bytes", len(data))
	}
	r := env.waitSession(t)
	if r.info.Mode != "source" || len(r.out) != 100_000 || len(r.info.WritesOut) < 2 {
		t.Errorf("mode=%s out=%d writes=%d", r.info.Mode, len(r.out), len(r.info.WritesOut))
	}
}

func TestSourceClientClosesFirst(t *testing.T) {
	// Linha incompleta e FIN do cliente: o source manda assim mesmo e fecha.
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "source"}}, func(c *Config) { c.SourceBytes = 10 })
	c := dial(t, env.addr[0])
	_, _ = c.Write([]byte("PROBE abc"))
	_ = c.CloseWrite()
	data, _ := io.ReadAll(c)
	if len(data) != 10 {
		t.Fatalf("got %d bytes", len(data))
	}
	if r := env.waitSession(t); string(r.in) != "PROBE abc" || r.info.ProbeLine != nil {
		t.Errorf("in=%q info=%+v", r.in, r.info)
	}
}

func TestIdleTimeout(t *testing.T) {
	// RF-07: sem atividade, o servidor espera FS_IDLE_DEFAULT e só então fecha (sem half-close).
	const idle = 300 * time.Millisecond
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo"}}, func(c *Config) { c.Idle = idle })
	c := dial(t, env.addr[0])
	start := time.Now()
	data, _ := io.ReadAll(c)
	if el := time.Since(start); el < idle-20*time.Millisecond {
		t.Fatalf("closed after %v (< %v)", el, idle)
	}
	if len(data) != 0 {
		t.Errorf("got %q", data)
	}
	if r := env.waitSession(t); r.info.HalfClose != nil {
		t.Errorf("half_close = %+v", r.info.HalfClose)
	}
}

func TestStreamTruncated(t *testing.T) {
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo"}}, func(c *Config) { c.StreamMax = 10 })
	c := dial(t, env.addr[0])
	msg := strings.Repeat("a", 20)
	_, _ = c.Write([]byte(msg))
	if got := readN(t, c, 20); got != msg {
		t.Fatalf("echo = %q", got)
	}
	_ = c.CloseWrite()
	_, _ = io.ReadAll(c)
	r := env.waitSession(t)
	if len(r.in) != 10 || len(r.out) != 10 || !r.truncated[event.DirectionIn] || !r.truncated[event.DirectionOut] {
		t.Errorf("in=%d out=%d truncated=%v", len(r.in), len(r.out), r.truncated)
	}
	// O registro de tempos continua completo mesmo com o fluxo truncado.
	if len(r.info.ReadsIn) == 0 || r.info.ReadsIn[0][1] != 20 {
		t.Errorf("reads_in = %v", r.info.ReadsIn)
	}
}

func TestTLSModeWithoutConfigServesPlain(t *testing.T) {
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "banner", TLS: true, Banner: BannerFor(993)}}, nil)
	c := dial(t, env.addr[0])
	if got := readN(t, c, len(BannerFor(993))); got != BannerFor(993) {
		t.Fatalf("banner = %q", got)
	}
	_ = c.CloseWrite()
	_, _ = io.ReadAll(c)
	if r := env.waitSession(t); r.info.TLS {
		t.Error("tls = true")
	}
}

func TestShutdownClosesSessions(t *testing.T) {
	pub := &fakePub{}
	srv := New(Config{
		ListenIPs: loopback, Ports: []PortSpec{{Port: 0, Mode: "sink"}, {Port: 0, Mode: "echo"}},
		Idle: time.Minute, StreamMax: DefaultStreamMax, SourceBytes: 1, ProbeWait: time.Second,
	}, pub, quietLog(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	// Run abre as portas sozinho quando Listen não foi chamado.
	go func() { done <- srv.Run(ctx) }()
	var addrs []net.Addr
	for i := 0; i < 100 && len(addrs) < 2; i++ {
		time.Sleep(10 * time.Millisecond)
		addrs = srv.Addrs()
	}
	if len(addrs) != 2 {
		t.Fatalf("addrs = %v", addrs)
	}
	c := dial(t, addrs[0].String())
	_, _ = c.Write([]byte("x"))
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	var sessions int
	for _, m := range pub.all() {
		if m.Subject == event.SubjectRawSession {
			sessions++
		}
	}
	if sessions != 1 {
		t.Errorf("sessions = %d", sessions)
	}
}

func TestListenError(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	port := busy.Addr().(*net.TCPAddr).Port
	srv := New(Config{ListenIPs: loopback, Ports: []PortSpec{{Port: 0, Mode: "echo"}, {Port: port, Mode: "echo"}}}, &fakePub{}, quietLog(), nil)
	if err := srv.Run(context.Background()); err == nil {
		t.Fatal("Run with busy port: nil error")
	}
	if len(srv.Addrs()) != 0 {
		t.Error("listeners left open")
	}
}

func TestListenOnlyConfiguredIPs(t *testing.T) {
	// ADR 0001: um socket por IP configurado e porta; nenhum em todos os endereços.
	ips := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	if ln, err := net.Listen("tcp", "[::1]:0"); err == nil {
		_ = ln.Close()
		ips = append(ips, netip.MustParseAddr("::1"))
	}
	srv := New(Config{ListenIPs: ips, Ports: []PortSpec{{Port: 0, Mode: "echo"}, {Port: 0, Mode: "sink"}}}, &fakePub{}, quietLog(), nil)
	if err := srv.Listen(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.closeListeners()
	addrs := srv.Addrs()
	if len(addrs) != 2*len(ips) {
		t.Fatalf("addrs = %v", addrs)
	}
	for i, a := range addrs {
		ip := a.(*net.TCPAddr).AddrPort().Addr()
		if ip.IsUnspecified() || ip != ips[i%len(ips)] {
			t.Errorf("addr %d = %v", i, a)
		}
	}

	if err := New(Config{Ports: []PortSpec{{Port: 0, Mode: "echo"}}}, &fakePub{}, quietLog(), nil).Listen(context.Background()); err == nil {
		t.Error("Listen without ListenIPs: nil error")
	}
}

func TestFlowOfNonTCP(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	if f := flowOf(a); f.SrcIP != "" || f.DstPort != 0 {
		t.Errorf("flow = %+v", f)
	}
	if closeWrite(a) == nil {
		t.Error("closeWrite on pipe: nil error")
	}
}
