package raw

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// TestSourceNClamped: n acima de 64 MiB é cortado para 64 MiB, a linha continua válida e o servidor fecha
// (spec 006 RF-02, task 162); n=1000 segue com 1000 bytes no TestProbeSourceAfterBanner.
func TestSourceNClamped(t *testing.T) {
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo"}}, func(c *Config) { c.StreamMax = 1 << 10 })
	c := dial(t, env.addr[0])
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	line := "PROBE abcdefgh mode=source n=9223372036854775807\r\n"
	if _, err := c.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, c)
	if err != nil {
		t.Fatal(err)
	}
	if n != MaxSourceBytes {
		t.Fatalf("recebeu %d bytes, esperado %d", n, MaxSourceBytes)
	}
	_ = c.Close()
	r := env.waitSession(t)
	if r.info.Mode != "source" || r.info.ProbeLine == nil || *r.info.ProbeLine != line || r.env.ProbeID == nil {
		t.Fatalf("info %+v", r.info)
	}
}

// TestMaxConnsWaits: com MaxConns 2, a 3ª conexão não é recusada nem atendida até uma das 2 fechar; depois
// recebe o banner. raw_active_sessions nunca passa de 2 (spec 006 RF-07a, task 156).
func TestMaxConnsWaits(t *testing.T) {
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "banner", Banner: GenericBanner}}, func(c *Config) { c.MaxConns = 2 })
	c1 := dial(t, env.addr[0])
	c2 := dial(t, env.addr[0])
	for _, c := range []net.Conn{c1, c2} {
		if got := readN(t, c, len(GenericBanner)); got != GenericBanner {
			t.Fatalf("banner = %q", got)
		}
	}
	c3 := dial(t, env.addr[0])
	_ = c3.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := c3.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("3ª conexão atendida sem vaga: n=%d err=%v", n, err)
	}
	if got := env.srv.metrics.Get(MetricActiveSessions); got != 2 {
		t.Fatalf("%s = %v", MetricActiveSessions, got)
	}
	_ = c1.Close()
	_ = c3.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got := readN(t, c3, len(GenericBanner)); got != GenericBanner {
		t.Fatalf("banner da 3ª = %q", got)
	}
	if got := env.srv.metrics.Get(MetricActiveSessions); got > 2 {
		t.Fatalf("%s = %v", MetricActiveSessions, got)
	}
}

// TestRunEndsWithAcceptWaiting: com as vagas cheias e um accept esperando, cancelar o contexto termina o Run
// (task 156).
func TestRunEndsWithAcceptWaiting(t *testing.T) {
	srv := New(Config{
		ListenIPs: loopback, Ports: []PortSpec{{Port: 0, Mode: "echo"}, {Port: 0, Mode: "sink"}}, MaxConns: 1,
		Idle: time.Minute, StreamMax: DefaultStreamMax, SourceBytes: 1, ProbeWait: time.Second,
	}, &fakePub{}, quietLog(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	addrs := srv.Addrs()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	c1 := dial(t, addrs[0].String())
	if _, err := c1.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, c1, 6); got != "hello\n" {
		t.Fatalf("echo = %q", got)
	}
	// As duas portas esperam vaga: uma no backlog, a outra sem accept.
	dial(t, addrs[0].String())
	dial(t, addrs[1].String())
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run não terminou com accept esperando vaga")
	}
}

// TestMaxConnsZeroUsesDefault: FS_MAX_CONNS <= 0 vira o padrão de 1000 com aviso no log (ADR 0034 item 12,
// ADR 0039 item 5).
func TestMaxConnsZeroUsesDefault(t *testing.T) {
	if DefaultMaxConns != 1000 {
		t.Fatalf("DefaultMaxConns = %d, want 1000", DefaultMaxConns)
	}
	for _, v := range []int{0, -3} {
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, nil))
		srv := New(Config{MaxConns: v}, &fakePub{}, log, nil)
		if cap(srv.sem) != 1000 || srv.cfg.MaxConns != 1000 {
			t.Fatalf("MaxConns %d: cap=%d", v, cap(srv.sem))
		}
		out := buf.String()
		if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "FS_MAX_CONNS") ||
			!strings.Contains(out, "default=1000") {
			t.Errorf("MaxConns %d: aviso ausente: %q", v, out)
		}
	}
}
