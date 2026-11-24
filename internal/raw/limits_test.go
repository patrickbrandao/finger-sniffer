package raw

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
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

// trickleConn entrega n bytes, um por Read, e depois bloqueia até Close (a sessão fica viva, como um cliente
// que parou de mandar); o prazo de leitura é ignorado. Escritas são descartadas.
type trickleConn struct {
	discardConn
	left   int
	fed    chan struct{}
	closed chan struct{}
	once   sync.Once
}

func newTrickleConn(n int) *trickleConn {
	return &trickleConn{left: n, fed: make(chan struct{}), closed: make(chan struct{})}
}

func (c *trickleConn) Read(p []byte) (int, error) {
	if c.left > 0 {
		c.left--
		p[0] = 'x'
		if c.left == 0 {
			close(c.fed)
		}
		return 1, nil
	}
	<-c.closed
	return 0, io.EOF
}

func (c *trickleConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (*trickleConn) SetReadDeadline(time.Time) error { return nil }
func (*trickleConn) CloseWrite() error               { return nil }

// countPub conta os eventos sem guardá-los; dos resumos guarda só as marcas de corte.
type countPub struct {
	reads, sessions, cutIn, cutOut atomic.Int64
}

func (p *countPub) Publish(m *nats.Msg) {
	switch m.Subject {
	case event.SubjectRawRead:
		p.reads.Add(1)
	case event.SubjectRawSession:
		p.sessions.Add(1)
		env, err := event.Decode(m.Data)
		if err != nil {
			return
		}
		var info Info
		if json.Unmarshal(env.Payload, &info) != nil {
			return
		}
		if info.ReadsInTruncated {
			p.cutIn.Add(1)
		}
		if info.WritesOutTruncated {
			p.cutOut.Add(1)
		}
	}
}

// TestEchoMemoryThousandSessions: 1000 sessões de eco vivas, cada uma com 8192 leituras de 1 byte, ficam
// abaixo de um teto de heap (as listas reservam do orçamento de 64 MiB e as cortadas trazem *_truncated), e
// os bytes saem juntados em poucos fs.v1.raw.read por sessão em vez de 2 por byte (task 345, spec 006 RF-06 e
// RF-07b). O heap inclui o buf de 32 KiB de cada sessão; a conta da ADR 0070 item 8 é 64 MiB do orçamento +
// 1000 × (32 KiB das listas fixas + 32 KiB do buf), abaixo do GOMEMLIMIT de 192 MiB.
func TestEchoMemoryThousandSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("1000 sessões × 8192 leituras")
	}
	sessions := 1000
	if raceOn {
		// Com -race o mesmo laço leva muito mais: menos sessões, sem os tetos de heap e de corte.
		sessions = 40
	}
	const heapCap = 144 << 20
	pub := &countPub{}
	metrics := service.NewMetrics()
	budget := newInputBudget(InputBudget, metrics)
	cfg := &Config{Idle: time.Minute, StreamMax: DefaultStreamMax}
	em := &emitter{pub: pub, log: quietLog(), flow: &event.Flow{L4: "tcp"}, metrics: metrics}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	conns := make([]*trickleConn, sessions)
	var wg sync.WaitGroup
	for i := range conns {
		c := newTrickleConn(maxTimed)
		conns[i] = c
		s := newSession(c, cfg, PortSpec{Port: 7, Mode: probe.ModeEcho}, time.Now(), em)
		s.hold = &hold{b: budget}
		wg.Go(func() {
			defer s.hold.releaseAll()
			s.run()
		})
	}
	for _, c := range conns {
		<-c.fed
	}
	// Todas as leituras feitas e as sessões vivas, paradas no Read seguinte.
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	heap := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	used := budget.inUse()
	t.Logf("heap vivo %.1f MiB com %d sessões; orçamento usado %.1f MiB; fs.v1.raw.read publicados %d",
		float64(heap)/(1<<20), sessions, float64(used)/(1<<20), pub.reads.Load())
	if !raceOn && heap > heapCap {
		t.Errorf("heap vivo %.1f MiB > teto %d MiB", float64(heap)/(1<<20), heapCap>>20)
	}
	if used > InputBudget {
		t.Errorf("orçamento usado %d > %d", used, InputBudget)
	}

	for _, c := range conns {
		_ = c.Close()
	}
	wg.Wait()
	if got := pub.sessions.Load(); got != int64(sessions) {
		t.Fatalf("fs.v1.raw.session = %d", got)
	}
	t.Logf("fs.v1.raw.read no fim: %d; listas cortadas in=%d out=%d", pub.reads.Load(), pub.cutIn.Load(), pub.cutOut.Load())
	// Por sessão: in juntado (1) e out juntado mais o half-close (2); folga para um pedaço a mais.
	if got := pub.reads.Load(); got > int64(4*sessions) {
		t.Errorf("fs.v1.raw.read = %d para %d sessões (teto %d)", got, sessions, 4*sessions)
	}
	if !raceOn && (pub.cutIn.Load() == 0 || pub.cutOut.Load() == 0) {
		t.Errorf("sem listas cortadas pelo orçamento: in=%d out=%d", pub.cutIn.Load(), pub.cutOut.Load())
	}
	if got := budget.inUse(); got != 0 {
		t.Errorf("orçamento não voltou a zero: %d", got)
	}
}
