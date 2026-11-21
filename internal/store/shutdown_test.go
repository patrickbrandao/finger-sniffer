package store

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// syncBuffer é um bytes.Buffer seguro para o log de várias goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestStoreShutdownWaitsIngest: parar o store com lotes chegando termina o lote em curso antes de fechar os
// bancos: nenhum "database is closed" no log, nada fica sem ack/nak e Run volta em menos de 10 s (task 206).
func TestStoreShutdownWaitsIngest(t *testing.T) {
	ns := startNATS(t, 0)
	defer ns.Shutdown()
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_HEARTBEAT_INTERVAL", "100ms")

	svc, err := service.New(event.ServiceStore)
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	svc.Log = slog.New(slog.NewTextHandler(&logs, nil))
	_, path := testDB(t)
	cfg := Config{
		DBPath: path, HTTPAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)), Retention: "10m", MaxBytes: 1 << 30,
		DownAfter: time.Second, Host: hostFixture(t, false), RetentionDur: 10 * time.Minute,
		Ingest: IngestConfig{
			PcapMax: 16 << 20, TCPIdle: time.Minute, UDPIdle: 30 * time.Second, CloseGrace: 100 * time.Millisecond,
			MaxOpen: 200, MaxNewPerS: 50, Snaplen: 65535,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := newTestStore(ctx, t, svc, cfg)
	done := make(chan error, 1)
	go func() { done <- st.Run(ctx) }()

	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, _ := jetstream.New(nc)
	eventually(t, 5*time.Second, func() bool {
		_, err := js.Consumer(ctx, StreamName, ConsumerName)
		return err == nil
	}, "consumer not created")

	// Publica lotes sem parar; o store é parado no meio.
	pubCtx, stopPub := context.WithCancel(context.Background())
	defer stopPub()
	go func() {
		for i := 0; pubCtx.Err() == nil; i++ {
			cli := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.30"), uint16(10000+i%50000)) //nolint:gosec // teste
			m := batch(cli, mirror, protoTCP, fullTCP)
			_, _ = js.PublishMsg(pubCtx, natsMsg(m.subject, m.data))
		}
	}()
	time.Sleep(500 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return in 10 s")
	}
	stopPub()
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("shutdown took %v", d)
	}
	if l := logs.String(); strings.Contains(l, "database is closed") {
		t.Fatalf("SQL error after close:\n%s", l)
	}
	c, err := js.Consumer(context.Background(), StreamName, ConsumerName)
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.NumAckPending != 0 || info.Delivered.Consumer == 0 {
		t.Fatalf("ack pending %d delivered %d", info.NumAckPending, info.Delivered.Consumer)
	}
}

// TestStoreShutdownStalledAPIConn: uma conexão na API que nunca manda pedido (varredura de porta, cliente
// parado) não segura o desligamento nem vira erro do Run: vencido o prazo gracioso, a API fecha o que resta
// (task 222; era a causa do "run: context deadline exceeded" no CI, com outro processo conectado à porta).
func TestStoreShutdownStalledAPIConn(t *testing.T) {
	old := apiShutdownWait
	apiShutdownWait = 300 * time.Millisecond
	defer func() { apiShutdownWait = old }()

	ns := startNATS(t, 0)
	defer ns.Shutdown()
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_HEARTBEAT_INTERVAL", "100ms")
	svc, err := service.New(event.ServiceStore)
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	svc.Log = slog.New(slog.NewTextHandler(&logs, nil))
	_, path := testDB(t)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg := Config{
		DBPath: path, HTTPAddr: addr, Retention: "10m", MaxBytes: 1 << 30,
		DownAfter: time.Second, Host: hostFixture(t, false), RetentionDur: 10 * time.Minute,
		Ingest: IngestConfig{
			PcapMax: 16 << 20, TCPIdle: time.Minute, UDPIdle: 30 * time.Second, CloseGrace: 100 * time.Millisecond,
			MaxOpen: 200, MaxNewPerS: 50, Snaplen: 65535,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := newTestStore(ctx, t, svc, cfg)
	done := make(chan error, 1)
	go func() { done <- st.Run(ctx) }()
	var conn net.Conn
	eventually(t, 5*time.Second, func() bool {
		conn, err = net.Dial("tcp", addr)
		return err == nil
	}, "api not listening")
	defer func() { _ = conn.Close() }()
	time.Sleep(100 * time.Millisecond) // o servidor aceita e marca a conexão como nova

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return in 10 s")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("shutdown took %v with a stalled connection", d)
	}
	if !strings.Contains(logs.String(), "api shutdown timed out") {
		t.Fatalf("no warning about the forced close:\n%s", logs.String())
	}
}
