package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// TestNewAndRun sobe um NATS embutido, cria o serviço e confere que Run publica heartbeat e repassa o erro de main.
func TestNewAndRun(t *testing.T) {
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: server.RANDOM_PORT, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	defer ns.Shutdown()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_HEARTBEAT_INTERVAL", "50ms")
	t.Setenv("FS_LOG_LEVEL", "error")

	obs, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer obs.Close()
	beats := make(chan *nats.Msg, 16)
	if _, err := obs.ChanSubscribe(event.SubjectHeartbeat, beats); err != nil {
		t.Fatal(err)
	}
	_ = obs.Flush()

	svc, err := New(event.ServiceRaw)
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("done")
	err = svc.Run(func(ctx context.Context) error {
		select {
		case m := <-beats:
			env, err := event.Decode(m.Data)
			if err != nil || env.Service != event.ServiceRaw {
				t.Errorf("heartbeat %v %+v", err, env)
			}
		case <-time.After(5 * time.Second):
			t.Error("no heartbeat")
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Run = %v", err)
	}
}

func TestNewBadConfig(t *testing.T) {
	t.Setenv("FS_LOG_LEVEL", "loud")
	if _, err := New("x"); err == nil {
		t.Fatal("expected error")
	}
}
