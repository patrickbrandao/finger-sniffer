package service

import (
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

func TestLoadConfigDefaults(t *testing.T) {
	for _, k := range []string{"FS_NATS_URL", "FS_LOG_LEVEL", "FS_PRODUCER_BUFFER_MAX_AGE", "FS_PRODUCER_BUFFER_MAX_BYTES", "FS_HEARTBEAT_INTERVAL"} {
		t.Setenv(k, "")
	}
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.NATSURL != "nats://127.0.0.1:4222" || c.LogLevel != slog.LevelInfo || c.BufferMaxAge != 30*time.Second ||
		c.BufferMaxBytes != 16<<20 || c.HeartbeatInterval != 5*time.Second {
		t.Fatalf("%+v", c)
	}
}

func TestLoadConfigValues(t *testing.T) {
	t.Setenv("FS_NATS_URL", "nats://x:1")
	t.Setenv("FS_LOG_LEVEL", "debug")
	t.Setenv("FS_PRODUCER_BUFFER_MAX_AGE", "2s")
	t.Setenv("FS_PRODUCER_BUFFER_MAX_BYTES", "100")
	t.Setenv("FS_HEARTBEAT_INTERVAL", "1s")
	c, err := LoadConfig()
	if err != nil || c.NATSURL != "nats://x:1" || c.LogLevel != slog.LevelDebug || c.BufferMaxAge != 2*time.Second ||
		c.BufferMaxBytes != 100 || c.HeartbeatInterval != time.Second {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	for k, v := range map[string]string{
		"FS_LOG_LEVEL": "loud", "FS_PRODUCER_BUFFER_MAX_AGE": "x", "FS_PRODUCER_BUFFER_MAX_BYTES": "x", "FS_HEARTBEAT_INTERVAL": "x",
	} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := LoadConfig(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestMetrics(t *testing.T) {
	m := NewMetrics()
	m.Add("a", 2)
	m.Add("a", 3)
	m.Set("b", 7)
	if m.Get("a") != 5 || m.Get("b") != 7 || m.Get("c") != 0 {
		t.Fatalf("%v", m.Snapshot())
	}
	s := m.Snapshot()
	s["a"] = 0
	if m.Get("a") != 5 {
		t.Fatal("snapshot must be a copy")
	}
}

// fakeConn simula a conexão NATS.
type fakeConn struct {
	connected bool
	fail      bool
	sent      []string
}

func (f *fakeConn) IsConnected() bool { return f.connected }
func (f *fakeConn) PublishMsg(m *nats.Msg) error {
	if f.fail {
		return errors.New("publish failed")
	}
	f.sent = append(f.sent, string(m.Data))
	return nil
}

func msg(s string) *nats.Msg {
	return &nats.Msg{Subject: "fs.v1.x", Data: []byte(s), Header: nats.Header{"K": []string{"v"}}}
}

func TestProducerConnected(t *testing.T) {
	c := &fakeConn{connected: true}
	m := NewMetrics()
	p := NewProducer(c, time.Minute, 1<<20, m)
	p.Publish(msg("a"))
	if len(c.sent) != 1 || m.Get(MetricPublished) != 1 || p.Buffered() != 0 {
		t.Fatalf("sent=%v metrics=%v", c.sent, m.Snapshot())
	}
}

func TestProducerBuffersAndFlushesInOrder(t *testing.T) {
	c := &fakeConn{}
	m := NewMetrics()
	p := NewProducer(c, time.Minute, 1<<20, m)
	p.Publish(msg("a"))
	p.Publish(msg("b"))
	c.connected = true
	// Com fila pendente, a nova mensagem não fura a fila.
	p.Publish(msg("c"))
	if len(c.sent) != 0 || p.Buffered() != 3 || m.Get(MetricBuffered) != 3 {
		t.Fatalf("sent=%v buffered=%d", c.sent, p.Buffered())
	}
	p.Flush()
	if got := c.sent; len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("order: %v", got)
	}
	if p.Buffered() != 0 || m.Get(MetricBufferedSize) != 0 || m.Get(MetricPublished) != 3 {
		t.Fatalf("metrics: %v", m.Snapshot())
	}
}

func TestProducerPublishErrorBuffers(t *testing.T) {
	c := &fakeConn{connected: true, fail: true}
	p := NewProducer(c, time.Minute, 1<<20, NewMetrics())
	p.Publish(msg("a"))
	p.Flush() // continua falhando: fica no buffer
	if p.Buffered() != 1 {
		t.Fatalf("buffered=%d", p.Buffered())
	}
}

func TestProducerDropsByAge(t *testing.T) {
	c := &fakeConn{}
	m := NewMetrics()
	p := NewProducer(c, 30*time.Second, 1<<20, m)
	now := time.Now()
	p.now = func() time.Time { return now }
	p.Publish(msg("old"))
	now = now.Add(31 * time.Second)
	p.Publish(msg("new"))
	c.connected = true
	p.Flush()
	if len(c.sent) != 1 || c.sent[0] != "new" || m.Get(MetricDropped) != 1 {
		t.Fatalf("sent=%v metrics=%v", c.sent, m.Snapshot())
	}
}

func TestProducerDropsBySize(t *testing.T) {
	c := &fakeConn{}
	m := NewMetrics()
	// Cada mensagem ocupa 7 (subject) + 2 (header) + 4 (dados) = 13 bytes.
	p := NewProducer(c, time.Minute, 30, m)
	for _, s := range []string{"aaaa", "bbbb", "cccc"} {
		p.Publish(msg(s))
	}
	if p.Buffered() != 2 || m.Get(MetricDropped) != 1 {
		t.Fatalf("buffered=%d metrics=%v", p.Buffered(), m.Snapshot())
	}
	c.connected = true
	p.Flush()
	if c.sent[0] != "bbbb" {
		t.Fatalf("oldest must be dropped first: %v", c.sent)
	}
}

func TestHeartbeatMessage(t *testing.T) {
	s := &Service{Name: event.ServiceWeb, Metrics: NewMetrics(), started: time.Unix(0, 0)}
	s.Metrics.Set("x", 1)
	now := time.Date(2026, 11, 7, 0, 0, 0, 5, time.UTC)

	check := func(wantStatus string, wantReasons int) {
		t.Helper()
		m, err := s.HeartbeatMessage(now)
		if err != nil {
			t.Fatal(err)
		}
		if m.Subject != event.SubjectHeartbeat {
			t.Fatalf("subject %q", m.Subject)
		}
		env, err := event.Decode(m.Data)
		if err != nil {
			t.Fatal(err)
		}
		var hb event.Heartbeat
		if err := json.Unmarshal(env.Payload, &hb); err != nil {
			t.Fatal(err)
		}
		if env.Service != event.ServiceWeb || hb.Status != wantStatus || len(hb.Reasons) != wantReasons || hb.Metrics["x"] != 1 ||
			env.Ts != "2026-11-07T00:00:00.000000005Z" {
			t.Fatalf("%+v %+v", env, hb)
		}
	}
	check(event.StatusOK, 0)
	s.SetStatus(func() (string, []string) { return event.StatusDegraded, []string{"offload on"} })
	check(event.StatusDegraded, 1)
}
