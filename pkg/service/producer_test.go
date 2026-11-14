package service

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// maxPayloadConn recusa com nats.ErrMaxPayload as mensagens de dados "big" e aceita as demais.
type maxPayloadConn struct {
	connected bool
	sent      []string
}

func (f *maxPayloadConn) IsConnected() bool { return f.connected }
func (f *maxPayloadConn) PublishMsg(m *nats.Msg) error {
	if string(m.Data) == "big" {
		return nats.ErrMaxPayload
	}
	f.sent = append(f.sent, string(m.Data))
	return nil
}

// TestProducerMaxPayloadPublish: recusa definitiva no Publish descarta e conta, sem enfileirar (task 149).
func TestProducerMaxPayloadPublish(t *testing.T) {
	c := &maxPayloadConn{connected: true}
	m := NewMetrics()
	p := NewProducer(c, time.Minute, 1<<20, m)
	p.Publish(msg("big"))
	p.Publish(msg("next"))
	if p.Buffered() != 0 || len(c.sent) != 1 || c.sent[0] != "next" || m.Get(MetricDropped) != 1 || m.Get(MetricPublished) != 1 {
		t.Fatalf("buffered=%d sent=%v metrics=%v", p.Buffered(), c.sent, m.Snapshot())
	}
}

// TestProducerMaxPayloadFlush: a mensagem grande já na fila (NATS fora no Publish) sai no Flush sem segurar
// as seguintes (task 149).
func TestProducerMaxPayloadFlush(t *testing.T) {
	c := &maxPayloadConn{}
	m := NewMetrics()
	p := NewProducer(c, time.Minute, 1<<20, m)
	p.Publish(msg("a"))
	p.Publish(msg("big"))
	p.Publish(msg("b"))
	c.connected = true
	p.Flush()
	if p.Buffered() != 0 || len(c.sent) != 2 || c.sent[0] != "a" || c.sent[1] != "b" || m.Get(MetricDropped) != 1 ||
		m.Get(MetricBufferedSize) != 0 {
		t.Fatalf("buffered=%d sent=%v metrics=%v", p.Buffered(), c.sent, m.Snapshot())
	}
}
