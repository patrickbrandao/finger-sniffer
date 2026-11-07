package service

import (
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// Nomes das métricas do produtor.
const (
	MetricPublished    = "published_events_total"
	MetricDropped      = "dropped_events_total"
	MetricBuffered     = "buffered_events"
	MetricBufferedSize = "buffered_bytes"
)

// publisher é o pedaço da nats.Conn que o produtor usa (permite testar sem servidor).
type publisher interface {
	IsConnected() bool
	PublishMsg(*nats.Msg) error
}

type pending struct {
	msg  *nats.Msg
	at   time.Time
	size int
}

// Producer publica no NATS e, quando ele está fora, guarda até maxAge / maxBytes em memória e reenvia na
// ordem; acima disso descarta os mais antigos e conta em dropped_events_total (spec 003 RF-05, ADR 0003).
type Producer struct {
	conn     publisher
	maxAge   time.Duration
	maxBytes int
	metrics  *Metrics
	now      func() time.Time

	mu    sync.Mutex
	queue []pending
	bytes int
}

// NewProducer cria um produtor sobre a conexão.
func NewProducer(conn publisher, maxAge time.Duration, maxBytes int, m *Metrics) *Producer {
	return &Producer{conn: conn, maxAge: maxAge, maxBytes: maxBytes, metrics: m, now: time.Now}
}

// Publish envia a mensagem ou a guarda no buffer. Nunca bloqueia esperando o NATS.
func (p *Producer) Publish(msg *nats.Msg) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Com fila pendente, a nova mensagem vai para o fim para manter a ordem.
	if len(p.queue) == 0 && p.conn.IsConnected() {
		if err := p.conn.PublishMsg(msg); err == nil {
			p.metrics.Add(MetricPublished, 1)
			return
		}
	}
	size := len(msg.Data) + len(msg.Subject)
	for k, v := range msg.Header {
		size += len(k)
		for _, s := range v {
			size += len(s)
		}
	}
	p.queue = append(p.queue, pending{msg: msg, at: p.now(), size: size})
	p.bytes += size
	p.trimLocked()
	p.gaugesLocked()
}

// Flush descarta o que passou de maxAge e reenvia o restante, na ordem, enquanto houver conexão.
func (p *Producer) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.trimLocked()
	for len(p.queue) > 0 && p.conn.IsConnected() {
		head := p.queue[0]
		if err := p.conn.PublishMsg(head.msg); err != nil {
			break
		}
		p.metrics.Add(MetricPublished, 1)
		p.queue = p.queue[1:]
		p.bytes -= head.size
	}
	if len(p.queue) == 0 {
		p.queue = nil
	}
	p.gaugesLocked()
}

// Buffered devolve quantas mensagens estão no buffer.
func (p *Producer) Buffered() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.queue)
}

func (p *Producer) trimLocked() {
	cut := p.now().Add(-p.maxAge)
	for len(p.queue) > 0 && (p.bytes > p.maxBytes || p.queue[0].at.Before(cut)) {
		p.bytes -= p.queue[0].size
		p.queue = p.queue[1:]
		p.metrics.Add(MetricDropped, 1)
	}
}

func (p *Producer) gaugesLocked() {
	p.metrics.Set(MetricBuffered, float64(len(p.queue)))
	p.metrics.Set(MetricBufferedSize, float64(p.bytes))
}
