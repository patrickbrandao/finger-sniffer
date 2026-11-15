package store

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// Limiares do health do store para o consumidor do FS_EVENTS (ADR 0041 item 3, spec 004 RF-09).
const (
	backlogDegraded = 5 * time.Second // backlog acima disso: degraded ("ingest backlog <n>s")
	lostWindow      = 5 * time.Minute // perda dentro desta janela: degraded ("stream lost <n> messages in 5m")
)

// streamStats acompanha a posição do consumidor no stream: mensagens perdidas (saltos de Sequence.Stream),
// backlog e pendentes. Escrito pelo laço de ingest; lido pelo heartbeat e pelo /metrics (com a trava).
type streamStats struct {
	mu      sync.Mutex
	maxSeq  uint64  // maior Sequence.Stream visto; 0 = nenhum desde a partida
	lost    uint64  // fs_store_stream_lost_total
	backlog float64 // fs_store_ingest_backlog_seconds
	pending uint64  // fs_store_ingest_pending_messages
	lostLog []lostAt
}

// lostAt é uma perda detectada no instante de parede at.
type lostAt struct {
	at time.Time
	n  uint64
}

// observe registra o metadado de uma mensagem processada no instante de parede wall e devolve quantas mensagens
// o salto de sequência dela revela (0 sem salto, na reentrega e na primeira mensagem depois da partida).
func (s *streamStats) observe(md *jetstream.MsgMetadata, wall time.Time) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !md.Timestamp.IsZero() {
		s.backlog = max(wall.Sub(md.Timestamp).Seconds(), 0)
	}
	s.pending = md.NumPending
	seq := md.Sequence.Stream
	var gap uint64
	switch {
	case seq == 0:
	case s.maxSeq == 0:
		s.maxSeq = seq
	case seq > s.maxSeq:
		gap = seq - s.maxSeq - 1
		s.maxSeq = seq
	}
	if gap > 0 {
		s.lost += gap
		s.lostLog = append(s.lostLog, lostAt{at: wall, n: gap})
	}
	return gap
}

// caughtUp zera o backlog: um Fetch sem mensagens mostra que o consumidor alcançou o stream.
func (s *streamStats) caughtUp() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backlog, s.pending = 0, 0
}

// snapshot devolve os valores das métricas.
func (s *streamStats) snapshot() (lost uint64, backlog float64, pending uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lost, s.backlog, s.pending
}

// reasons devolve os motivos de degradação do store ligados ao stream no instante now.
func (s *streamStats) reasons(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	if s.backlog > backlogDegraded.Seconds() {
		out = append(out, fmt.Sprintf("ingest backlog %ds", int64(math.Round(s.backlog))))
	}
	keep := s.lostLog[:0]
	var n uint64
	for _, l := range s.lostLog {
		if now.Sub(l.at) < lostWindow {
			keep = append(keep, l)
			n += l.n
		}
	}
	s.lostLog = keep
	if n > 0 {
		out = append(out, fmt.Sprintf("stream lost %d messages in 5m", n))
	}
	return out
}

// metadataOf devolve o metadado do JetStream da mensagem (nil sem ele, nos testes sem NATS).
func metadataOf(m msgSource) *jetstream.MsgMetadata {
	if ms, ok := m.(metadataSource); ok {
		if md, err := ms.Metadata(); err == nil && md != nil {
			return md
		}
	}
	return nil
}
