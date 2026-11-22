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
	backlogDegraded   = 5 * time.Second // backlog acima disso: degraded ("ingest backlog <n>s")
	lostWindow        = 5 * time.Minute // perda dentro desta janela: degraded ("stream lost <n> messages in 5m")
	fetchFailDegraded = 5 * time.Second // Fetch falhando há mais que isso: degraded ("ingest fetch failing <n>s")
)

// streamStats acompanha a posição do consumidor no stream: mensagens perdidas (saltos de Sequence.Stream),
// backlog e pendentes, falhas seguidas do Fetch e recriações do stream (task 320). Escrito pelo laço de ingest;
// lido pelo heartbeat e pelo /metrics (com a trava).
type streamStats struct {
	mu     sync.Mutex
	maxSeq uint64 // maior Sequence.Stream visto; 0 = nenhum desde a partida ou a recriação do stream
	lost   uint64 // fs_store_stream_lost_total
	// lastPub é o instante de publicação no stream da última mensagem processada; caught diz que um Fetch vazio
	// mostrou o consumidor em dia depois dela. O backlog sai deles no instante da leitura (ADR 0041 item 3): com o
	// ingest parado ele cresce com a parede, em vez de congelar no valor do último lote (task 338).
	lastPub time.Time
	caught  bool
	// clock é o relógio do /metrics (nil = time.Now; os testes fixam a parede).
	clock   func() time.Time
	pending uint64 // fs_store_ingest_pending_messages
	lostLog []lostAt
	// failSince é a primeira falha da sequência atual de Fetch com erro (zero enquanto o Fetch funciona).
	failSince time.Time
	recreated uint64      // fs_store_stream_recreated_total
	recLog    []time.Time // recriações dentro de lostWindow, para o health
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
		s.lastPub, s.caught = md.Timestamp, false
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
	s.caught, s.pending = true, 0
}

// backlogAt é o backlog em segundos no instante now: parede − publicação da última mensagem processada, 0 com o
// consumidor em dia ou sem mensagem desde a partida ou a recriação do stream. Chamado com a trava.
func (s *streamStats) backlogAt(now time.Time) float64 {
	if s.caught || s.lastPub.IsZero() {
		return 0
	}
	return max(now.Sub(s.lastPub).Seconds(), 0)
}

// fetchFailed registra um Fetch com erro no instante de parede wall e devolve há quanto tempo o Fetch falha sem
// interrupção.
func (s *streamStats) fetchFailed(wall time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSince.IsZero() {
		s.failSince = wall
	}
	return wall.Sub(s.failSince)
}

// fetchOK encerra a sequência de falhas do Fetch.
func (s *streamStats) fetchOK() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failSince = time.Time{}
}

// streamRecreated registra que o stream foi recriado em wall (o anterior sumiu, ex.: reinício do NATS com o
// FS_EVENTS em memória, ADR 0016). A sequência recomeça em 1: o rastreio volta a zero para não contar o recomeço
// como reentrega nem como salto. A perda entre a queda e a recriação não é mensurável pelo salto.
func (s *streamStats) streamRecreated(wall time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxSeq, s.lastPub, s.caught, s.pending = 0, time.Time{}, false, 0
	s.recreated++
	s.recLog = append(s.recLog, wall)
}

// snapshot devolve os valores das métricas agora.
func (s *streamStats) snapshot() (lost uint64, backlog float64, pending uint64) {
	now := time.Now
	if s.clock != nil {
		now = s.clock
	}
	return s.snapshotAt(now())
}

// snapshotAt devolve os valores das métricas no instante now.
func (s *streamStats) snapshotAt(now time.Time) (lost uint64, backlog float64, pending uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lost, s.backlogAt(now), s.pending
}

// recreatedTotal devolve fs_store_stream_recreated_total.
func (s *streamStats) recreatedTotal() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recreated
}

// reasons devolve os motivos de degradação do store ligados ao stream no instante now.
func (s *streamStats) reasons(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	if b := s.backlogAt(now); b > backlogDegraded.Seconds() {
		out = append(out, fmt.Sprintf("ingest backlog %ds", int64(math.Round(b))))
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
	// Com o Fetch falhando e o stream sem mensagem processada desde a partida ou a recriação, o backlog é 0: este
	// motivo cobre o ingest parado nesse caso (task 320).
	if !s.failSince.IsZero() && now.Sub(s.failSince) > fetchFailDegraded {
		out = append(out, fmt.Sprintf("ingest fetch failing %ds", int64(math.Round(now.Sub(s.failSince).Seconds()))))
	}
	rec := s.recLog[:0]
	for _, at := range s.recLog {
		if now.Sub(at) < lostWindow {
			rec = append(rec, at)
		}
	}
	s.recLog = rec
	if len(rec) > 0 {
		out = append(out, "stream recreated in 5m")
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
