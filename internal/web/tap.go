package web

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// idleConn aplica a ociosidade do servidor (spec 005 RF-08): cada leitura e escrita tem prazo de
// "última atividade + idle". O servidor só fecha a conexão quando esse prazo vence, nunca antes.
type idleConn struct {
	net.Conn
	idle atomic.Int64 // time.Duration
	last atomic.Int64 // UnixNano da última atividade
	now  func() time.Time
}

func newIdleConn(c net.Conn, idle time.Duration, last time.Time, now func() time.Time) *idleConn {
	ic := &idleConn{Conn: c, now: now}
	ic.idle.Store(int64(idle))
	ic.last.Store(last.UnixNano())
	return ic
}

// SetIdle troca a ociosidade (controle idle=, task 023).
func (c *idleConn) SetIdle(d time.Duration) { c.idle.Store(int64(d)) }

func (c *idleConn) deadline() time.Time {
	return time.Unix(0, c.last.Load()).Add(time.Duration(c.idle.Load()))
}

func (c *idleConn) Read(p []byte) (int, error) {
	if err := c.SetReadDeadline(c.deadline()); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.last.Store(c.now().UnixNano())
	}
	return n, err
}

func (c *idleConn) Write(p []byte) (int, error) {
	// A escrita bloqueada por um cliente que não lê também conta como ociosidade.
	if err := c.SetWriteDeadline(c.now().Add(time.Duration(c.idle.Load()))); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.last.Store(c.now().UnixNano())
	}
	return n, err
}

// streamDir acumula os bytes de aplicação de um sentido e os publica em pedaços de até 64 KiB com offset
// (fs.v1.web.stream.bytes), até max bytes; passado o teto, manda um último pedaço vazio com truncated e
// para (ADR 0018). total conta todos os bytes do sentido, inclusive os não publicados.
type streamDir struct {
	dir       string
	max       int64
	emit      func(event.StreamBytes)
	total     int64
	kept      int64 // bytes já publicados ou pendentes (<= max)
	pending   []byte
	pendOff   int64
	truncated bool
}

func (s *streamDir) add(p []byte) {
	s.total += int64(len(p))
	if s.truncated || len(p) == 0 {
		return
	}
	take := int64(len(p))
	if room := s.max - s.kept; take > room {
		take = room
	}
	if len(s.pending) == 0 {
		s.pendOff = s.kept
	}
	s.pending = append(s.pending, p[:take]...)
	s.kept += take
	for len(s.pending) >= event.StreamChunkBytes {
		s.emitChunk(event.StreamChunkBytes)
	}
	if take < int64(len(p)) {
		s.flush()
		s.truncated = true
		s.emit(event.StreamBytes{Dir: s.dir, Offset: s.kept, Data: []byte{}, Truncated: true})
	}
}

func (s *streamDir) emitChunk(n int) {
	data := make([]byte, n)
	copy(data, s.pending[:n])
	s.emit(event.StreamBytes{Dir: s.dir, Offset: s.pendOff, Data: data})
	s.pendOff += int64(n)
	s.pending = s.pending[n:]
	if len(s.pending) == 0 {
		s.pending = nil
	}
}

func (s *streamDir) flush() {
	for len(s.pending) > 0 {
		n := min(len(s.pending), event.StreamChunkBytes)
		s.emitChunk(n)
	}
}

// tap envolve o fluxo de aplicação (texto claro, depois do TLS quando houver): copia os bytes lidos para o
// sentido in e os escritos para o out, e anota quando chegaram (tempos da spec 009 RF-06).
type tap struct {
	net.Conn
	now func() time.Time

	mu  sync.Mutex
	in  streamDir
	out streamDir
	// lastReadAt é o instante da última leitura com bytes; firstReadAt é o da primeira depois de markRead.
	lastReadAt  time.Time
	firstReadAt time.Time
	marked      bool
}

func newTap(c net.Conn, maxPerDir int, now func() time.Time, emit func(event.StreamBytes)) *tap {
	return &tap{
		Conn: c,
		now:  now,
		in:   streamDir{dir: event.DirectionIn, max: int64(maxPerDir), emit: emit},
		out:  streamDir{dir: event.DirectionOut, max: int64(maxPerDir), emit: emit},
	}
}

func (t *tap) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		at := t.now()
		t.mu.Lock()
		t.in.add(p[:n])
		t.lastReadAt = at
		if t.marked {
			t.firstReadAt, t.marked = at, false
		}
		t.mu.Unlock()
	}
	return n, err
}

func (t *tap) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		t.mu.Lock()
		t.out.add(p[:n])
		t.mu.Unlock()
	}
	return n, err
}

// markRead começa a esperar a próxima leitura com bytes; o instante dela sai em firstRead.
func (t *tap) markRead() {
	t.mu.Lock()
	t.marked, t.firstReadAt = true, time.Time{}
	t.mu.Unlock()
}

// firstRead devolve o instante da primeira leitura depois de markRead (zero se ainda não houve).
func (t *tap) firstRead() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.firstReadAt
}

// lastRead devolve o instante da última leitura com bytes.
func (t *tap) lastRead() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastReadAt
}

// outTotal devolve quantos bytes já saíram (offset do próximo byte no fluxo out).
func (t *tap) outTotal() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.out.total
}

// flush publica o que estiver pendente nos dois sentidos.
func (t *tap) flush() {
	t.mu.Lock()
	t.in.flush()
	t.out.flush()
	t.mu.Unlock()
}
