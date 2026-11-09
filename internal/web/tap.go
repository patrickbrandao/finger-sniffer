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

	// dmu serializa o cálculo do prazo de leitura com hold/release; active conta os streams h2 em
	// atendimento: com algum ativo a conexão não está ociosa e a leitura fica sem prazo.
	dmu    sync.Mutex
	active int
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

// hold marca um stream h2 em atendimento: enquanto houver algum, a ociosidade não corre (o leitor do h2
// fica bloqueado na leitura durante um delay_head, por exemplo, e não pode vencer o prazo).
func (c *idleConn) hold() {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	c.active++
	if c.active == 1 {
		_ = c.SetReadDeadline(time.Time{})
	}
}

// release encerra um stream de hold; o último a sair recomeça a contagem da ociosidade.
func (c *idleConn) release() {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	c.active--
	if c.active == 0 {
		c.last.Store(c.now().UnixNano())
		_ = c.SetReadDeadline(c.deadline())
	}
}

func (c *idleConn) Read(p []byte) (int, error) {
	c.dmu.Lock()
	var dl time.Time
	if c.active == 0 {
		dl = c.deadline()
	}
	err := c.SetReadDeadline(dl)
	c.dmu.Unlock()
	if err != nil {
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
	// observe, quando definido, recebe uma cópia de cada leitura (in) e escrita (out) com o instante, fora
	// do mu (parser passivo do h2).
	observe atomic.Pointer[func(dir string, at time.Time, p []byte)]

	mu  sync.Mutex
	in  streamDir
	out streamDir
	// lastReadAt é o instante da última leitura com bytes; firstReadAt é o da primeira depois de markRead.
	lastReadAt  time.Time
	firstReadAt time.Time
	marked      bool
	// firstWriteAt é o instante da primeira escrita com bytes depois de markWrite; lastWriteAt o da última
	// (instantes da resposta, spec 009 RF-06).
	firstWriteAt time.Time
	lastWriteAt  time.Time
	writeMarked  bool
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
		if f := t.observe.Load(); f != nil {
			(*f)(event.DirectionIn, at, p[:n])
		}
	}
	return n, err
}

func (t *tap) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		at := t.now()
		t.mu.Lock()
		t.out.add(p[:n])
		t.lastWriteAt = at
		if t.writeMarked {
			t.firstWriteAt, t.writeMarked = at, false
		}
		t.mu.Unlock()
		if f := t.observe.Load(); f != nil {
			(*f)(event.DirectionOut, at, p[:n])
		}
	}
	return n, err
}

// setObserver liga (ou desliga, com nil) a cópia das leituras e escritas.
func (t *tap) setObserver(f func(dir string, at time.Time, p []byte)) {
	if f == nil {
		t.observe.Store(nil)
		return
	}
	t.observe.Store(&f)
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

// markWrite começa a esperar a próxima escrita com bytes (início de uma resposta HTTP/1).
func (t *tap) markWrite() {
	t.mu.Lock()
	t.writeMarked, t.firstWriteAt = true, time.Time{}
	t.mu.Unlock()
}

// writeTimes devolve o instante da primeira escrita depois de markWrite (zero se não houve) e o da última.
func (t *tap) writeTimes() (first, last time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.firstWriteAt, t.lastWriteAt
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
