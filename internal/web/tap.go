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

// idleFor devolve a ociosidade corrente (padrão ou idle=).
func (c *idleConn) idleFor() time.Duration { return time.Duration(c.idle.Load()) }

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
//
// O pendente reserva do orçamento de entrada a capacidade que aloca (ADR 0036). Sem orçamento, o sentido
// não recusa nada: publica na hora o que tem (pedaço menor que 64 KiB) e segue sem reter; isso não conta
// como recusa. A reserva volta quando o pendente é publicado por inteiro.
type streamDir struct {
	dir       string
	max       int64
	emit      func(event.StreamBytes)
	budget    *inputBudget // nil: sem orçamento (testes)
	held      int64        // bytes reservados para a capacidade de pending
	total     int64
	kept      int64 // bytes já publicados ou pendentes (<= max)
	pending   []byte
	pendOff   int64
	truncated bool
}

// minPendingBuf é a menor capacidade alocada para o pendente.
const minPendingBuf = 512

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
	data := p[:take]
	s.kept += take
	for len(data) > 0 {
		if len(s.pending) == 0 && len(data) >= event.StreamChunkBytes {
			// Pedaço inteiro direto do que chegou, sem passar pelo pendente.
			s.emitData(data[:event.StreamChunkBytes])
			data = data[event.StreamChunkBytes:]
			continue
		}
		n := min(event.StreamChunkBytes-len(s.pending), len(data))
		if !s.grow(n, len(data)) {
			// Sem orçamento: publica o pendente e o resto agora, sem reter.
			s.flush()
			for len(data) > 0 {
				k := min(len(data), event.StreamChunkBytes)
				s.emitData(data[:k])
				data = data[k:]
			}
			break
		}
		s.pending = append(s.pending, data[:n]...)
		data = data[n:]
		if len(s.pending) == event.StreamChunkBytes {
			s.emitChunk(event.StreamChunkBytes)
		}
	}
	if take < int64(len(p)) {
		s.flush()
		s.truncated = true
		s.emit(event.StreamBytes{Dir: s.dir, Offset: s.kept, Data: []byte{}, Truncated: true})
	}
}

// grow garante capacidade para mais n bytes no pendente (want é quanto ainda há para acumular). A
// capacidade dobra, no mínimo minPendingBuf e no máximo um pedaço, e o crescimento é reservado antes de
// alocar. false: sem orçamento.
func (s *streamDir) grow(n, want int) bool {
	need := len(s.pending) + n
	if need <= cap(s.pending) {
		return true
	}
	newCap := min(max(2*cap(s.pending), len(s.pending)+want, minPendingBuf), event.StreamChunkBytes)
	delta := int64(newCap - cap(s.pending))
	if s.budget != nil && !s.budget.reserveTap(delta) {
		return false
	}
	s.held += delta
	nb := make([]byte, len(s.pending), newCap)
	copy(nb, s.pending)
	s.pending = nb
	return true
}

// emitData publica uma cópia de p no offset pendOff, que avança.
func (s *streamDir) emitData(p []byte) {
	data := make([]byte, len(p))
	copy(data, p)
	s.emit(event.StreamBytes{Dir: s.dir, Offset: s.pendOff, Data: data})
	s.pendOff += int64(len(p))
}

// emitChunk publica os primeiros n bytes do pendente; o resto vai para o começo do mesmo buffer. Pendente
// vazio solta o buffer e devolve a reserva.
func (s *streamDir) emitChunk(n int) {
	s.emitData(s.pending[:n])
	rest := copy(s.pending, s.pending[n:])
	s.pending = s.pending[:rest]
	if rest == 0 {
		s.pending = nil
		if s.budget != nil {
			s.budget.releaseTap(s.held)
		}
		s.held = 0
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
	// writing conta as escritas em andamento (do Write no socket até a cópia entregue ao observador);
	// writeIdle é fechado quando ela volta a zero (writesDone).
	writing   int
	writeIdle chan struct{}
}

// tapAfterWriteHook, quando definido (só em teste), roda entre a escrita no socket e a entrega da cópia ao
// observador: simula o atraso em que o cliente já recebeu os bytes e o parser passivo ainda não.
var tapAfterWriteHook func(p []byte)

// newTap cria o tap; budget (nil nos testes que não o usam) é o orçamento de entrada dos pendentes.
func newTap(c net.Conn, maxPerDir int, now func() time.Time, emit func(event.StreamBytes), budget *inputBudget) *tap {
	return &tap{
		Conn: c,
		now:  now,
		in:   streamDir{dir: event.DirectionIn, max: int64(maxPerDir), emit: emit, budget: budget},
		out:  streamDir{dir: event.DirectionOut, max: int64(maxPerDir), emit: emit, budget: budget},
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
	t.mu.Lock()
	if t.writing == 0 {
		t.writeIdle = make(chan struct{})
	}
	t.writing++
	t.mu.Unlock()
	defer t.endWrite()
	n, err := t.Conn.Write(p)
	if n > 0 {
		at := t.now()
		if hook := tapAfterWriteHook; hook != nil {
			hook(p[:n])
		}
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

// endWrite encerra uma escrita: a cópia dela já foi entregue ao observador.
func (t *tap) endWrite() {
	t.mu.Lock()
	t.writing--
	if t.writing == 0 {
		close(t.writeIdle)
	}
	t.mu.Unlock()
}

// closedChan é um canal já fechado (nenhuma escrita em andamento).
var closedChan = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// writesDone devolve um canal fechado quando as escritas em andamento agora (no socket, ainda sem a cópia
// entregue ao observador) terminarem. O cliente pode reagir a bytes que o parser passivo ainda não viu
// (RST_STREAM depois do HEADERS da resposta, task 213): quem decide pelo parser out espera esse canal.
func (t *tap) writesDone() <-chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.writing == 0 {
		return closedChan
	}
	return t.writeIdle
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

// flush publica o que estiver pendente nos dois sentidos (e devolve a reserva dos pendentes); idempotente.
func (t *tap) flush() {
	t.mu.Lock()
	t.in.flush()
	t.out.flush()
	t.mu.Unlock()
}
