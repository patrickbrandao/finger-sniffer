package raw

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/detect"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// Limites internos da sessão.
const (
	readBufSize = 32 << 10
	// maxTimed limita reads_in e writes_out para o evento caber no teto de 900 KiB (ADR 0018).
	maxTimed = 8192
	// drainAfterSource é quanto o servidor ainda lê depois de mandar o source e o FIN.
	drainAfterSource = 5 * time.Second
	// flushDelay é o prazo máximo de um pendente de fs.v1.raw.read (task 345): passado ele sem a sessão
	// publicar, o laço de leitura acorda e publica.
	flushDelay = 100 * time.Millisecond
	// minReadRoom é o espaço mínimo para a próxima leitura depois dos pendentes no buf; abaixo disso eles
	// são publicados e a leitura volta ao início do buf.
	minReadRoom = 4 << 10
)

var probePrefix = []byte("PROBE ")

// sourceBlock é o padrão repetido do modo source (ASCII imprimível, fácil de conferir).
var sourceBlock = func() []byte {
	const pattern = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
	return bytes.Repeat([]byte(pattern), readBufSize/len(pattern)+1)[:readBufSize]
}()

// session é uma conexão aceita numa porta crua.
type session struct {
	conn net.Conn
	// sock é o socket TCP aceito quando conn virou *tls.Conn (startTLS); nil em TCP claro. A conferência de
	// entrega do half-close precisa dele: os wrappers do TLS não expõem SyscallConn.
	sock  net.Conn
	cfg   *Config
	port  PortSpec
	start time.Time
	em    *emitter

	mode       string
	sourceN    int64
	bannerSent bool
	probeID    string

	// Detecção da linha PROBE: lineDone fica true quando a primeira linha do cliente foi decidida.
	lineDone bool
	lineBuf  []byte

	// TLS (spec 006 RF-02/RF-03). tlsCfg nil desliga o TLS; sniff guarda os primeiros bytes do cliente até
	// decidir se são um registro TLS (0x16 0x03).
	tlsCfg *tls.Config
	probes *probe.Extractor
	tlsOn  bool
	// hello é a captura do ClientHello do último startTLS (solta depois de publicada; os testes conferem).
	hello     *tlsparse.Conn
	sniff     []byte
	sniffDone bool
	// waitFrom é o início da espera pela linha PROBE no modo source (accept, ou fim do handshake TLS).
	waitFrom time.Time

	in, out stream
	info    Info

	// hold guarda as reservas da sessão no orçamento de entrada (RF-07b); devolvidas em defer no serve. O
	// servidor sempre o preenche; nil (só em testes de unidade) não limita.
	hold *hold
	// buf é o único buffer de leitura da sessão (retenção fixa de 32 KiB, ADR 0070 item 1). Os pendentes de
	// in e out são vistas dele; a leitura seguinte vai para depois deles (readPos).
	buf []byte
	// cur é a posição em buf dos bytes da leitura atual (-1: nenhuma); viewAt a usa para reconhecer uma vista.
	cur int
}

// testHook, nos testes, roda a cada leitura com dados (permite provocar um pânico no meio da sessão).
var testHook func(data []byte)

func newSession(conn net.Conn, cfg *Config, port PortSpec, start time.Time, em *emitter) *session {
	return &session{
		conn: conn, cfg: cfg, port: port, start: start, em: em,
		mode: port.Mode, sourceN: cfg.SourceBytes, tlsCfg: cfg.TLS, waitFrom: start,
		// Sem TLS configurado não há o que detectar.
		sniffDone: cfg.TLS == nil,
		in:        stream{dir: event.DirectionIn, max: cfg.StreamMax},
		out:       stream{dir: event.DirectionOut, max: cfg.StreamMax},
		info:      Info{ReadsIn: []TimedLength{}, WritesOut: []TimedLength{}},
		cur:       -1,
	}
}

// run atende a sessão até o fim e publica fs.v1.raw.session.
func (s *session) run() {
	defer s.finish()
	if s.port.TLS && s.tlsCfg != nil {
		// Porta tls-*: o TLS vem antes de tudo, inclusive do banner.
		s.sniffDone = true
		if !s.startTLS(nil) {
			return
		}
	}
	if s.mode == probe.ModeBanner {
		if s.sendBanner() != nil {
			return
		}
	}
	buf := s.readBuf()
	// idleFrom é o início da ociosidade (RF-07): o fim da última leitura; acordar só para publicar os
	// pendentes não a renova.
	var idleFrom time.Time
	for {
		if idleFrom.IsZero() {
			idleFrom = time.Now()
		}
		deadline := idleFrom.Add(s.cfg.Idle)
		// No modo source o servidor só espera a linha PROBE por ProbeWait; depois começa a mandar.
		waitingProbe := s.mode == probe.ModeSource && !s.lineDone
		if waitingProbe {
			deadline = s.waitFrom.Add(s.cfg.ProbeWait)
		}
		// readPos vem antes do prazo: pode publicar os pendentes para abrir espaço.
		pos := s.readPos()
		rd := deadline
		if fl := s.flushDeadline(); !fl.IsZero() && fl.Before(rd) {
			rd = fl
		}
		_ = s.conn.SetReadDeadline(rd)
		n, err := s.conn.Read(buf[pos:])
		if n > 0 {
			idleFrom = time.Time{}
			s.cur = pos
			data, upgrade := s.sniffTLS(buf[pos : pos+n])
			if upgrade != nil {
				if !s.startTLS(upgrade) {
					return
				}
				if s.mode == probe.ModeBanner && s.sendBanner() != nil {
					return
				}
				continue
			}
			if len(data) > 0 {
				if testHook != nil {
					testHook(data)
				}
				s.recordRead(data)
				data = s.feed(data)
				if s.mode == probe.ModeSource && s.lineDone {
					s.runSource()
					return
				}
				if s.handle(data) != nil {
					return
				}
			}
		}
		if err == nil {
			idleFrom = time.Time{}
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() && rd.Before(deadline) {
			// Prazo do pendente, não da ociosidade: publica e segue lendo. O crypto/tls aceita ler de novo
			// depois de um prazo vencido (erro temporário).
			s.flushStreams()
			continue
		}
		switch {
		case errors.As(err, &ne) && ne.Timeout() && waitingProbe:
			s.lineDone, s.lineBuf = true, nil
			s.runSource()
			return
		case isClientEOF(err, s.tlsOn):
			// Bytes guardados (início de TLS ou linha incompleta) viram dado comum do modo.
			var held []byte
			if sniffed, _ := s.flushSniff(); len(sniffed) > 0 {
				s.recordRead(sniffed)
				held = s.feed(sniffed)
			}
			held = append(held, s.flushLine()...)
			if s.mode == probe.ModeSource {
				s.runSource()
				return
			}
			if s.handle(held) != nil {
				return
			}
			s.halfClose()
			return
		default:
			// Ociosidade (RF-07), RST ou erro de leitura: fecha.
			return
		}
	}
}

// sniffTLS decide, pelos primeiros bytes do cliente, se a conexão é TLS (RF-03, pkg/detect). Devolve os
// bytes a tratar em claro, ou upgrade != nil com os bytes já lidos quando é TLS. Enquanto só chegou 0x16,
// guarda e espera o próximo byte.
func (s *session) sniffTLS(b []byte) (data, upgrade []byte) {
	if s.sniffDone {
		return b, nil
	}
	s.sniff = append(s.sniff, b...)
	if p, _ := detect.Classify(s.sniff); p == detect.TLS {
		up := s.sniff
		s.sniff, s.sniffDone = nil, true
		return nil, up
	}
	if len(s.sniff) < 2 && s.sniff[0] == 0x16 {
		return nil, nil
	}
	return s.flushSniff()
}

func (s *session) flushSniff() ([]byte, []byte) {
	held := s.sniff
	s.sniff, s.sniffDone = nil, true
	return held, nil
}

// feed passa os bytes pela detecção da linha PROBE e devolve o que deve ser tratado pelo modo. Enquanto os
// bytes ainda podem ser uma linha PROBE, eles ficam guardados (a linha não é ecoada, RF-04).
func (s *session) feed(b []byte) []byte {
	if s.lineDone {
		return b
	}
	if len(s.lineBuf) == 0 {
		// Nada guardado e já não começa com "PROBE ": segue como dado comum sem cópia (a vista do buf
		// continua juntável no eco, task 345).
		if k := min(len(b), len(probePrefix)); !bytes.Equal(b[:k], probePrefix[:k]) {
			s.lineDone = true
			return b
		}
	}
	s.lineBuf = append(s.lineBuf, b...)
	k := min(len(s.lineBuf), len(probePrefix))
	if !bytes.Equal(s.lineBuf[:k], probePrefix[:k]) {
		return s.flushLine()
	}
	i := bytes.IndexByte(s.lineBuf, '\n')
	if i < 0 {
		if len(s.lineBuf) >= probe.MaxLineLen {
			return s.flushLine()
		}
		return nil
	}
	line := s.lineBuf[:i+1]
	pl, err := probe.ParseLine(line)
	if err != nil {
		// Começa com "PROBE " mas não é uma linha válida: segue como dado comum.
		return s.flushLine()
	}
	rest := append([]byte(nil), s.lineBuf[i+1:]...)
	s.lineDone, s.lineBuf = true, nil
	s.applyProbe(string(line), pl)
	return rest
}

// flushLine encerra a detecção e devolve os bytes guardados.
func (s *session) flushLine() []byte {
	held := s.lineBuf
	s.lineDone, s.lineBuf = true, nil
	return held
}

// applyProbe associa o probe e troca o modo pedido pela linha.
func (s *session) applyProbe(line string, pl probe.Line) {
	s.info.ProbeLine = &line
	s.probeID = pl.ID
	if pl.N > 0 {
		// n acima do máximo é cortado e a linha continua válida (spec 006 RF-02, ADR 0035).
		s.sourceN = min(pl.N, MaxSourceBytes)
	}
	if pl.Mode != "" {
		s.mode = pl.Mode
	}
	if s.mode == probe.ModeBanner && !s.bannerSent {
		_ = s.sendBanner()
	}
}

// handle aplica o modo aos bytes do cliente.
func (s *session) handle(data []byte) error {
	if len(data) == 0 || s.mode != probe.ModeEcho {
		// banner (depois do banner) e sink só recebem.
		return nil
	}
	return s.write(data)
}

func (s *session) sendBanner() error {
	s.bannerSent = true
	b := s.port.Banner
	s.info.Banner = &b
	return s.write([]byte(b))
}

// runSource manda sourceN bytes, fecha o sentido de escrita e ainda lê o que o cliente mandar por um tempo.
func (s *session) runSource() {
	left := s.sourceN
	for left > 0 {
		n := min(left, int64(len(sourceBlock)))
		if s.write(sourceBlock[:n]) != nil {
			return
		}
		left -= n
	}
	if closeWrite(s.conn) != nil {
		return
	}
	buf := s.readBuf()
	_ = s.conn.SetReadDeadline(time.Now().Add(drainAfterSource))
	for {
		pos := s.readPos()
		n, err := s.conn.Read(buf[pos:])
		if n > 0 {
			s.cur = pos
			s.recordRead(buf[pos : pos+n])
		}
		if err != nil {
			return
		}
	}
}

// write manda bytes ao cliente, registra a escrita e publica o sentido out.
func (s *session) write(b []byte) error {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.cfg.Idle))
	n, err := s.conn.Write(b)
	if n > 0 {
		now := time.Now()
		s.info.WritesOut = s.appendTimed(s.info.WritesOut, &s.info.WritesOutTruncated, s.elapsedMS(now), n)
		s.out.add(s.em, s.buf, now, s.probeID, b[:n], s.viewAt(b))
	}
	return err
}

func (s *session) recordRead(b []byte) {
	now := time.Now()
	s.info.ReadsIn = s.appendTimed(s.info.ReadsIn, &s.info.ReadsInTruncated, s.elapsedMS(now), len(b))
	s.in.add(s.em, s.buf, now, s.probeID, b, s.viewAt(b))
}

// viewAt devolve a posição de b em buf quando b é a vista da leitura atual (começa em cur), ou -1.
func (s *session) viewAt(b []byte) int {
	if s.cur >= 0 && s.cur < len(s.buf) && len(b) > 0 && &b[0] == &s.buf[s.cur] {
		return s.cur
	}
	return -1
}

// readPos devolve onde a próxima leitura entra em buf: depois dos pendentes, que não podem ser sobrescritos.
// Com menos de minReadRoom livres, publica os pendentes e volta ao início.
func (s *session) readPos() int {
	end := 0
	for _, st := range []*stream{&s.in, &s.out} {
		if st.pending() {
			end = max(end, st.pEnd)
		}
	}
	if len(s.buf)-end < minReadRoom {
		s.flushStreams()
		return 0
	}
	return end
}

// flushDeadline é quando o pendente mais antigo precisa sair (zero sem pendente).
func (s *session) flushDeadline() time.Time {
	var t time.Time
	for _, st := range []*stream{&s.in, &s.out} {
		if st.pending() && (t.IsZero() || st.pTS.Before(t)) {
			t = st.pTS
		}
	}
	if t.IsZero() {
		return t
	}
	return t.Add(flushDelay)
}

// flushStreams publica os pendentes dos dois sentidos.
func (s *session) flushStreams() {
	s.in.flush(s.em, s.buf)
	s.out.flush(s.em, s.buf)
}

// elapsedMS é o tempo desde o accept em milissegundos, com resolução de nanossegundo.
func (s *session) elapsedMS(t time.Time) float64 {
	return float64(t.Sub(s.start).Nanoseconds()) / 1e6
}

// readBuf devolve o buffer de leitura da sessão, criado uma vez.
func (s *session) readBuf() []byte {
	if s.buf == nil {
		s.buf = make([]byte, readBufSize)
	}
	return s.buf
}

// appendTimed acrescenta [ms, n] até maxTimed itens; dali em diante descarta e liga *cut. A capacidade cresce
// sob controle: até fixedTimed entradas é retenção fixa; acima, cada crescimento reserva antes do orçamento de
// entrada e, sem ele, a lista para com a marca (spec 006 RF-06 e RF-07b).
func (s *session) appendTimed(list []TimedLength, cut *bool, ms float64, n int) []TimedLength {
	if *cut || len(list) >= maxTimed {
		*cut = true
		return list
	}
	if len(list) == cap(list) {
		c := cap(list)
		var next int
		if c < fixedTimed {
			next = min(max(2*c, 16), fixedTimed)
		} else {
			next = min(2*c, maxTimed)
			if s.hold != nil && !s.hold.reserve(int64(next-c)*timedSize, false) {
				*cut = true
				return list
			}
		}
		grown := make([]TimedLength, len(list), next)
		copy(grown, list)
		list = grown
	}
	return append(list, TimedLength{ms, float64(n)})
}

// finish fecha a conexão e publica o resumo da sessão (ts = accept, para o store achar a conexão).
func (s *session) finish() {
	_ = s.conn.Close()
	// Os pendentes saem antes do resumo, como quando cada leitura era publicada na hora.
	s.flushStreams()
	s.info.Mode = s.mode
	s.em.publish(event.SubjectRawSession, s.start, s.probeID, s.info)
}
