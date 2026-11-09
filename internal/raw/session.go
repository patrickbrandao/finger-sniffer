package raw

import (
	"bytes"
	"errors"
	"io"
	"net"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
)

// Limites internos da sessão.
const (
	readBufSize = 32 << 10
	// maxTimed limita reads_in e writes_out para o evento caber no teto de 900 KiB (ADR 0018).
	maxTimed = 8192
	// drainAfterSource é quanto o servidor ainda lê depois de mandar o source e o FIN.
	drainAfterSource = 5 * time.Second
)

var probePrefix = []byte("PROBE ")

// sourceBlock é o padrão repetido do modo source (ASCII imprimível, fácil de conferir).
var sourceBlock = func() []byte {
	const pattern = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
	return bytes.Repeat([]byte(pattern), readBufSize/len(pattern)+1)[:readBufSize]
}()

// session é uma conexão aceita numa porta crua.
type session struct {
	conn  net.Conn
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

	in, out stream
	info    Info
}

func newSession(conn net.Conn, cfg *Config, port PortSpec, start time.Time, em *emitter) *session {
	return &session{
		conn: conn, cfg: cfg, port: port, start: start, em: em,
		mode: port.Mode, sourceN: cfg.SourceBytes,
		in:   stream{dir: event.DirectionIn, max: cfg.StreamMax},
		out:  stream{dir: event.DirectionOut, max: cfg.StreamMax},
		info: Info{TLS: port.TLS, ReadsIn: []TimedLength{}, WritesOut: []TimedLength{}},
	}
}

// run atende a sessão até o fim e publica fs.v1.raw.session.
func (s *session) run() {
	defer s.finish()
	if s.mode == probe.ModeBanner {
		if s.sendBanner() != nil {
			return
		}
	}
	buf := make([]byte, readBufSize)
	for {
		deadline := time.Now().Add(s.cfg.Idle)
		// No modo source o servidor só espera a linha PROBE por ProbeWait; depois começa a mandar.
		waitingProbe := s.mode == probe.ModeSource && !s.lineDone
		if waitingProbe {
			deadline = s.start.Add(s.cfg.ProbeWait)
		}
		_ = s.conn.SetReadDeadline(deadline)
		n, err := s.conn.Read(buf)
		if n > 0 {
			s.recordRead(buf[:n])
			data := s.feed(buf[:n])
			if s.mode == probe.ModeSource && s.lineDone {
				s.runSource()
				return
			}
			if s.handle(data) != nil {
				return
			}
		}
		if err == nil {
			continue
		}
		var ne net.Error
		switch {
		case errors.As(err, &ne) && ne.Timeout() && waitingProbe:
			s.lineDone, s.lineBuf = true, nil
			s.runSource()
			return
		case errors.Is(err, io.EOF):
			// Linha incompleta guardada vira dado comum do modo.
			held := s.flushLine()
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

// feed passa os bytes pela detecção da linha PROBE e devolve o que deve ser tratado pelo modo. Enquanto os
// bytes ainda podem ser uma linha PROBE, eles ficam guardados (a linha não é ecoada, RF-04).
func (s *session) feed(b []byte) []byte {
	if s.lineDone {
		return b
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
		s.sourceN = pl.N
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
	buf := make([]byte, readBufSize)
	_ = s.conn.SetReadDeadline(time.Now().Add(drainAfterSource))
	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			s.recordRead(buf[:n])
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
		s.info.WritesOut = appendTimed(s.info.WritesOut, s.elapsedMS(now), n)
		s.out.write(s.em, now, s.probeID, b[:n])
	}
	return err
}

func (s *session) recordRead(b []byte) {
	now := time.Now()
	s.info.ReadsIn = appendTimed(s.info.ReadsIn, s.elapsedMS(now), len(b))
	s.in.write(s.em, now, s.probeID, b)
}

// elapsedMS é o tempo desde o accept em milissegundos, com resolução de nanossegundo.
func (s *session) elapsedMS(t time.Time) float64 {
	return float64(t.Sub(s.start).Nanoseconds()) / 1e6
}

func appendTimed(list []TimedLength, ms float64, n int) []TimedLength {
	if len(list) >= maxTimed {
		return list
	}
	return append(list, TimedLength{ms, float64(n)})
}

// finish fecha a conexão e publica o resumo da sessão (ts = accept, para o store achar a conexão).
func (s *session) finish() {
	_ = s.conn.Close()
	s.info.Mode = s.mode
	s.em.publish(event.SubjectRawSession, s.start, s.probeID, s.info)
}
