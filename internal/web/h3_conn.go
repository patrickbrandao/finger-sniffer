package web

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// h3Conn é uma conexão QUIC/HTTP/3 aceita. O h3 é do próprio web (RFC 9114 sem push, QPACK sem tabela
// dinâmica) sobre quic.Conn: o http3 do quic-go lê os streams por dentro e não deixa ver os frames depois
// do primeiro HEADERS nem o stream de controle depois do SETTINGS (ADR 0019).
type h3Conn struct {
	srv    *Server
	ctx    context.Context
	qc     *quic.Conn
	flow   *event.Flow
	entry  *initEntry
	connID *connIDFuture
	start  time.Time

	mu       sync.Mutex
	info     *quicparse.Info
	probeID  string
	requests int
	ctlSeen  bool
	// ctlDeadline: fim da espera pelo SETTINGS, marcado pela primeira requisição que esperou
	ctlDeadline time.Time
	ctlReady    chan struct{} // fechado quando o SETTINGS do cliente foi lido
	wg          sync.WaitGroup
}

// h3SettingsWait é quanto uma requisição espera, antes de responder, o SETTINGS do cliente ainda não lido.
// O quic-go descarta os bytes ainda não lidos dos streams e os streams ainda não aceitos quando a conexão
// fecha; um cliente que fecha logo depois da resposta (curl) perderia o SETTINGS que chegou junto da
// requisição se o leitor do stream de controle ainda não tivesse rodado (task 063). Clientes conformes
// mandam o SETTINGS no início e a espera termina assim que ele é lido; sem stream de controle, a espera
// só acontece uma vez por conexão: as requisições seguintes respeitam o mesmo prazo (ctlDeadline).
var h3SettingsWait = 50 * time.Millisecond

// handleQUIC atende uma conexão do accept ao fim e publica os até três http3.connection.
func (s *Server) handleQUIC(ctx context.Context, qc *quic.Conn) {
	h := &h3Conn{srv: s, ctx: ctx, qc: qc, start: s.now(), ctlReady: make(chan struct{})}
	flow := udpFlow(qc.LocalAddr(), qc.RemoteAddr())
	h.flow = &flow
	if t := s.h3.tracker; t != nil {
		h.entry, h.info = t.claim(qc.RemoteAddr(), h3ClaimWait)
		defer t.release(h.entry)
	}
	if h.entry != nil {
		h.start = h.entry.first
		h.flow.QUICDCIDHex = h.entry.flow.QUICDCIDHex
		h.connID = h.entry.connID
	} else {
		h.connID = s.requestConnID(ctx, flow, h.start)
	}
	if h.info == nil {
		h.info = &quicparse.Info{
			InitialFrames: []string{}, TransportParams: []quicparse.TransportParam{},
			H3Settings: [][2]uint64{}, Requests: []quicparse.HTTP3Request{}, InitialPacketNumber: -1,
		}
	}
	if ch := h.info.ClientHello; ch != nil && ch.SNI != nil {
		if p, ok := s.probes.Host(*ch.SNI); ok {
			h.setProbe(p.ID)
		}
	}

	// handshake terminado ou falho: primeiro evento
	select {
	case <-qc.HandshakeComplete():
	case <-qc.Context().Done():
		h.finish(false)
		return
	case <-ctx.Done():
		_ = qc.CloseWithError(h3NoError, "")
		<-qc.Context().Done()
		h.finish(false)
		return
	}
	st := qc.ConnectionState()
	h.mu.Lock()
	if ch := h.info.ClientHello; ch != nil {
		ch.Negotiated = negotiatedOf(st.TLS)
		ch.HandshakeMs = ptr(msSince(h.start, s.now()))
	}
	h.mu.Unlock()
	if p, ok := s.probes.Host(st.TLS.ServerName); ok {
		h.setProbe(p.ID)
	}
	h.publishConn()

	if err := h.openControl(); err != nil {
		_ = qc.CloseWithError(h3InternalError, "")
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.acceptUni()
	}()
	h.acceptBidi()
	<-qc.Context().Done()
	h.wg.Wait()
	h.finish(true)
}

// finish publica o último http3.connection, com close.
func (h *h3Conn) finish(handshakeDone bool) {
	h.mu.Lock()
	h.info.Close = quicCloseOf(context.Cause(h.qc.Context()), handshakeDone)
	h.mu.Unlock()
	h.publishConn()
}

func (h *h3Conn) setProbe(id string) {
	if id == "" {
		return
	}
	h.mu.Lock()
	if h.probeID == "" {
		h.probeID = id
	}
	h.mu.Unlock()
}

func (h *h3Conn) probe() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.probeID
}

// publishConn publica o estado atual do nível de conexão (requests vai vazio).
func (h *h3Conn) publishConn() {
	h.mu.Lock()
	info := *h.info
	info.InitialFrames = slices.Clone(info.InitialFrames)
	info.TransportParams = slices.Clone(info.TransportParams)
	info.H3Settings = slices.Clone(info.H3Settings)
	info.Requests = []quicparse.HTTP3Request{}
	if info.ClientHello != nil {
		ch := *info.ClientHello
		info.ClientHello = &ch
	}
	probeID := h.probeID
	h.mu.Unlock()
	h.srv.publishH3Conn(h.flow, probeID, &info)
}

// openControl abre o stream de controle do servidor e manda o SETTINGS fixo (o stream fica aberto).
func (h *h3Conn) openControl() error {
	str, err := h.qc.OpenUniStream()
	if err != nil {
		return err
	}
	var p []byte
	for _, kv := range h3Settings {
		p = quicparse.AppendVarint(p, kv[0])
		p = quicparse.AppendVarint(p, kv[1])
	}
	b := quicparse.AppendH3Frame([]byte{quicparse.StreamTypeControl}, quicparse.H3FrameSettings, p)
	_, err = str.Write(b)
	return err
}

// acceptUni lê os streams unidirecionais do cliente: controle (SETTINGS, GOAWAY) e QPACK; os bytes são
// sempre consumidos para liberar o controle de fluxo.
func (h *h3Conn) acceptUni() {
	for {
		str, err := h.qc.AcceptUniStream(h.ctx)
		if err != nil {
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.readUni(str)
		}()
	}
}

func (h *h3Conn) readUni(str *quic.ReceiveStream) {
	u := quicparse.NewUniStream()
	buf := make([]byte, 4<<10)
	reported := false
	for {
		n, err := str.Read(buf)
		if n > 0 {
			u.Feed(buf[:n])
			if !reported && u.Typed && u.StreamType == quicparse.StreamTypeControl && u.SettingsSeen {
				reported = true
				h.onSettings(u.Settings)
			}
		}
		if err != nil {
			return
		}
	}
}

// onSettings guarda o SETTINGS do primeiro stream de controle do cliente e publica o segundo evento.
func (h *h3Conn) onSettings(settings [][2]uint64) {
	h.mu.Lock()
	if h.ctlSeen {
		h.mu.Unlock()
		return
	}
	h.ctlSeen = true
	h.info.H3Settings = slices.Clone(settings)
	h.info.H3ControlStreamSeen = true
	h.mu.Unlock()
	close(h.ctlReady)
	h.publishConn()
}

// waitSettings espera o SETTINGS do cliente até h3SettingsWait depois da primeira requisição que o esperou.
func (h *h3Conn) waitSettings() {
	h.mu.Lock()
	if h.ctlSeen {
		h.mu.Unlock()
		return
	}
	now := time.Now()
	if h.ctlDeadline.IsZero() {
		h.ctlDeadline = now.Add(h3SettingsWait)
	}
	d := h.ctlDeadline.Sub(now)
	h.mu.Unlock()
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-h.ctlReady:
	case <-t.C:
	case <-h.qc.Context().Done():
	case <-h.ctx.Done():
	}
}

// acceptBidi atende os streams de requisição até a conexão acabar.
func (h *h3Conn) acceptBidi() {
	for {
		str, err := h.qc.AcceptStream(h.ctx)
		if err != nil {
			if h.ctx.Err() != nil {
				_ = h.qc.CloseWithError(h3NoError, "")
			}
			return
		}
		h.mu.Lock()
		index := h.requests
		h.requests++
		h.mu.Unlock()
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			st := &h3Stream{h: h, str: str, index: index}
			st.serve()
		}()
	}
}

// readAll lê o stream de requisição até o FIN, alimentando o parser passivo; erro de leitura que não é
// o fim normal aborta (stream cancelado pelo cliente, conexão fechada).
func readAll(str *quic.Stream, rs *quicparse.RequestStream) error {
	buf := make([]byte, 16<<10)
	for {
		n, err := str.Read(buf)
		if n > 0 {
			rs.Feed(buf[:n])
			if rs.Err() != nil {
				return rs.Err()
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
