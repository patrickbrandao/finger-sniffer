package web

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// Métricas e motivos do h3 no heartbeat.
const (
	MetricH3Listening     = "web_h3_listening"
	MetricH3ConnsTotal    = "web_http3_connections_total"
	MetricH3RequestsTotal = "web_http3_requests_total"
	// ReasonH3Down: FS_WEB_UDP_PORTS contém 443 e o listener UDP 443 não está de pé (spec 005 RF-04).
	ReasonH3Down = "h3_listener_down"
)

// altSvcH3 é o anúncio do h3 nas respostas h1/h2 de portas TLS (spec 005 RF-04).
const altSvcH3 = `h3=":443"; ma=60`

// Códigos de erro do HTTP/3 (RFC 9114 seção 8.1) usados pelo servidor.
const (
	h3NoError       = 0x100
	h3InternalError = 0x102
)

// h3Settings é o SETTINGS fixo do servidor (spec 011 RF-06): sem tabela dinâmica QPACK
// (QPACK_MAX_TABLE_CAPACITY = 0, QPACK_BLOCKED_STREAMS = 0) e MAX_FIELD_SECTION_SIZE de 1 MiB, o mesmo teto
// do cabeçalho do HTTP/1 (spec 009 RF-10). Sem ENABLE_CONNECT_PROTOCOL (WebSocket sobre h3 fora do MVP)
// e sem H3_DATAGRAM.
var h3Settings = [][2]uint64{
	{quicparse.SettingQPACKMaxTableCapacity, 0},
	{quicparse.SettingQPACKBlockedStreams, 0},
	{quicparse.SettingMaxFieldSectionSize, 1 << 20},
}

// h3HandshakeWait é quanto o web espera o ClientHello analisado depois de aceitar a conexão.
const h3ClaimWait = 200 * time.Millisecond

// h3State é o estado dos listeners UDP do servidor.
type h3State struct {
	mu      sync.Mutex
	up      map[string]bool // endereço UDP → de pé
	conns   map[*quic.Conn]struct{}
	tracker *initTracker
}

// quicConfig é a configuração do QUIC (spec 011 RF-06): ociosidade = FS_IDLE_DEFAULT, sem 0-RTT, sem
// datagramas. Retry fica desligado (Transport.VerifySourceAddress nil) e o quic-go não oferece endereço
// preferido nem migra a conexão por conta própria.
func (s *Server) quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:        s.cfg.IdleDefault,
		HandshakeIdleTimeout:  10 * time.Second,
		Allow0RTT:             false,
		EnableDatagrams:       false,
		MaxIncomingStreams:    100,
		MaxIncomingUniStreams: 16,
	}
}

// h3TLS é a configuração TLS do QUIC: a mesma de pkg/certs (SNI, recarga a quente), ALPN h3, TLS 1.3.
func (s *Server) h3TLS() *tls.Config {
	cfg := s.deps.TLS.Clone()
	cfg.NextProtos = []string{"h3"}
	cfg.MinVersion = tls.VersionTLS13
	cfg.GetConfigForClient = nil
	return cfg
}

// runH3 abre os listeners UDP de FS_WEB_UDP_PORTS (sem TLS configurado o h3 fica desligado).
func (s *Server) runH3(ctx context.Context) {
	if s.deps.TLS == nil {
		return
	}
	s.h3.tracker = newInitTracker(ctx, s)
	s.h3.tracker.orphans = s.publishOrphan
	s.metrics.Set(MetricH3Listening, 0)
	go s.h3Janitor(ctx)
	for _, addr := range s.cfg.udpAddrs() {
		s.wg.Add(1)
		go s.h3ListenLoop(ctx, addr)
	}
}

// h3Janitor limpa a tabela de Initials mesmo sem tráfego novo (órfãs viram handshake_failed).
func (s *Server) h3Janitor(ctx context.Context) {
	t := time.NewTicker(initSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.h3.tracker.sweep()
		}
	}
}

// h3ListenLoop abre addr (tentando de novo a cada RetryListen) e atende QUIC até ctx acabar.
func (s *Server) h3ListenLoop(ctx context.Context, addr string) {
	defer s.wg.Done()
	for {
		err := s.serveUDP(ctx, addr)
		if ctx.Err() != nil {
			return
		}
		s.setFailed("udp/"+addr, err.Error())
		s.log.Error("web h3 listen", "addr", addr, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.RetryListen):
		}
	}
}

// serveUDP abre o socket, o transporte QUIC e o listener, e atende até o listener cair.
func (s *Server) serveUDP(ctx context.Context, addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	return s.ServeQUIC(ctx, pc)
}

// ServeQUIC atende QUIC/HTTP/3 em pc até ctx acabar ou o transporte falhar.
func (s *Server) ServeQUIC(ctx context.Context, pc *net.UDPConn) error {
	if s.h3.tracker == nil {
		s.h3.tracker = newInitTracker(ctx, s)
		s.h3.tracker.orphans = s.publishOrphan
	}
	addr := pc.LocalAddr().String()
	tr := &quic.Transport{Conn: &udpConn{c: pc, obs: s.h3.tracker.observe}}
	ln, err := tr.ListenEarly(s.h3TLS(), s.quicConfig())
	if err != nil {
		_ = tr.Close()
		_ = pc.Close()
		return err
	}
	s.setUDP(addr, true)
	s.setFailed("udp/"+addr, "")
	s.log.Info("web h3 listening", "addr", addr)
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer func() {
		stop()
		s.setUDP(addr, false)
		_ = ln.Close()
		_ = tr.Close()
		_ = pc.Close()
	}()
	for {
		qc, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		// Vaga de FS_MAX_CONNS (a mesma do TCP): o accept espera em vez de recusar.
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			_ = qc.CloseWithError(h3NoError, "")
			return ctx.Err()
		}
		if !s.trackQUIC(qc) {
			<-s.sem
			_ = qc.CloseWithError(h3NoError, "")
			return net.ErrClosed
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer s.untrackQUIC(qc)
			s.handleQUIC(ctx, qc)
		}()
	}
}

func (s *Server) setUDP(addr string, up bool) {
	s.h3.mu.Lock()
	if s.h3.up == nil {
		s.h3.up = map[string]bool{}
	}
	if up {
		s.h3.up[addr] = true
	} else {
		delete(s.h3.up, addr)
	}
	s.h3.mu.Unlock()
	v := 0.0
	if s.h3Active() {
		v = 1
	}
	s.metrics.Set(MetricH3Listening, v)
}

// h3Active informa se um listener UDP 443 está de pé (spec 005 RF-04: só então o h3 é anunciado).
func (s *Server) h3Active() bool {
	s.h3.mu.Lock()
	defer s.h3.mu.Unlock()
	for addr := range s.h3.up {
		if ap, err := netip.ParseAddrPort(addr); err == nil && ap.Port() == 443 {
			return true
		}
	}
	return s.h3AnyPort && len(s.h3.up) > 0
}

// h3Wanted informa se FS_WEB_UDP_PORTS pede a porta 443 (com TLS).
func (s *Server) h3Wanted() bool {
	if s.deps.TLS == nil {
		return false
	}
	for _, p := range s.cfg.UDPPorts {
		if p == 443 {
			return true
		}
	}
	return false
}

func (s *Server) trackQUIC(qc *quic.Conn) bool {
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		return false
	}
	s.h3.mu.Lock()
	if s.h3.conns == nil {
		s.h3.conns = map[*quic.Conn]struct{}{}
	}
	s.h3.conns[qc] = struct{}{}
	s.h3.mu.Unlock()
	s.metrics.Add(MetricH3ConnsTotal, 1)
	return true
}

func (s *Server) untrackQUIC(qc *quic.Conn) {
	s.h3.mu.Lock()
	delete(s.h3.conns, qc)
	s.h3.mu.Unlock()
}

// closeQUIC encerra as conexões QUIC abertas (parada do serviço).
func (s *Server) closeQUIC() {
	s.h3.mu.Lock()
	conns := make([]*quic.Conn, 0, len(s.h3.conns))
	for qc := range s.h3.conns {
		conns = append(conns, qc)
	}
	s.h3.mu.Unlock()
	for _, qc := range conns {
		_ = qc.CloseWithError(h3NoError, "")
	}
}

// quicCloseOf traduz o motivo do fim da conexão QUIC (spec 011, HTTP3Info.close).
func quicCloseOf(err error, handshakeDone bool) *quicparse.Close {
	c := &quicparse.Close{By: "unknown", How: quicparse.CloseConnection}
	var appErr *quic.ApplicationError
	var trErr *quic.TransportError
	var idle *quic.IdleTimeoutError
	var reset *quic.StatelessResetError
	var hsTimeout *quic.HandshakeTimeoutError
	by := func(remote bool) string {
		if remote {
			return "client"
		}
		return "server"
	}
	switch {
	case errors.As(err, &appErr):
		c.By, c.How = by(appErr.Remote), quicparse.CloseApplication
		c.ErrorCode = ptr(uint64(appErr.ErrorCode))
		c.Reason = ptr(appErr.ErrorMessage)
	case errors.As(err, &trErr):
		c.By = by(trErr.Remote)
		c.ErrorCode = ptr(uint64(trErr.ErrorCode))
		c.Reason = ptr(trErr.ErrorMessage)
	case errors.As(err, &idle):
		c.By, c.How = "server", quicparse.CloseIdleTimeout
	case errors.As(err, &reset):
		c.By, c.How = "client", quicparse.CloseStatelessReset
	case errors.As(err, &hsTimeout):
		c.How = quicparse.CloseHandshakeFailed
	}
	if !handshakeDone {
		c.How = quicparse.CloseHandshakeFailed
	}
	return c
}

// negotiatedOf monta o resultado do handshake QUIC no formato do TLSInfo.
func negotiatedOf(st tls.ConnectionState) *tlsparse.Negotiated {
	n := &tlsparse.Negotiated{
		Version: tls.VersionName(st.Version),
		Cipher:  tls.CipherSuiteName(st.CipherSuite),
		Resumed: st.DidResume,
	}
	if st.CurveID != 0 {
		n.Group = st.CurveID.String()
	}
	if st.NegotiatedProtocol != "" {
		n.ALPN = ptr(st.NegotiatedProtocol)
	}
	return n
}

// publishOrphan publica o http3.connection de uma 5-tupla cujo handshake não virou conexão aceita (ex.:
// ALPN sem h3, versão desconhecida): o Initial analisado e close = handshake_failed.
func (s *Server) publishOrphan(e *initEntry, info *quicparse.Info) {
	info.Close = &quicparse.Close{By: "unknown", How: quicparse.CloseHandshakeFailed}
	flow := e.flow
	probeID := ""
	if info.ClientHello != nil && info.ClientHello.SNI != nil {
		if h, ok := s.probes.Host(*info.ClientHello.SNI); ok {
			probeID = h.ID
		}
	}
	s.publishH3Conn(&flow, probeID, info)
}

// publishH3Conn publica fs.v1.web.http3.connection dentro do teto (ADR 0018): a lista de frames do Initial
// e os parâmetros de transporte encolhem se preciso.
func (s *Server) publishH3Conn(flow *event.Flow, probeID string, info *quicparse.Info) {
	data := s.fitH3Conn(flow, probeID, info)
	if data != nil {
		s.publishRaw(event.SubjectWebHTTP3Connection, data)
	}
}

func (s *Server) fitH3Conn(flow *event.Flow, probeID string, info *quicparse.Info) []byte {
	ts := s.now()
	data := s.encode(ts, flow, probeID, info)
	for i := 0; i < 64 && data != nil && len(data) > event.MaxEventBytes; i++ {
		if len(info.InitialFrames) > 0 {
			info.InitialFrames = halve(info.InitialFrames)
			info.InitialFramesTruncated = true
		}
		if ch := info.ClientHello; ch != nil && len(ch.ClientHelloB64) > 1024 {
			ch.ClientHelloB64 = ch.ClientHelloB64[:len(ch.ClientHelloB64)/2]
			ch.ClientHelloTruncated = true
		} else {
			info.TransportParams = halve(info.TransportParams)
			info.H3Settings = halve(info.H3Settings)
		}
		data = s.encode(ts, flow, probeID, info)
	}
	return data
}
