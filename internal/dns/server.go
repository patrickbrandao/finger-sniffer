package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Limites dos listeners.
const (
	// udpMaxNoEDNS é o tamanho máximo da resposta UDP sem EDNS (RFC 1035).
	udpMaxNoEDNS = 512
	// udpMaxEDNS é o maior tamanho de resposta UDP que anunciamos e usamos (DNS flag day 2020, sem fragmentar).
	udpMaxEDNS = 1232
	// tcpIdleTimeout fecha conexões TCP paradas (RFC 7766 recomenda alguns segundos).
	tcpIdleTimeout = 10 * time.Second
	// tcpMaxQueries é o máximo de consultas por conexão TCP.
	tcpMaxQueries = 100
	// tcpMaxConns limita as conexões TCP simultâneas.
	tcpMaxConns = 256
	// defaultRetry é o intervalo entre tentativas de subir um listener que falhou.
	defaultRetry = 10 * time.Second
)

// Nomes das métricas do dns no heartbeat.
const (
	MetricQueriesUDP  = "dns_queries_udp_total"
	MetricQueriesTCP  = "dns_queries_tcp_total"
	MetricFormErr     = "dns_formerr_total"
	MetricDropped     = "dns_dropped_total"
	MetricRateLimited = "dns_rate_limited_total"
)

// Query é uma consulta atendida, entregue ao Observer (o evento fs.v1.dns.query chega na task 028).
type Query struct {
	At    time.Time
	Proto string // udp | tcp
	Src   netip.AddrPort
	Dst   netip.AddrPort
	Raw   []byte    // mensagem crua recebida (antes do unpack)
	Req   *mdns.Msg // nil se não deu para decodificar
	Resp  *mdns.Msg // mensagem enviada (nil se nada foi respondido)
	// RateLimited: acima do RRL (UDP recebeu TC=1 sem dados; TCP foi descartado).
	RateLimited bool
}

// Server é o autoritativo UDP/TCP.
type Server struct {
	cfg     Config
	zone    *Zone
	log     *slog.Logger
	metrics *service.Metrics
	// RRL limita as respostas por IP de origem (nil = sem limite).
	RRL *RRL
	// Observer, se definido, recebe cada consulta depois da resposta enviada.
	Observer func(*Query)
	// RetryEvery é o intervalo para tentar de novo um listener que não subiu.
	RetryEvery time.Duration

	mu      sync.Mutex
	failed  map[string]string // "udp ip:porta" → erro
	udp     []*net.UDPConn
	tcp     []*net.TCPListener
	wg      sync.WaitGroup
	tcpSem  chan struct{}
	conns   map[*net.TCPConn]struct{}
	stopped bool
}

// NewServer cria o servidor (metrics pode ser nil).
func NewServer(cfg Config, zone *Zone, log *slog.Logger, metrics *service.Metrics) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if metrics == nil {
		metrics = service.NewMetrics()
	}
	return &Server{
		cfg: cfg, zone: zone, log: log, metrics: metrics, RetryEvery: defaultRetry, RRL: NewRRL(cfg.RRLPerIP, nil),
		failed: map[string]string{}, conns: map[*net.TCPConn]struct{}{}, tcpSem: make(chan struct{}, tcpMaxConns),
	}
}

// Status é a StatusFunc do heartbeat: degraded com o motivo de cada listener que não subiu.
func (s *Server) Status() (string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.failed) == 0 {
		return event.StatusOK, nil
	}
	reasons := make([]string, 0, len(s.failed))
	for k, v := range s.failed {
		reasons = append(reasons, fmt.Sprintf("listener %s: %s", k, v))
	}
	slices.Sort(reasons)
	return event.StatusDegraded, reasons
}

// Addrs devolve os endereços efetivos dos listeners ativos (útil com porta 0 em teste).
func (s *Server) Addrs() (udp, tcp []net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.udp {
		udp = append(udp, c.LocalAddr())
	}
	for _, l := range s.tcp {
		tcp = append(tcp, l.Addr())
	}
	return udp, tcp
}

// Start sobe os listeners. Os que falham ficam em degraded e são tentados de novo a cada RetryEvery até ctx
// terminar. Não bloqueia.
func (s *Server) Start(ctx context.Context) {
	type slot struct{ proto, addr string }
	var pending []slot
	for _, a := range s.cfg.listenAddrs() {
		pending = append(pending, slot{"udp", a}, slot{"tcp", a})
	}
	try := func() {
		var still []slot
		for _, sl := range pending {
			if err := s.listen(ctx, sl.proto, sl.addr); err != nil {
				still = append(still, sl)
			}
		}
		pending = still
	}
	try()
	if len(pending) == 0 {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(s.RetryEvery)
		defer t.Stop()
		for len(pending) > 0 {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				try()
			}
		}
	}()
}

// Serve sobe os listeners e atende até ctx terminar (função main do service.Run).
func (s *Server) Serve(ctx context.Context) error {
	s.Start(ctx)
	<-ctx.Done()
	s.Close()
	return nil
}

// Close fecha os listeners e espera as goroutines.
func (s *Server) Close() {
	s.mu.Lock()
	s.stopped = true
	for _, c := range s.udp {
		_ = c.Close()
	}
	for _, l := range s.tcp {
		_ = l.Close()
	}
	// Conexões TCP abertas: fecha para não esperar o tempo ocioso.
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) listen(ctx context.Context, proto, addr string) error {
	key := proto + " " + addr
	var lc net.ListenConfig
	var err error
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil
	}
	switch proto {
	case "udp":
		var pc net.PacketConn
		if pc, err = lc.ListenPacket(ctx, "udp", addr); err == nil {
			c := pc.(*net.UDPConn)
			s.udp = append(s.udp, c)
			s.wg.Add(1)
			go s.serveUDP(c)
		}
	default:
		var l net.Listener
		if l, err = lc.Listen(ctx, "tcp", addr); err == nil {
			tl := l.(*net.TCPListener)
			s.tcp = append(s.tcp, tl)
			s.wg.Add(1)
			go s.serveTCP(tl)
		}
	}
	if err != nil {
		if _, seen := s.failed[key]; !seen {
			s.log.Warn("dns listener failed", "listener", key, "err", err)
		}
		s.failed[key] = err.Error()
		return err
	}
	delete(s.failed, key)
	s.log.Info("dns listener up", "listener", key)
	return nil
}

func (s *Server) serveUDP(c *net.UDPConn) {
	defer s.wg.Done()
	dst := addrPort(c.LocalAddr())
	buf := make([]byte, 65535)
	for {
		n, src, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		at := time.Now()
		raw := slices.Clone(buf[:n])
		s.metrics.Add(MetricQueriesUDP, 1)
		out, req, resp, limited := s.handle(raw, false, src.Addr().Unmap())
		if out != nil {
			_, _ = c.WriteToUDPAddrPort(out, src)
		} else {
			s.metrics.Add(MetricDropped, 1)
		}
		s.observe(&Query{At: at, Proto: "udp", Src: unmap(src), Dst: dst, Raw: raw, Req: req, Resp: resp, RateLimited: limited})
	}
}

func (s *Server) serveTCP(l *net.TCPListener) {
	defer s.wg.Done()
	for {
		c, err := l.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		select {
		case s.tcpSem <- struct{}{}:
		default:
			_ = c.Close()
			s.metrics.Add(MetricDropped, 1)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.tcpSem }()
			s.serveTCPConn(c)
		}()
	}
}

func (s *Server) serveTCPConn(c *net.TCPConn) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		_ = c.Close()
		return
	}
	s.conns[c] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		_ = c.Close()
	}()
	src, dst := addrPort(c.RemoteAddr()), addrPort(c.LocalAddr())
	var lenBuf [2]byte
	for range tcpMaxQueries {
		_ = c.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return
		}
		raw := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(c, raw); err != nil {
			return
		}
		at := time.Now()
		s.metrics.Add(MetricQueriesTCP, 1)
		out, req, resp, limited := s.handle(raw, true, src.Addr())
		if out != nil {
			frame := make([]byte, 2+len(out))
			binary.BigEndian.PutUint16(frame, uint16(len(out))) //nolint:gosec // Pack limita a mdns.MaxMsgSize
			copy(frame[2:], out)
			_ = c.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
			if _, err := c.Write(frame); err != nil {
				return
			}
		} else {
			s.metrics.Add(MetricDropped, 1)
		}
		s.observe(&Query{At: at, Proto: "tcp", Src: src, Dst: dst, Raw: raw, Req: req, Resp: resp, RateLimited: limited})
		if out == nil {
			return
		}
	}
}

func (s *Server) observe(q *Query) {
	if s.Observer != nil {
		s.Observer(q)
	}
}

// handle responde à mensagem crua aplicando o RRL; o último retorno indica limite atingido.
func (s *Server) handle(raw []byte, tcp bool, src netip.Addr) ([]byte, *mdns.Msg, *mdns.Msg, bool) {
	out, req, resp := s.answer(raw, tcp)
	if out == nil || s.RRL.Allow(src) {
		return out, req, resp, false
	}
	s.metrics.Add(MetricRateLimited, 1)
	// Acima do limite: TCP descarta; UDP responde TC=1 sem dados, para o resolvedor legítimo repetir em TCP.
	if tcp || resp == nil {
		return nil, req, nil, true
	}
	tc := resp.Copy()
	tc.Truncated = true
	tc.Answer, tc.Ns = nil, nil
	var extra []mdns.RR
	if opt := tc.IsEdns0(); opt != nil {
		extra = []mdns.RR{opt}
	}
	tc.Extra = extra
	if out, err := tc.Pack(); err == nil {
		return out, req, tc, true
	}
	return nil, req, nil, true
}

// answer decodifica a mensagem crua, responde e devolve os bytes a enviar (nil = não responder).
func (s *Server) answer(raw []byte, tcp bool) ([]byte, *mdns.Msg, *mdns.Msg) {
	req := new(mdns.Msg)
	if err := req.Unpack(raw); err != nil {
		// Com cabeçalho legível e sem QR, responde FORMERR com o mesmo ID; senão descarta.
		if len(raw) < 12 || raw[2]&0x80 != 0 {
			return nil, nil, nil
		}
		s.metrics.Add(MetricFormErr, 1)
		resp := new(mdns.Msg)
		resp.Id = binary.BigEndian.Uint16(raw[0:2])
		resp.Response = true
		resp.Opcode = int(raw[2]>>3) & 0x0f
		resp.Rcode = mdns.RcodeFormatError
		out, err := resp.Pack()
		if err != nil {
			return nil, nil, nil
		}
		return out, nil, resp
	}
	if req.Response {
		return nil, req, nil
	}

	resp := s.zone.Answer(req)
	maxSize := udpMaxNoEDNS
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(udpMaxEDNS, false)
		if opt.Version() != 0 {
			// RFC 6891 6.1.3: versão desconhecida → BADVERS, sem dados.
			resp.Rcode = mdns.RcodeBadVers
			resp.Answer, resp.Ns = nil, nil
		}
		maxSize = max(udpMaxNoEDNS, min(int(opt.UDPSize()), udpMaxEDNS))
	}
	if tcp {
		maxSize = mdns.MaxMsgSize
	}
	resp.Truncate(maxSize)
	out, err := resp.Pack()
	if err != nil {
		s.log.Warn("dns pack", "err", err)
		fail := new(mdns.Msg)
		fail.SetRcode(req, mdns.RcodeServerFailure)
		if out, err = fail.Pack(); err != nil {
			return nil, req, nil
		}
		return out, req, fail
	}
	return out, req, resp
}

// addrPort converte um net.Addr de socket em AddrPort (IPv4 sem o prefixo ::ffff:).
func addrPort(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.UDPAddr:
		return unmap(v.AddrPort())
	case *net.TCPAddr:
		return unmap(v.AddrPort())
	}
	return netip.AddrPort{}
}

func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// Run é o serviço dns completo sobre a base comum: zona, listeners, request/reply do DNS-01 e status.
func Run(svc *service.Service, cfg Config) error {
	zone := NewZone(cfg, nil)
	srv := NewServer(cfg, zone, svc.Log, svc.Metrics)
	svc.SetStatus(srv.Status)
	// Cada consulta vira um fs.v1.dns.query; o produtor nunca bloqueia o laço do listener.
	srv.Observer = func(q *Query) {
		msg, err := zone.QueryMessage(q, version.Version)
		if err != nil {
			svc.Log.Warn("dns event", "err", err)
			return
		}
		svc.Producer.Publish(msg)
	}
	if _, err := SubscribeACME(svc.NC, zone, svc.Log.Info); err != nil {
		return err
	}
	svc.Log.Info("dns zone", "zone", cfg.Zone, "listen", cfg.listenAddrs())
	return svc.Run(srv.Serve)
}
