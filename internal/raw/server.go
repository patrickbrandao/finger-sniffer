package raw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Métricas do raw (vão no heartbeat).
const (
	MetricSessions       = "raw_sessions_total"
	MetricActiveSessions = "raw_active_sessions"
)

// Server escuta as portas cruas e atende cada conexão numa goroutine.
type Server struct {
	cfg     Config
	pub     Publisher
	log     *slog.Logger
	metrics *service.Metrics
	probes  *probe.Extractor

	mu        sync.Mutex
	listeners []listener
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
}

type listener struct {
	net.Listener
	spec PortSpec
}

// New cria o servidor. metrics pode ser nil.
func New(cfg Config, pub Publisher, log *slog.Logger, metrics *service.Metrics) *Server {
	if metrics == nil {
		metrics = service.NewMetrics()
	}
	return &Server{
		cfg: cfg, pub: pub, log: log, metrics: metrics, probes: probe.NewExtractor(),
		conns: map[net.Conn]struct{}{},
	}
}

// Listen abre todas as portas. Falha em qualquer uma fecha as já abertas.
func (s *Server) Listen(ctx context.Context) error {
	// Sem keepalive do lado do servidor: ele mudaria os pacotes analisados da conexão (spec 013).
	lc := net.ListenConfig{KeepAlive: -1}
	for _, spec := range s.cfg.Ports {
		addr := net.JoinHostPort(s.cfg.ListenHost, strconv.Itoa(spec.Port))
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("raw: listen %s: %w", addr, err)
		}
		if spec.TLS && s.cfg.TLS == nil {
			s.log.Warn("raw: no tls config, serving plain", "port", spec.Port, "mode", spec.Name())
		}
		s.mu.Lock()
		s.listeners = append(s.listeners, listener{Listener: ln, spec: spec})
		s.mu.Unlock()
	}
	return nil
}

// Addrs devolve os endereços abertos, na ordem de Config.Ports (útil com porta 0 nos testes).
func (s *Server) Addrs() []net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]net.Addr, len(s.listeners))
	for i, l := range s.listeners {
		out[i] = l.Addr()
	}
	return out
}

// Run abre as portas (se ainda não abertas), aceita conexões até ctx terminar e então fecha tudo e espera
// as sessões publicarem o resumo.
func (s *Server) Run(ctx context.Context) error {
	s.mu.Lock()
	opened := len(s.listeners) > 0
	s.mu.Unlock()
	if !opened {
		if err := s.Listen(ctx); err != nil {
			return err
		}
	}
	s.mu.Lock()
	lns := append([]listener(nil), s.listeners...)
	s.mu.Unlock()
	for _, ln := range lns {
		s.log.Info("raw: listening", "addr", ln.Addr().String(), "mode", ln.spec.Name())
	}

	var accepting sync.WaitGroup
	for _, ln := range lns {
		accepting.Go(func() { s.acceptLoop(ln) })
	}
	<-ctx.Done()
	s.closeListeners()
	accepting.Wait()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

func (s *Server) acceptLoop(ln listener) {
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Erro de accept (ex.: falta de descritores): espera um pouco e tenta de novo, como o net/http.
			delay = min(max(delay*2, 5*time.Millisecond), time.Second)
			s.log.Warn("raw: accept", "addr", ln.Addr().String(), "err", err)
			time.Sleep(delay)
			continue
		}
		delay = 0
		start := time.Now()
		if !s.track(c) {
			_ = c.Close()
			return
		}
		s.wg.Go(func() {
			defer s.untrack(c)
			s.serve(c, ln.spec, start)
		})
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listeners == nil {
		return false
	}
	s.conns[c] = struct{}{}
	s.metrics.Add(MetricSessions, 1)
	s.metrics.Set(MetricActiveSessions, float64(len(s.conns)))
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.metrics.Set(MetricActiveSessions, float64(len(s.conns)))
	s.mu.Unlock()
}

func (s *Server) closeListeners() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.listeners {
		_ = l.Close()
	}
	s.listeners = nil
}

// serve atende uma conexão aceita.
func (s *Server) serve(c net.Conn, spec PortSpec, start time.Time) {
	em := &emitter{pub: s.pub, log: s.log, flow: flowOf(c)}
	sess := newSession(c, &s.cfg, spec, start, em)
	sess.probes = s.probes
	sess.run()
}

// flowOf monta a 5-tupla do ponto de vista do cliente.
func flowOf(c net.Conn) *event.Flow {
	f := &event.Flow{L4: "tcp"}
	if a, ok := addrPort(c.RemoteAddr()); ok {
		f.SrcIP, f.SrcPort = a.Addr().String(), int(a.Port())
	}
	if a, ok := addrPort(c.LocalAddr()); ok {
		f.DstIP, f.DstPort = a.Addr().String(), int(a.Port())
	}
	return f
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := ta.AddrPort()
	// IPv4 mapeado em IPv6 (socket dual-stack) vira IPv4, como nos pacotes capturados.
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}
