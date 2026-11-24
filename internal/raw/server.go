package raw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Métricas do raw (vão no heartbeat).
const (
	MetricSessions       = "raw_sessions_total"
	MetricActiveSessions = "raw_active_sessions"
	// MetricEventsOversize conta eventos descartados por passarem de event.MaxEventBytes (ADR 0035).
	MetricEventsOversize = "raw_events_oversize_total"
)

// Server escuta as portas cruas e atende cada conexão numa goroutine.
type Server struct {
	cfg     Config
	pub     Publisher
	log     *slog.Logger
	metrics *service.Metrics
	probes  *probe.Extractor
	budget  *inputBudget

	mu        sync.Mutex
	listeners []listener
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
	// sem são as vagas de FS_MAX_CONNS, globais entre os listeners (spec 006 RF-07a); done libera o accept que
	// espera uma vaga quando o Run termina.
	sem  chan struct{}
	done chan struct{}
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
	if cfg.MaxConns <= 0 {
		// Só o store dá significado ao 0 (modo degradado); no raw vale o padrão (ADR 0034 item 12).
		log.Warn("raw: FS_MAX_CONNS <= 0, using default", "value", cfg.MaxConns, "default", DefaultMaxConns)
		cfg.MaxConns = DefaultMaxConns
	}
	limit := cfg.inputBudget
	if limit <= 0 {
		limit = InputBudget
	}
	metrics.Add(MetricPanics, 0)
	// Uma única tls.Config para todas as sessões (task 419): clonar por conexão trocaria as chaves de ticket.
	cfg.TLS = newServerTLS(cfg.TLS)
	return &Server{
		budget: newInputBudget(limit, metrics),
		cfg:    cfg, pub: pub, log: log, metrics: metrics, probes: probe.NewExtractor(),
		conns: map[net.Conn]struct{}{},
		sem:   make(chan struct{}, cfg.MaxConns), done: make(chan struct{}),
	}
}

// Listen abre todas as portas. Falha em qualquer uma fecha as já abertas.
func (s *Server) Listen(ctx context.Context) error {
	lc := s.listenConfig()
	if len(s.cfg.ListenIPs) == 0 {
		return errors.New("raw: no listen address (FS_LISTEN_IPV4/FS_LISTEN_IPV6)")
	}
	for _, spec := range s.cfg.Ports {
		if spec.TLS && s.cfg.TLS == nil {
			s.log.Warn("raw: no tls config, serving plain", "port", spec.Port, "mode", spec.Name())
		}
		for _, ip := range s.cfg.ListenIPs {
			addr := netip.AddrPortFrom(ip, uint16(spec.Port)).String() //nolint:gosec // portas validadas em ParsePorts (0..65535)
			ln, err := lc.Listen(ctx, "tcp", addr)
			if err != nil {
				s.closeListeners()
				return fmt.Errorf("raw: listen %s: %w", addr, err)
			}
			s.mu.Lock()
			s.listeners = append(s.listeners, listener{Listener: ln, spec: spec})
			s.mu.Unlock()
		}
	}
	return nil
}

// tfoQueue é a fila de pedidos TFO pendentes dos listeners (ADR 0029).
const tfoQueue = 256

// listenConfig devolve a configuração dos listeners: sem keepalive do lado do servidor (ele mudaria os
// pacotes analisados da conexão, spec 013) e com TCP_FASTOPEN ligado antes do listen (spec 006 RF-01).
// Falha no setsockopt só registra aviso e o listener segue sem TFO.
func (s *Server) listenConfig() net.ListenConfig {
	return net.ListenConfig{KeepAlive: -1, Control: func(_, address string, c syscall.RawConn) error {
		if err := enableTFO(c, tfoQueue); err != nil {
			s.log.Warn("raw tcp fastopen", "addr", address, "err", err)
		}
		return nil
	}}
}

// Addrs devolve os endereços abertos, na ordem de Config.Ports e, dentro de cada porta, de Config.ListenIPs
// (útil com porta 0 nos testes).
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
	close(s.done)
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
		// Vaga de FS_MAX_CONNS: sem vaga, o laço espera com a conexão aceita sem atendê-la e não aceita mais
		// nada, então o excedente fica no backlog do kernel; nenhuma sessão é fechada antes da hora (spec 006
		// RF-07a, ADR 0035). A vaga não é pega antes do accept para um listener ocioso não segurar vagas das
		// outras portas.
		select {
		case s.sem <- struct{}{}:
		case <-s.done:
			_ = c.Close()
			return
		}
		if !s.track(c) {
			<-s.sem
			_ = c.Close()
			return
		}
		s.wg.Go(func() {
			defer func() { <-s.sem }()
			defer s.untrack(c)
			defer s.recoverSession(c)
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

// recoverSession recupera um pânico da sessão: registra com a pilha, conta em raw_panics_total e fecha só
// aquela conexão; as outras sessões e o processo seguem (spec 006 RF-07b, ADR 0070 item 6). As reservas já
// voltaram ao orçamento pelos defers da sessão.
func (s *Server) recoverSession(c net.Conn) {
	r := recover()
	if r == nil {
		return
	}
	_ = c.Close()
	s.metrics.Add(MetricPanics, 1)
	s.log.Error("raw: session panic", "panic", fmt.Sprint(r), "remote", c.RemoteAddr().String(), "stack", string(debug.Stack()))
}

// serve atende uma conexão aceita.
func (s *Server) serve(c net.Conn, spec PortSpec, start time.Time) {
	em := &emitter{pub: s.pub, log: s.log, flow: flowOf(c), metrics: s.metrics}
	sess := newSession(c, &s.cfg, spec, start, em)
	sess.probes = s.probes
	sess.hold = &hold{b: s.budget}
	defer sess.hold.releaseAll()
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
