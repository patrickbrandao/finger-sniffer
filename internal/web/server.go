package web

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// ConnIDFunc pede ao store o conn_id da 5-tupla (fs.v1.store.conn_id, ADR 0017).
type ConnIDFunc func(ctx context.Context, flow event.Flow, ts time.Time) (string, error)

// ACMEFunc responde um token do HTTP-01 (spec 015); ok false = 404. Gancho para a task 027.
type ACMEFunc func(token string) (keyAuth []byte, ok bool)

// Deps são as dependências externas do servidor (injetadas para os testes).
type Deps struct {
	Log     *slog.Logger
	Metrics *service.Metrics
	// Publish entrega uma mensagem ao produtor (nunca bloqueia esperando o NATS).
	Publish func(*nats.Msg)
	// ConnID pede o conn_id; nil = sempre "unknown".
	ConnID ConnIDFunc
	// TLS é a configuração base com GetCertificate (pkg/certs); nil desliga o TLS.
	TLS *tls.Config
	// CertReasons devolve os motivos de degradação dos certificados (pkg/certs).
	CertReasons func(now time.Time) []string
	// ACME responde o desafio HTTP-01; nil = 404.
	ACME ACMEFunc
	// Now é o relógio (padrão time.Now).
	Now func() time.Time
}

// Server atende as portas TCP do web.
type Server struct {
	cfg     Config
	deps    Deps
	log     *slog.Logger
	metrics *service.Metrics
	now     func() time.Time
	probes  *probe.Extractor
	static  *static
	sem     chan struct{}

	mu        sync.Mutex
	listeners []net.Listener
	failed    map[string]string
	conns     map[net.Conn]struct{}
	stopped   bool
	wg        sync.WaitGroup
}

// NewServer cria o servidor.
func NewServer(cfg Config, d Deps) *Server {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.Metrics == nil {
		d.Metrics = service.NewMetrics()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Publish == nil {
		d.Publish = func(*nats.Msg) {}
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.RetryListen <= 0 {
		cfg.RetryListen = defaultRetryListen
	}
	return &Server{
		cfg: cfg, deps: d, log: d.Log, metrics: d.Metrics, now: d.Now,
		probes: probe.NewExtractor(cfg.Zones...),
		static: &static{root: cfg.Htdocs},
		sem:    make(chan struct{}, cfg.MaxConns),
		failed: map[string]string{},
		conns:  map[net.Conn]struct{}{},
	}
}

// Run abre os listeners configurados e atende até ctx acabar.
func (s *Server) Run(ctx context.Context) error {
	for _, addr := range s.cfg.listenAddrs() {
		s.wg.Add(1)
		go s.listenLoop(ctx, addr)
	}
	<-ctx.Done()
	s.Close()
	return nil
}

// listenLoop abre addr (tentando de novo a cada RetryListen se falhar) e atende.
func (s *Server) listenLoop(ctx context.Context, addr string) {
	defer s.wg.Done()
	for {
		var lc net.ListenConfig
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err == nil {
			s.setFailed(addr, "")
			s.log.Info("web listening", "addr", addr)
			_ = s.Serve(ctx, ln)
			return
		}
		s.setFailed(addr, err.Error())
		s.log.Error("web listen", "addr", addr, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.RetryListen):
		}
	}
}

func (s *Server) setFailed(addr, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if msg == "" {
		delete(s.failed, addr)
	} else {
		s.failed[addr] = msg
	}
}

// Serve atende ln até ctx acabar ou o listener fechar. O limite FS_MAX_CONNS é global (todos os
// listeners): conexões além dele esperam em vez de serem fechadas pelo servidor (RF-08).
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		_ = ln.Close()
		return net.ErrClosed
	}
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	backoff := 5 * time.Millisecond
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return err
			}
			// Erro transitório (ex.: EMFILE): espera um pouco e segue.
			s.log.Warn("web accept", "err", err)
			time.Sleep(backoff)
			backoff = min(backoff*2, time.Second)
			continue
		}
		backoff = 5 * time.Millisecond
		at := s.now()
		// Vaga de FS_MAX_CONNS: o accept para até abrir uma (no máximo uma conexão por listener espera aqui,
		// as outras ficam no backlog do kernel).
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			_ = c.Close()
			return ctx.Err()
		}
		if !s.track(c) {
			<-s.sem
			_ = c.Close()
			return net.ErrClosed
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer s.untrack(c)
			s.handle(ctx, c, at)
		}()
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.conns[c] = struct{}{}
	s.metrics.Add(MetricConnsTotal, 1)
	s.metrics.Set(MetricConnsActive, float64(len(s.conns)))
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
	s.metrics.Set(MetricConnsActive, float64(len(s.conns)))
}

// Addrs devolve os endereços dos listeners abertos.
func (s *Server) Addrs() []net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]net.Addr, 0, len(s.listeners))
	for _, ln := range s.listeners {
		out = append(out, ln.Addr())
	}
	return out
}

// Close fecha os listeners e as conexões abertas (parada do serviço) e espera as goroutines.
func (s *Server) Close() {
	s.mu.Lock()
	s.stopped = true
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// Status é o estado do heartbeat: degraded quando um listener não abriu ou quando pkg/certs aponta
// autoassinado ou certificado expirando (spec 015 RF-05).
func (s *Server) Status() (string, []string) {
	var reasons []string
	s.mu.Lock()
	for addr := range s.failed {
		reasons = append(reasons, "listen_failed:"+addr)
	}
	s.mu.Unlock()
	slices.Sort(reasons)
	if s.deps.CertReasons != nil {
		reasons = append(reasons, s.deps.CertReasons(s.now())...)
	}
	if len(reasons) > 0 {
		return event.StatusDegraded, reasons
	}
	return event.StatusOK, nil
}

// Run sobe o serviço web completo: certificados, servidor e heartbeat.
func Run(svc *service.Service, cfg Config) error {
	for _, w := range cfg.Warnings {
		svc.Log.Warn("web config", "warning", w)
	}
	store, err := certs.Open(certs.LoadConfig(), svc.Log)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	srv := NewServer(cfg, Deps{
		Log:     svc.Log,
		Metrics: svc.Metrics,
		Publish: svc.Producer.Publish,
		ConnID: func(ctx context.Context, flow event.Flow, ts time.Time) (string, error) {
			rep, err := service.RequestConnID(ctx, svc.NC, flow, ts)
			return rep.ConnID, err
		},
		TLS:         store.TLSConfig(),
		CertReasons: store.Reasons,
	})
	svc.SetStatus(srv.Status)
	svc.Log.Info("web config", "listen", cfg.listenAddrs(), "htdocs", cfg.Htdocs, "idle", cfg.IdleDefault.String())
	return svc.Run(srv.Run)
}
