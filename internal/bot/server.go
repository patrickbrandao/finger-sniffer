package bot

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/netutil"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Constantes de operação.
const (
	// MaxPublicConns é o teto de conexões simultâneas na 9002 (ADR 0051 item 4).
	MaxPublicConns = 200
	// keyReload é o intervalo de recarga das chaves (a CLI escreve no banco com o serviço rodando).
	keyReload = 2 * time.Second
	// purgeInterval é o intervalo do expurgo dos agregados (spec 018 RF-08).
	purgeInterval = time.Hour
	// dbSpaceDegraded é a fração do teto do banco a partir da qual o health fica degraded (spec 018 RF-11).
	dbSpaceDegraded = 0.9
	shutdownTimeout = 5 * time.Second
)

// SubscribeFunc assina um subject do NATS e devolve como cancelar (nats.Conn.Subscribe nos binários, falso nos
// testes).
type SubscribeFunc func(subject string, handle func(data []byte)) (unsubscribe func(), err error)

// Deps são as dependências externas do serviço.
type Deps struct {
	Log       *slog.Logger
	Metrics   *service.Metrics
	DB        *sql.DB
	TLS       *tls.Config // certificados da 9000 (pkg/certs), escolha por SNI
	OpenAPI   []byte
	Version   string
	Subscribe SubscribeFunc
	// Reasons (opcional) soma motivos de degraded externos ao bot (certificados).
	Reasons func(now time.Time) []string
	Now     func() time.Time
}

// Server é o serviço bot.
type Server struct {
	cfg     Config
	deps    Deps
	keys    *KeyStore
	limiter *Limiter
	index   *Index
	hub     *Hub
	feed    *StoreFeed
	api     *API
}

// New monta o serviço sem abrir portas.
func New(cfg Config, d Deps) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Metrics == nil {
		d.Metrics = service.NewMetrics()
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	s := &Server{cfg: cfg, deps: d}
	s.keys = NewKeyStore(d.DB)
	s.limiter = NewLimiter(d.DB, d.Now)
	s.index = NewIndex(cfg.ConnTTL, cfg.MaxConns, func(n int) { d.Metrics.Add(metricConnsEvicted, float64(n)) })
	s.hub = NewHub()
	s.feed = NewStoreFeed(s.index, d.Now)
	s.api = &API{
		Keys: s.keys, Limiter: s.limiter, Index: s.index, Hub: s.hub, DB: d.DB, OpenAPI: d.OpenAPI,
		Health: s.Health, Metrics: d.Metrics, Now: d.Now, ViewWait: cfg.ViewWait,
	}
	return s
}

// Status é o estado do heartbeat e do health (spec 018 RF-11; listas, webhook e silêncio do store na segunda
// onda).
func (s *Server) Status() (string, []string) {
	var reasons []string
	if s.cfg.MaxBytes > 0 && float64(dbFileSize(s.cfg.DBPath)) > dbSpaceDegraded*float64(s.cfg.MaxBytes) {
		reasons = append(reasons, "db space")
	}
	if s.deps.Reasons != nil {
		reasons = append(reasons, s.deps.Reasons(s.deps.Now())...)
	}
	if len(reasons) > 0 {
		return event.StatusDegraded, reasons
	}
	return event.StatusOK, nil
}

// Health monta o BotHealth do openapi.
func (s *Server) Health() Health {
	st, reasons := s.Status()
	return Health{
		Status: st, Version: s.deps.Version, Reasons: reasons, RulesVersion: RulesVersion, ListsVersion: ListsVersion,
		Lists: []ListHealth{},
	}
}

// Handler devolve o handler de uma porta (para os testes).
func (s *Server) Handler(internal bool) http.Handler {
	return s.api.Handler(internal, s.cfg.InternalAllow)
}

// Index expõe o índice (para os testes e a segunda onda).
func (s *Server) Index() *Index { return s.index }

// Keys expõe o cache de chaves.
func (s *Server) Keys() *KeyStore { return s.keys }

// Run abre as portas e atende até ctx acabar.
func (s *Server) Run(ctx context.Context) error {
	internalIPs := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	if s.cfg.InternalListen.IsValid() && s.cfg.InternalListen != internalIPs[0] {
		internalIPs = append(internalIPs, s.cfg.InternalListen)
	}
	internal, err := listenAll(listenerAddrs(internalIPs, s.cfg.InternalPort))
	if err != nil {
		return err
	}
	public, err := listenAll(listenerAddrs(s.cfg.PublicIPs, s.cfg.PublicPort))
	if err != nil {
		closeAll(internal)
		return err
	}
	if len(public) == 0 {
		s.deps.Log.Warn("bot: FS_LISTEN_IPV4 and FS_LISTEN_IPV6 empty, public port disabled")
	}
	return s.Serve(ctx, public, internal)
}

// Serve atende os listeners já abertos: public com TLS e teto de conexões, internal em HTTP.
func (s *Server) Serve(ctx context.Context, public, internal []net.Listener) error {
	if err := s.keys.Reload(ctx); err != nil {
		closeAll(public)
		closeAll(internal)
		return err
	}
	unsubscribe := func() {}
	if s.deps.Subscribe != nil {
		u, err := s.deps.Subscribe(event.SubjectStoreConnection, func(data []byte) {
			if err := s.feed.Handle(data); err != nil {
				s.deps.Log.Debug("bot: store connection ignored", "err", err)
			}
		})
		if err != nil {
			closeAll(public)
			closeAll(internal)
			return fmt.Errorf("bot: subscribe: %w", err)
		}
		unsubscribe = u
	}
	defer unsubscribe()

	var servers []*http.Server
	errc := make(chan error, len(public)+len(internal))
	serve := func(l net.Listener, h http.Handler, tlsCfg *tls.Config) {
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, TLSConfig: tlsCfg}
		servers = append(servers, srv)
		go func() {
			var err error
			if tlsCfg != nil {
				err = srv.ServeTLS(l, "", "")
			} else {
				err = srv.Serve(l)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	for _, l := range internal {
		serve(l, s.Handler(true), nil)
	}
	for _, l := range public {
		tlsCfg := s.deps.TLS
		if tlsCfg == nil {
			closeAll(public)
			closeAll(internal)
			return errors.New("bot: public port without TLS config")
		}
		serve(netutil.LimitListener(l, MaxPublicConns), s.Handler(false), tlsCfg.Clone())
	}
	s.deps.Log.Info("bot: listening", "public", addrs(public), "internal", addrs(internal))

	var wg sync.WaitGroup
	loopCtx, stopLoops := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.loops(loopCtx)
	}()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	stopLoops()
	wg.Wait()
	shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shCtx)
	}
	if err := s.limiter.Flush(shCtx); err != nil {
		s.deps.Log.Warn("bot: final usage flush", "err", err)
	}
	return runErr
}

// loops roda a recarga das chaves, o flush do uso e das métricas e o expurgo.
func (s *Server) loops(ctx context.Context) {
	reload := time.NewTicker(keyReload)
	defer reload.Stop()
	flush := time.NewTicker(s.cfg.FlushInterval)
	defer flush.Stop()
	purge := time.NewTicker(purgeInterval)
	defer purge.Stop()
	s.purge(ctx)
	s.updateMetrics()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reload.C:
			if err := s.keys.Reload(ctx); err != nil && ctx.Err() == nil {
				s.deps.Log.Warn("bot: key reload", "err", err)
			}
		case <-flush.C:
			if err := s.limiter.Flush(ctx); err != nil && ctx.Err() == nil {
				s.deps.Log.Warn("bot: usage flush", "err", err)
			}
			s.updateMetrics()
		case <-purge.C:
			s.purge(ctx)
		}
	}
}

func (s *Server) purge(ctx context.Context) {
	n, err := Purge(ctx, s.deps.DB, s.deps.Now(), s.cfg.AggRetention)
	if err != nil {
		if ctx.Err() == nil {
			s.deps.Log.Warn("bot: purge", "err", err)
		}
		return
	}
	s.deps.Metrics.Add(metricPurged, float64(n))
}

func (s *Server) updateMetrics() {
	m := s.deps.Metrics
	m.Set(metricKeysActive, float64(s.keys.Active()))
	m.Set(metricStoreFeedMessages, float64(s.feed.Messages()))
	m.Set(metricDBBytes, float64(dbFileSize(s.cfg.DBPath)))
}

func listenAll(addrs []string) ([]net.Listener, error) {
	ls := make([]net.Listener, 0, len(addrs))
	for _, a := range addrs {
		l, err := net.Listen("tcp", a)
		if err != nil {
			closeAll(ls)
			return nil, fmt.Errorf("bot: listen %s: %w", a, err)
		}
		ls = append(ls, l)
	}
	return ls, nil
}

func closeAll(ls []net.Listener) {
	for _, l := range ls {
		_ = l.Close()
	}
}

func addrs(ls []net.Listener) string {
	s := make([]string, len(ls))
	for i, l := range ls {
		s[i] = l.Addr().String()
	}
	return strings.Join(s, ",")
}
