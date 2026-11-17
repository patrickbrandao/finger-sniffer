package bot

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/agg"
	"github.com/patrickbrandao/finger-sniffer/internal/bot/lists"
	"github.com/patrickbrandao/finger-sniffer/internal/bot/rules"
	"github.com/patrickbrandao/finger-sniffer/internal/bot/webhook"
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
	// indexBytesDegraded é por quanto tempo um despejo por bytes deixa o health degraded (spec 018 RF-11).
	indexBytesDegraded = 60 * time.Second
	// metricIndexBytes é o total contabilizado do índice (spec 018 RF-12, ADR 0057 item 2).
	metricIndexBytes = "bot_index_bytes"
	// metricAggDropped conta as observações descartadas pelo teto de entradas dos agregados (ADR 0056).
	metricAggDropped = "bot_agg_dropped_total"
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
	// ListsClient e Resolver (opcionais) são o cliente HTTP do download das listas e o DNS da verificação de robô
	// (nil = os padrões; falsos nos testes).
	ListsClient *http.Client
	Resolver    lists.Resolver
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
	agg     *agg.Aggregator
	lists   *lists.Manager
	hooks   *webhook.Dispatcher
	judge   *Judge
	// store é o estado do store pelos heartbeats (health store feed silent).
	store storeWatch
	// reloadEvery é o ciclo da recarga das chaves e dos pedidos da CLI (keyReload; menor nos testes).
	reloadEvery time.Duration
	// refreshing marca um lists refresh pedido pela CLI em andamento; bg espera as goroutines dele na parada.
	refreshing atomic.Bool
	bg         sync.WaitGroup
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
	s := &Server{cfg: cfg, deps: d, reloadEvery: keyReload}
	s.keys = NewKeyStore(d.DB)
	s.limiter = NewLimiter(d.DB, d.Now)
	s.index = NewIndex(cfg.ConnTTL, cfg.MaxConns, cfg.IndexMaxBytes, func(reason string, n int) {
		d.Metrics.Add(evictedMetric(reason), float64(n))
	})
	for _, r := range []string{evictCount, evictBytes} {
		d.Metrics.Add(evictedMetric(r), 0) // as duas séries aparecem desde o início
	}
	// Contadores da spec 018 RF-12 que só andam com eventos aparecem zerados desde o primeiro heartbeat.
	for _, k := range []string{
		metricIngestRecords, metricIngestDropped, metricRateLimited, webhook.MetricDropped,
		metricIngestParseErrors + `{part="client_hello"}`, metricIngestParseErrors + `{part="h2_prefix"}`,
		metricPurged + `{reason="age"}`, metricPurged + `{reason="size"}`,
	} {
		d.Metrics.Add(k, 0)
	}
	s.hub = NewHub()
	s.agg = agg.New(agg.Config{MaxAge: cfg.AggRetention})
	s.lists = newLists(cfg, d)
	s.hooks = webhook.New(webhook.Options{Now: d.Now, Count: d.Metrics.Add})
	s.hub.SetSink(s.publishWebhook)
	s.feed = NewStoreFeed(s.index, d.Now)
	s.judge = newJudge(cfg, s.index, s.agg, s.hub, s.lists, d.Metrics, d.Now)
	s.api = &API{
		Keys: s.keys, Limiter: s.limiter, Index: s.index, Hub: s.hub, DB: d.DB, OpenAPI: d.OpenAPI,
		Health: s.Health, Metrics: d.Metrics, Now: d.Now, ViewWait: cfg.ViewWait, Judge: s.judge,
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
	if s.lists != nil {
		reasons = append(reasons, s.lists.StaleReasons(s.deps.Now())...)
	}
	if t := s.index.LastBytesEviction(); !t.IsZero() && s.deps.Now().Sub(t) < indexBytesDegraded {
		reasons = append(reasons, "index bytes")
	}
	if s.store.silent(s.feed.LastMessage(), s.deps.Now()) {
		reasons = append(reasons, "store feed silent")
	}
	if s.hooks.Backlog(s.deps.Now()) {
		reasons = append(reasons, "webhook backlog")
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
	h := Health{
		Status: st, Version: s.deps.Version, Reasons: reasons, RulesVersion: rules.RulesVersion,
		ListsVersion: s.judge.ListsVersion(), Lists: []ListHealth{},
	}
	if s.lists != nil {
		for _, l := range s.lists.Status(s.deps.Now()) {
			lh := ListHealth{Name: l.Name, Entries: l.Entries, Stale: l.Stale}
			if !l.FetchedAt.IsZero() {
				ts := event.FormatTime(l.FetchedAt)
				lh.FetchedAt = &ts
			}
			h.Lists = append(h.Lists, lh)
		}
	}
	return h
}

// newLists cria o gerenciador das listas (spec 018 RF-07); sem ListsDir (testes), só a base própria.
func newLists(cfg Config, d Deps) *lists.Manager {
	m, err := lists.NewManager(lists.Options{
		Dir: cfg.ListsDir, URLs: cfg.ListURLs, JA4DBEnable: cfg.JA4DBEnable, JA4DBURL: cfg.JA4DBURL,
		RefreshAt: cfg.ListRefreshAt, Version: d.Version, DB: d.DB, Now: d.Now, Log: d.Log,
		Client: d.ListsClient, Resolver: d.Resolver,
	})
	if err != nil {
		d.Log.Error("bot: lists disabled", "err", err)
		return nil
	}
	return m
}

// Lists expõe o gerenciador das listas (vereditos e CLI, tasks 282 e 283); nil se a base própria é inválida.
func (s *Server) Lists() *lists.Manager { return s.lists }

// Handler devolve o handler de uma porta (para os testes).
func (s *Server) Handler(internal bool) http.Handler {
	return s.api.Handler(internal, s.cfg.InternalAllow)
}

// Index expõe o índice (para os testes e a segunda onda).
func (s *Server) Index() *Index { return s.index }

// Agg expõe os agregados e o cache de comportamento (Observe e Query na task 282, Forget na 283).
func (s *Server) Agg() *agg.Aggregator { return s.agg }

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
	if s.deps.DB != nil {
		if err := s.agg.Load(ctx, s.deps.DB, s.deps.Now()); err != nil {
			s.deps.Log.Warn("bot: behavior cache load", "err", err)
		}
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
		// Heartbeats só para saber se o store está ok (store feed silent, spec 018 RF-11).
		uh, err := s.deps.Subscribe(event.SubjectHeartbeat, func(data []byte) { s.store.heartbeat(data, s.deps.Now()) })
		if err != nil {
			u()
			closeAll(public)
			closeAll(internal)
			return fmt.Errorf("bot: subscribe: %w", err)
		}
		unsubscribe = func() { uh(); u() }
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

	if s.lists != nil {
		s.lists.Load(ctx)
	}
	var wg sync.WaitGroup
	loopCtx, stopLoops := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.loops(loopCtx)
	}()
	if s.lists != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.lists.Run(loopCtx)
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	stopLoops()
	wg.Wait()
	s.bg.Wait()
	s.hooks.Wait()
	s.judge.bg.Wait()
	shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shCtx)
	}
	if err := s.limiter.Flush(shCtx); err != nil {
		s.deps.Log.Warn("bot: final usage flush", "err", err)
	}
	if err := s.flushAgg(shCtx); err != nil {
		s.deps.Log.Warn("bot: final aggregate flush", "err", err)
	}
	return runErr
}

// loops roda a recarga das chaves e os pedidos da CLI, o flush do uso, dos agregados e das métricas e o expurgo.
func (s *Server) loops(ctx context.Context) {
	reload := time.NewTicker(s.reloadEvery)
	defer reload.Stop()
	flush := time.NewTicker(s.cfg.FlushInterval)
	defer flush.Stop()
	purge := time.NewTicker(purgeInterval)
	defer purge.Stop()
	s.purge(ctx)
	s.updateMetrics()
	s.syncWebhooks(ctx)
	s.handleControls(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-reload.C:
			if err := s.keys.Reload(ctx); err != nil && ctx.Err() == nil {
				s.deps.Log.Warn("bot: key reload", "err", err)
			}
			s.syncWebhooks(ctx)
			s.handleControls(ctx)
		case <-flush.C:
			if err := s.limiter.Flush(ctx); err != nil && ctx.Err() == nil {
				s.deps.Log.Warn("bot: usage flush", "err", err)
			}
			if err := s.flushAgg(ctx); err != nil && ctx.Err() == nil {
				s.deps.Log.Warn("bot: aggregate flush", "err", err)
			}
			if s.cfg.MaxBytes > 0 && dbFileSize(s.cfg.DBPath) > s.cfg.MaxBytes {
				s.purgeSize(ctx)
			}
			s.updateMetrics()
		case <-purge.C:
			s.purge(ctx)
		}
	}
}

// flushAgg grava os agregados (spec 018 RF-08).
func (s *Server) flushAgg(ctx context.Context) error {
	if s.deps.DB == nil {
		return nil
	}
	return s.agg.Flush(ctx, s.deps.DB, s.deps.Now())
}

// syncWebhooks passa as chaves com webhook ao despachante (depois de cada recarga).
func (s *Server) syncWebhooks(ctx context.Context) {
	keys := s.keys.WebhookKeys()
	ts := make([]webhook.Target, 0, len(keys))
	for _, k := range keys {
		doms := k.Domains
		ts = append(ts, webhook.Target{
			KeyID: k.ID, Prefix: keyPrefix + k.Prefix, URL: k.WebhookURL, Secret: k.WebhookSecret(), Classes: k.WebhookClasses,
			Match: func(site string) bool { return MatchDomain(doms, site) },
		})
	}
	s.hooks.SetTargets(ctx, ts)
}

// publishWebhook é a saída do Hub para o webhook: corpo VerdictEvent, serializado só se alguma chave aceitar.
func (s *Server) publishWebhook(v *Verdict, site string) {
	if !s.hooks.Active() {
		return
	}
	s.hooks.Publish(v.Class, site, func() []byte {
		b, err := json.Marshal(VerdictEvent{Kind: "verdict", Ts: v.Ts, Verdict: v})
		if err != nil {
			return nil
		}
		return b
	})
}

// purge expurga por idade e, se o banco passou do teto, pelas horas mais antigas (ADR 0056 item 4: rótulo reason).
func (s *Server) purge(ctx context.Context) {
	n, err := Purge(ctx, s.deps.DB, s.deps.Now(), s.cfg.AggRetention)
	s.deps.Metrics.Add(metricPurged+`{reason="age"}`, float64(n))
	if err != nil && ctx.Err() == nil {
		s.deps.Log.Warn("bot: purge", "err", err)
	}
	s.purgeSize(ctx)
}

func (s *Server) purgeSize(ctx context.Context) {
	n, err := PurgeSize(ctx, s.deps.DB, s.cfg.DBPath, s.cfg.MaxBytes)
	if n > 0 {
		s.deps.Metrics.Add(metricPurged+`{reason="size"}`, float64(n))
	}
	if err != nil && ctx.Err() == nil {
		s.deps.Log.Warn("bot: purge size", "err", err)
	}
}

func (s *Server) updateMetrics() {
	m := s.deps.Metrics
	m.Set(metricKeysActive, float64(s.keys.Active()))
	m.Set(metricStoreFeedMessages, float64(s.feed.Messages()))
	m.Set(metricDBBytes, float64(dbFileSize(s.cfg.DBPath)))
	m.Set(metricAggDropped, float64(s.agg.Dropped()))
	m.Set(metricIndexBytes, float64(s.index.Bytes(s.deps.Now())))
	if s.lists != nil {
		s.lists.UpdateMetrics(s.deps.Now(), m.Set)
	}
}

// evictedMetric é bot_conns_evicted_total com o rótulo reason (formato da ADR 0056 item 4).
func evictedMetric(reason string) string {
	return metricConnsEvicted + `{reason="` + reason + `"}`
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
