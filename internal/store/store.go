package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Config do store nesta fase.
type Config struct {
	DBPath       string
	HTTPAddr     string
	Retention    string
	RetentionDur time.Duration
	MaxBytes     int64
	DownAfter    time.Duration
	Host         HostPaths
	Ingest       IngestConfig
}

// LoadConfig lê FS_* do store.
func LoadConfig() (Config, error) {
	c := Config{
		DBPath:    service.Env("FS_STORE_DB", "/finger-sniffer/var/store/finger-sniffer.sqlite"),
		HTTPAddr:  ":" + service.Env("FS_API_HTTP_PORT", "9001"),
		Retention: service.Env("FS_RETENTION", "10m"),
		Host:      DefaultHostPaths,
	}
	maxBytes, err := service.EnvInt("FS_STORE_MAX_BYTES", 2<<30)
	if err != nil {
		return c, err
	}
	c.MaxBytes = int64(maxBytes)
	if c.DownAfter, err = service.EnvDuration("FS_HEALTH_DOWN_AFTER", DefaultDownAfter); err != nil {
		return c, err
	}
	c.Host.SysctlFile = service.Env("FS_SYSCTL_FILE", c.Host.SysctlFile)
	if c.RetentionDur, err = time.ParseDuration(c.Retention); err != nil {
		return c, fmt.Errorf("store: FS_RETENTION: %w", err)
	}
	idle, err := service.EnvDuration("FS_IDLE_DEFAULT", 120*time.Second)
	if err != nil {
		return c, err
	}
	pcapMax, err := service.EnvInt("FS_PCAP_MAX_BYTES_PER_CONN", 16<<20)
	if err != nil {
		return c, err
	}
	maxOpen, err := service.EnvInt("FS_MAX_CONNS", 200)
	if err != nil {
		return c, err
	}
	maxNew, err := service.EnvInt("FS_MAX_NEW_CONNS_PER_S", 50)
	if err != nil {
		return c, err
	}
	snap, err := service.EnvInt("FS_CAPTURE_SNAPLEN", 65535)
	if err != nil {
		return c, err
	}
	c.Ingest = IngestConfig{
		PcapMax: int64(pcapMax), TCPIdle: idle + 30*time.Second, UDPIdle: 30 * time.Second,
		CloseGrace: time.Second, MaxOpen: maxOpen, MaxNewPerS: maxNew, Snaplen: uint32(snap), //nolint:gosec // snaplen pequeno
	}
	return c, nil
}

// Store junta banco, barramento, rastreador de heartbeats e API.
type Store struct {
	cfg     Config
	svc     *service.Service
	db      *sql.DB // escrita (ingest, retenção, DELETE)
	rdb     *sql.DB // leitura (API)
	tracker *Tracker
	ingest  *Ingestor
	queries *Queries
	openapi []byte
}

// New abre o banco e prepara o store.
func New(ctx context.Context, svc *service.Service, cfg Config, openapi []byte) (*Store, error) {
	db, err := OpenDB(ctx, cfg.DBPath)
	if err != nil {
		return nil, err
	}
	rdb, err := OpenReadDB(cfg.DBPath, 4)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &Store{cfg: cfg, svc: svc, db: db, rdb: rdb, tracker: NewTracker(event.Services, cfg.DownAfter), openapi: openapi}
	s.ingest = NewIngestor(db, cfg.Ingest, svc.Log, svc.Metrics)
	s.queries = NewQueries(rdb, s.ingest.flows.live, cfg.Ingest.Snaplen)
	// O estado do próprio store no heartbeat reflete o host (offloads, NTP, conntrack).
	svc.SetStatus(func() (string, []string) {
		if _, reasons := ReadHost(cfg.Host); len(reasons) > 0 {
			return event.StatusDegraded, reasons
		}
		return event.StatusOK, nil
	})
	return s, nil
}

// HealthAt monta a resposta do health.
func (s *Store) HealthAt(ctx context.Context, now time.Time) Health {
	services, allUp, match := s.tracker.Services(now, version.Version)
	host, _ := ReadHost(s.cfg.Host)
	size, conns, oldest := dbStats(ctx, s.db, s.cfg.DBPath)
	st := &DBHealth{DBBytes: size, MaxBytes: s.cfg.MaxBytes, Retention: s.cfg.Retention, Connections: conns}
	if oldest.Valid {
		o := event.FormatTime(time.Unix(0, oldest.Int64))
		st.Oldest = &o
	}
	host.Store = st
	return Health{OK: allUp, Version: version.Version, VersionsMatch: match, Services: services, Host: host}
}

// Run cria o stream, assina os heartbeats e serve a API até ctx terminar.
func (s *Store) Run(ctx context.Context) error {
	defer func() { _ = s.db.Close(); _ = s.rdb.Close() }()

	sub, err := s.svc.NC.Subscribe(event.SubjectHeartbeat, func(m *nats.Msg) {
		if err := s.tracker.Observe(m.Data, time.Now()); err != nil {
			s.svc.Log.Warn("invalid heartbeat", "err", err)
		}
	})
	if err != nil {
		return err
	}
	defer func() { _ = sub.Unsubscribe() }()

	// O stream é criado em segundo plano (o NATS pode ainda estar subindo); depois começa o ingest.
	go func() {
		cons := s.ensureStream(ctx)
		if cons == nil {
			return
		}
		if err := s.ingest.Run(ctx, cons); err != nil {
			s.svc.Log.Error("ingest stopped", "err", err)
		}
	}()
	go s.retentionLoop(ctx)

	api := &API{OpenAPI: s.openapi, Health: s.HealthAt, Now: time.Now, Q: s.queries, W: s.db}
	srv := &http.Server{
		Addr: s.cfg.HTTPAddr, Handler: api.Handler(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	s.svc.Log.Info("api listening", "addr", s.cfg.HTTPAddr)

	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shut)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Store) ensureStream(ctx context.Context) jetstream.Consumer {
	js, err := jetstream.New(s.svc.NC)
	if err != nil {
		s.svc.Log.Error("jetstream", "err", err)
		return nil
	}
	for ctx.Err() == nil {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		cons, err := EnsureStream(c, js)
		cancel()
		if err == nil {
			s.svc.Log.Info("stream ready", "stream", StreamName, "storage", "memory")
			return cons
		}
		s.svc.Log.Warn("stream not ready", "err", err)
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	return nil
}

// retentionLoop expurga a cada 10 s (spec 004 RF-06).
func (s *Store) retentionLoop(ctx context.Context) {
	r := NewRetention(s.db, s.cfg.RetentionDur, s.cfg.MaxBytes)
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := r.RunOnce(ctx, time.Now())
			if err != nil {
				s.svc.Log.Warn("retention", "err", err)
			}
			s.svc.Metrics.Add("store_expunged_total", float64(n))
			size, _, _ := dbStats(ctx, s.db, s.cfg.DBPath)
			s.svc.Metrics.Set("store_db_bytes", float64(size))
		}
	}
}
