package store

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/p0f"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Padrões do modo degradado (spec 004 RF-11): acima da garantia da spec 000 RNF-01 (200 e 50/s), com margem para
// o tráfego alheio de um servidor público (ADR 0030).
const (
	DefaultMaxConns        = 250
	DefaultMaxNewConnsPerS = 60
)

// Config do store nesta fase.
type Config struct {
	DBPath    string
	HTTPAddr  string
	HTTPSAddr string // FS_API_HTTPS_PORT; vazio desliga a 9000
	// ListenIPs são os IPs da API (127.0.0.1 + FS_LISTEN_IPV4/IPV6); vazio = HTTPAddr/HTTPSAddr como vieram.
	ListenIPs    []netip.Addr
	Certs        certs.Config
	Retention    string
	RetentionDur time.Duration
	MaxBytes     int64
	DownAfter    time.Duration
	Host         HostPaths
	Ingest       IngestConfig
	P0FPath      string // FS_P0F_DB
	LiveBuffer   int    // FS_LIVE_BUFFER (ADR 0020)
	LiveMax      int    // FS_LIVE_MAX_CLIENTS
}

// LoadConfig lê FS_* do store.
func LoadConfig() (Config, error) {
	c := Config{
		DBPath:    service.Env("FS_STORE_DB", "/finger-sniffer/var/store/finger-sniffer.sqlite"),
		HTTPAddr:  ":" + service.Env("FS_API_HTTP_PORT", "9001"),
		HTTPSAddr: ":" + service.Env("FS_API_HTTPS_PORT", "9000"),
		Certs:     certs.LoadConfig(),
		Retention: service.Env("FS_RETENTION", "10m"),
		Host:      DefaultHostPaths,
		P0FPath:   service.Env("FS_P0F_DB", "/finger-sniffer/etc/p0f.fp"),
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
	if c.ListenIPs, err = listenIPs(); err != nil {
		return c, err
	}
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
	maxOpen, err := service.EnvInt("FS_MAX_CONNS", DefaultMaxConns)
	if err != nil {
		return c, err
	}
	maxNew, err := service.EnvInt("FS_MAX_NEW_CONNS_PER_S", DefaultMaxNewConnsPerS)
	if err != nil {
		return c, err
	}
	snap, err := service.EnvInt("FS_CAPTURE_SNAPLEN", 65535)
	if err != nil {
		return c, err
	}
	rawMax, err := service.EnvInt(event.EnvRawStreamMaxBytes, event.DefaultRawStreamMaxBytes)
	if err != nil {
		return c, err
	}
	segs, err := service.EnvInt("FS_TCP_SEGMENTS_TRACKED", 32)
	if err != nil {
		return c, err
	}
	if c.LiveBuffer, err = service.EnvInt("FS_LIVE_BUFFER", DefaultLiveBuffer); err != nil {
		return c, err
	}
	if c.LiveMax, err = service.EnvInt("FS_LIVE_MAX_CLIENTS", DefaultLiveMaxClients); err != nil {
		return c, err
	}
	grace, err := service.EnvDuration("FS_TCP_CLOSE_GRACE", DefaultCloseGrace)
	if err != nil {
		return c, err
	}
	if grace < 0 || grace > 500*time.Millisecond {
		return c, fmt.Errorf("store: FS_TCP_CLOSE_GRACE precisa estar entre 0 e 500ms (spec 004 RNF-01)")
	}
	if segs < 32 {
		return c, fmt.Errorf("store: FS_TCP_SEGMENTS_TRACKED precisa ser >= 32 (spec 013 RF-09)")
	}
	c.Ingest = IngestConfig{
		PcapMax: int64(pcapMax), TCPIdle: idle + 30*time.Second, UDPIdle: 30 * time.Second,
		CloseGrace: grace, MaxOpen: maxOpen, MaxNewPerS: maxNew, Snaplen: uint32(snap), //nolint:gosec // snaplen pequeno
		SegmentsTracked: segs, RawStreamMax: rawMax, Retention: c.RetentionDur,
	}
	netstat := c.Host.ProcNetstat
	c.Ingest.Syncookies = func() int64 { return readNetstat(netstat, "TcpExt", "SyncookiesSent") }
	return c, nil
}

// Store junta banco, barramento, rastreador de heartbeats e API.
type Store struct {
	cfg     Config
	svc     *service.Service
	db      *sql.DB // escrita (ingest, retenção, DELETE)
	rdb     *sql.DB // leitura (API)
	cdb     *sql.DB // checkpoint do WAL (task 105)
	tracker *Tracker
	ingest  *Ingestor
	queries *Queries
	openapi []byte
	certs   *certs.Store // nil quando a 9000 está desligada
	live    *Hub
	prom    *storeMetrics
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
	cdb, err := OpenCheckpointDB(cfg.DBPath)
	if err != nil {
		_ = db.Close()
		_ = rdb.Close()
		return nil, err
	}
	s := &Store{cfg: cfg, svc: svc, db: db, rdb: rdb, cdb: cdb, tracker: NewTracker(event.Services, cfg.DownAfter), openapi: openapi}
	if cfg.Ingest.P0F == nil && cfg.P0FPath != "" {
		// Sem o p0f.fp o store sobe assim mesmo: a assinatura p0f sai crua, sem palpite de SO.
		if fp, err := p0f.LoadDB(cfg.P0FPath); err != nil {
			svc.Log.Warn("p0f.fp not loaded", "path", cfg.P0FPath, "err", err)
		} else {
			cfg.Ingest.P0F = fp
			svc.Log.Info("p0f.fp loaded", "path", cfg.P0FPath, "tcp_request_sigs", len(fp.TCPRecords(true)))
		}
	}
	if cfg.HTTPSAddr != "" {
		// Sem arquivos em FS_CERT_DIR o pkg/certs usa um autoassinado em memória (spec 015 RF-05).
		if s.certs, err = certs.Open(cfg.Certs, svc.Log); err != nil {
			_ = db.Close()
			_ = rdb.Close()
			_ = cdb.Close()
			return nil, err
		}
	}
	s.ingest = NewIngestor(db, cfg.Ingest, svc.Log, svc.Metrics)
	s.live = NewHub(cfg.LiveBuffer, cfg.LiveMax)
	s.ingest.SetLive(s.live)
	s.prom = newStoreMetrics(func(ctx context.Context) Health { return s.HealthAt(ctx, time.Now()) }, s.ingest.flows.open, s.live)
	s.ingest.SetMetrics(s.prom)
	s.queries = NewQueries(rdb, s.ingest.flows.live, cfg.Ingest.Snaplen)
	// O estado do próprio store no heartbeat reflete o host (offloads, NTP, conntrack).
	// O estado dos certificados da 9000 também conta (spec 015 RF-05: autoassinado ou expirando = degraded).
	svc.SetStatus(func() (string, []string) {
		_, reasons := ReadHost(cfg.Host)
		if s.certs != nil {
			reasons = append(reasons, s.certs.Reasons(time.Now())...)
		}
		if len(reasons) > 0 {
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
	size, conns, oldest := dbStats(ctx, s.rdb, s.cfg.DBPath)
	st := &DBHealth{DBBytes: size, MaxBytes: s.cfg.MaxBytes, Retention: s.cfg.Retention, Connections: conns}
	if oldest.Valid {
		o := event.FormatTime(time.Unix(0, oldest.Int64))
		st.Oldest = &o
	}
	host.Store = st
	tlsInfo := certs.Describe()
	host.TLSServer = &tlsInfo
	if s.certs != nil {
		host.Certificates = certificatesJSON(s.certs.State())
	}
	return Health{OK: allUp, Version: version.Version, VersionsMatch: match, Services: services, Host: host}
}

// Run cria o stream, assina os heartbeats e serve a API até ctx terminar.
func (s *Store) Run(ctx context.Context) error {
	defer func() { _ = s.db.Close(); _ = s.rdb.Close(); _ = s.cdb.Close() }()
	if s.certs != nil {
		defer func() { _ = s.certs.Close() }()
	}

	sub, err := s.svc.NC.Subscribe(event.SubjectHeartbeat, func(m *nats.Msg) {
		if err := s.tracker.Observe(m.Data, time.Now()); err != nil {
			s.svc.Log.Warn("invalid heartbeat", "err", err)
		}
	})
	if err != nil {
		return err
	}
	defer func() { _ = sub.Unsubscribe() }()

	// Request/reply NATS core, fora do laço de ingest (ADR 0017); a tabela de fluxos tem trava própria.
	cid, err := s.svc.NC.Subscribe(event.SubjectStoreConnID, s.handleConnID)
	if err != nil {
		return err
	}
	defer func() { _ = cid.Unsubscribe() }()

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
	go s.live.Run(ctx.Done())

	api := &API{OpenAPI: s.openapi, Health: s.HealthAt, Now: time.Now, Q: s.queries, W: s.db, Live: s.live, Prom: s.prom}
	srv := &http.Server{
		Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	addrs, err := s.cfg.apiAddrs(s.cfg.HTTPAddr)
	if err != nil {
		return err
	}
	ls, err := listenAll(addrs)
	if err != nil {
		return err
	}
	errc := serveAll(ls, srv.Serve)
	s.svc.Log.Info("api listening", "addr", addrsString(ls))
	var tlsSrv *http.Server
	tlsErr := make(<-chan error)
	if s.certs != nil {
		if tlsSrv, tlsErr, err = s.serveHTTPS(ctx, api); err != nil {
			_ = srv.Close()
			return err
		}
	}

	shutdown := func() error {
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if tlsSrv != nil {
			_ = tlsSrv.Shutdown(shut)
		}
		return srv.Shutdown(shut)
	}
	select {
	case <-ctx.Done():
		return shutdown()
	case err := <-errc:
		_ = shutdown()
		return err
	case err := <-tlsErr:
		_ = shutdown()
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

// retentionLoop expurga a cada segundo, em lotes curtos e com orçamento por rodada (spec 004 RF-06, task 105).
func (s *Store) retentionLoop(ctx context.Context) {
	r := NewRetention(s.db, s.cfg.RetentionDur, s.cfg.MaxBytes)
	r.OnPurge = s.prom.purge
	r.Budget = DefaultRetentionBudget
	t := time.NewTicker(RetentionInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := r.RunOnce(ctx, time.Now())
			if err != nil && ctx.Err() == nil {
				s.svc.Log.Warn("retention", "err", err)
			}
			if _, _, err := Checkpoint(ctx, s.cdb); err != nil && ctx.Err() == nil {
				s.svc.Log.Warn("wal checkpoint", "err", err)
			}
			s.svc.Metrics.Add("store_expunged_total", float64(n))
			s.svc.Metrics.Set("store_db_bytes", float64(dbFileSize(s.cfg.DBPath)))
		}
	}
}
