package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// StatusFunc devolve o estado atual do serviço para o heartbeat (ok ou degraded, com motivos).
type StatusFunc func() (status string, reasons []string)

// Service é o esqueleto comum: log, NATS, produtor, métricas e heartbeat.
type Service struct {
	Name     string
	Config   Config
	Log      *slog.Logger
	Metrics  *Metrics
	NC       *nats.Conn
	Producer *Producer

	started time.Time
	mu      sync.Mutex
	status  StatusFunc
}

// New carrega a configuração, cria o log e conecta ao NATS. A conexão é assíncrona: se o NATS estiver fora,
// o serviço sobe assim mesmo e o produtor guarda os eventos (ADR 0003).
func New(name string) (*Service, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel})).
		With("service", name, "version", version.Version)
	s := &Service{Name: name, Config: cfg, Log: log, Metrics: NewMetrics(), started: time.Now()}

	nc, err := nats.Connect(cfg.NATSURL,
		nats.Name("finger-sniffer-"+name),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
		// Sem o buffer interno do cliente: o buffer é o do Producer, com limites do contrato.
		nats.ReconnectBufSize(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) { log.Warn("nats disconnected", "err", err) }),
		nats.ReconnectHandler(func(*nats.Conn) {
			log.Info("nats reconnected")
			s.Producer.Flush()
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("service: nats: %w", err)
	}
	s.NC = nc
	s.Producer = NewProducer(nc, cfg.BufferMaxAge, cfg.BufferMaxBytes, s.Metrics)
	return s, nil
}

// SetStatus define a função de estado usada no heartbeat (padrão: sempre ok).
func (s *Service) SetStatus(f StatusFunc) {
	s.mu.Lock()
	s.status = f
	s.mu.Unlock()
}

// HeartbeatMessage monta a mensagem de heartbeat atual.
func (s *Service) HeartbeatMessage(now time.Time) (*nats.Msg, error) {
	s.mu.Lock()
	f := s.status
	s.mu.Unlock()
	st, reasons := event.StatusOK, []string(nil)
	if f != nil {
		st, reasons = f()
	}
	env, err := event.New(s.Name, version.Version, now, nil, event.Heartbeat{
		Status: st, Reasons: reasons, Commit: version.Commit,
		StartedAt: event.FormatTime(s.started), Metrics: s.Metrics.Snapshot(),
	})
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	return &nats.Msg{Subject: event.SubjectHeartbeat, Data: data}, nil
}

// Run publica heartbeats e chama main até SIGINT/SIGTERM ou até main retornar. main pode ser nil
// (serviço que só publica heartbeat, como os stubs da F1).
func (s *Service) Run(main func(ctx context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s.Log.Info("service started", "commit", version.Commit, "nats", s.Config.NATSURL)

	go s.heartbeatLoop(ctx)

	var err error
	if main != nil {
		err = main(ctx)
	} else {
		<-ctx.Done()
	}
	s.Producer.Flush()
	_ = s.NC.Drain()
	s.Log.Info("service stopped", "err", err)
	return err
}

func (s *Service) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(s.Config.HeartbeatInterval)
	defer t.Stop()
	flush := time.NewTicker(200 * time.Millisecond)
	defer flush.Stop()
	send := func() {
		msg, err := s.HeartbeatMessage(time.Now())
		if err != nil {
			s.Log.Error("heartbeat", "err", err)
			return
		}
		s.Producer.Publish(msg)
	}
	send()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			send()
		case <-flush.C:
			s.Producer.Flush()
		}
	}
}
