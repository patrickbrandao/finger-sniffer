// Comando finger-sniffer-bot: serviço de vereditos de bot (specs 018 e 020). Sem subcomando, sobe o serviço
// (API 9002 HTTPS e 9003 HTTP, ingest do traefik, assinatura de fs.v1.store.connection, heartbeat); com
// `key ...` ou `forget ...`, opera a CLI no banco em disco (FS_BOT_DB).
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/internal/bot"
	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

const serviceName = "finger-sniffer-bot"

// pendingLimit é a fila do assinante de fs.v1.store.connection no cliente NATS; cheia, o NATS descarta (o store
// publica cada estágio de novo, e o índice é só a visão mais recente).
const pendingLimit = 65536

//go:embed openapi.yaml
var openapiYAML []byte

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String(serviceName))
		return
	}
	if args := flag.Args(); len(args) > 0 {
		os.Exit(runCLI(args))
	}
	cfg, err := bot.LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
	svc, err := service.New(bot.ServiceName)
	if err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
	db, err := bot.OpenDB(context.Background(), cfg.DBPath)
	if err != nil {
		svc.Log.Error("bot: db", "err", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()
	// Certificados da 9000 (A e B por SNI, recarga a quente; ADR 0051 item 6).
	store, err := certs.Open(certs.LoadConfig(), svc.Log)
	if err != nil {
		svc.Log.Error("bot: certs", "err", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()
	srv := bot.New(cfg, bot.Deps{
		Log: svc.Log, Metrics: svc.Metrics, DB: db, TLS: store.TLSConfig(), OpenAPI: openapiYAML,
		Version: version.Version, Reasons: store.Reasons,
		Subscribe: func(subject string, handle func([]byte)) (func(), error) {
			sub, err := svc.NC.Subscribe(subject, func(m *nats.Msg) { handle(m.Data) })
			if err != nil {
				return nil, err
			}
			_ = sub.SetPendingLimits(pendingLimit, 256<<20)
			return func() { _ = sub.Unsubscribe() }, nil
		},
	})
	svc.SetStatus(srv.Status)
	if err := svc.Run(srv.Run); err != nil {
		svc.Log.Error("bot: stopped", "err", err)
		_ = db.Close()
		_ = store.Close()
		os.Exit(1)
	}
}

// runCLI roda key/forget e devolve o código de saída.
func runCLI(args []string) int {
	path := service.Env("FS_BOT_DB", "/finger-sniffer/var/bot/bot.db")
	err := bot.RunCLI(context.Background(), args, path, os.Stdout, os.Stderr, time.Now())
	switch {
	case err == nil:
		return 0
	case errors.Is(err, bot.ErrUsage):
		return 2
	}
	fmt.Fprintln(os.Stderr, serviceName+":", err)
	return 1
}
