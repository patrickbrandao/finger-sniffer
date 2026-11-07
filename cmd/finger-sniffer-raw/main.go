// Comando finger-sniffer-raw: stub do serviço raw (task 001).
// Por enquanto só identifica a versão e aguarda o sinal de parada, para o systemd manter a unit ativa.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
)

const serviceName = "finger-sniffer-raw"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String(serviceName))
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("service started", "service", serviceName, "version", version.Version, "commit", version.Commit, "stub", true)

	// Aguarda SIGINT/SIGTERM (systemd stop) para encerrar de forma limpa.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("service stopped", "service", serviceName)
}
