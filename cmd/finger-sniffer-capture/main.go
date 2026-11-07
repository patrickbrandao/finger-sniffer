// Comando finger-sniffer-capture: captura AF_PACKET da eth0 e publica lotes FSPB v1 no NATS (spec 003).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/patrickbrandao/finger-sniffer/internal/capture"
	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

const serviceName = "finger-sniffer-capture"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String(serviceName))
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := capture.LoadConfig()
	if err != nil {
		return err
	}
	svc, err := service.New(event.ServiceCapture)
	if err != nil {
		return err
	}
	return svc.Run(func(ctx context.Context) error { return capture.Run(ctx, svc, cfg) })
}
