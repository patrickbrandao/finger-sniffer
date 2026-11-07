// Comando finger-sniffer-store: dono dos registros, API e health (spec 004).
package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"os"

	"github.com/patrickbrandao/finger-sniffer/internal/store"
	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

const serviceName = "finger-sniffer-store"

// openAPISpec é o contrato da API (spec 004), servido em /api/v1/openapi.yaml.
//
//go:embed openapi.yaml
var openAPISpec []byte

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
	svc, err := service.New(event.ServiceStore)
	if err != nil {
		return err
	}
	cfg, err := store.LoadConfig()
	if err != nil {
		return err
	}
	st, err := store.New(context.Background(), svc, cfg, openAPISpec)
	if err != nil {
		return err
	}
	return svc.Run(st.Run)
}
