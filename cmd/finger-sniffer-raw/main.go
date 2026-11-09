// Comando finger-sniffer-raw: serviço raw (spec 006). Portas TCP cruas com os modos echo, banner, sink e
// source, linha PROBE e meio-fechamento; publica os bytes e o resumo de cada sessão no NATS.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/patrickbrandao/finger-sniffer/internal/raw"
	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

const serviceName = "finger-sniffer-raw"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String(serviceName))
		return
	}
	cfg, err := raw.LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
	svc, err := service.New(event.ServiceRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
	srv := raw.New(cfg, svc.Producer, svc.Log, svc.Metrics)
	if err := svc.Run(srv.Run); err != nil {
		svc.Log.Error("raw: stopped", "err", err)
		os.Exit(1)
	}
}
