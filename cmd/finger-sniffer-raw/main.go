// Comando finger-sniffer-raw: serviço raw (spec 006). Portas TCP cruas com os modos echo, banner, sink e
// source, TLS (portas tls-* e TLS automático), linha PROBE e meio-fechamento; publica os bytes e o resumo de
// cada sessão no NATS.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/raw"
	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
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
	// Certificado e configuração TLS do espelho: os mesmos do web, com recarga a quente (spec 015 RF-04).
	store, err := certs.Open(certs.LoadConfig(), svc.Log)
	if err != nil {
		svc.Log.Error("raw: certs", "err", err)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()
	cfg.TLS = store.TLSConfig()
	cfg.EventInlineMax = svc.Config.EventInlineMax
	// Certificado autoassinado ou perto de expirar deixa o serviço degraded, como no web.
	svc.SetStatus(func() (string, []string) {
		if r := store.Reasons(time.Now()); len(r) > 0 {
			return event.StatusDegraded, r
		}
		return event.StatusOK, nil
	})
	srv := raw.New(cfg, svc.Producer, svc.Log, svc.Metrics)
	if err := svc.Run(srv.Run); err != nil {
		svc.Log.Error("raw: stopped", "err", err)
		_ = store.Close()
		os.Exit(1)
	}
}
