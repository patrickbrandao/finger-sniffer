// Comando finger-sniffer-web: serviço web (spec 005). Atende as portas TCP capturadas com detecção do
// protocolo pelos primeiros bytes, TLS com ClientHello capturado (spec 008), HTTP/1 sem normalização
// (spec 009), rotas do espelho e o site de FS_HTDOCS (spec 014), e publica os eventos de aplicação no NATS.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/internal/web"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

const serviceName = "finger-sniffer-web"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String(serviceName))
		return
	}
	svc, err := service.New(event.ServiceWeb)
	if err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
	cfg, err := web.LoadConfig(svc.Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
	if err := web.Run(svc, cfg); err != nil {
		svc.Log.Error("web stopped", "err", err)
		os.Exit(1)
	}
}
