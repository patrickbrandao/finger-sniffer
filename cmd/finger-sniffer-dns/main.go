// Comando finger-sniffer-dns: autoritativo de FS_DNS_ZONE em UDP e TCP 53 (spec 007), com o TXT do DNS-01
// pedido pelo web por NATS (spec 015).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/patrickbrandao/finger-sniffer/internal/dns"
	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

const serviceName = "finger-sniffer-dns"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String(serviceName))
		return
	}
	cfg, err := dns.LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
	svc, err := service.New(event.ServiceDNS)
	if err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
	if err := dns.Run(svc, cfg); err != nil {
		svc.Log.Error("dns stopped", "err", err)
		os.Exit(1)
	}
}
