// Comando finger-sniffer-raw: stub do serviço raw. Na F1 só publica heartbeat (task 007); a função do
// serviço chega nas fases seguintes do PLAN.
package main

import (
	"flag"
	"fmt"
	"os"

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
	svc, err := service.New(event.ServiceRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
	if err := svc.Run(nil); err != nil {
		os.Exit(1)
	}
}
