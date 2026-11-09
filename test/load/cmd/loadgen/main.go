//go:build load

// Comando loadgen: gerador e medidor da carga de 10 min (task 068, spec 017 RF-13, ADR 0022). Roda na máquina
// cliente (fora da vps602). Dois modos:
//
//	loadgen run -out DIR [flags]   gera a carga, lê o feed (/ws e /stream), amostra a API e o health e grava os
//	                               dados brutos em DIR (gen.json, conns.csv, timeline.csv, feed_*.csv);
//	loadgen report -dir DIR        junta gen.json e o cgroup.csv da vps602 e escreve summary.json e summary.md.
//
// Cada conexão tem um probe ID próprio (Host/SNI <id>.dns-monitor.tmsoft.com.br ou linha PROBE no raw) e vive
// -life; o pacer abre -rate conexões novas por segundo, em intervalos iguais, sem passar de -max-active.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "uso: loadgen run|report [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runCmd(os.Args[2:])
	case "report":
		err = reportCmd(os.Args[2:])
	default:
		err = fmt.Errorf("modo desconhecido: %s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(1)
	}
}
