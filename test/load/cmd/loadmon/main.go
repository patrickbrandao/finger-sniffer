//go:build load

// Comando loadmon: lado vps602 do teste de carga (task 068). Dois modos:
//
//	loadmon sample -out /tmp/fs-load/cgroup.csv [-interval 1s]
//	    a cada intervalo, CPU (usage_usec) e memória (memory.current, anon, file) do cgroup de cada unit
//	    finger-sniffer-* e a CPU agregada do host (/proc/stat), até SIGTERM/SIGINT;
//	loadmon clock
//	    para cada linha recebida na entrada, escreve o relógio local em ns (estimativa do deslocamento de
//	    relógio feita pelo gerador por ssh).
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/patrickbrandao/finger-sniffer/test/load/loadstat"
)

// units monitoradas (5 serviços + NATS).
var units = []string{"capture", "web", "raw", "dns", "store", "nats"}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "uso: loadmon sample|clock [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "clock":
		clock()
	case "sample":
		fs := flag.NewFlagSet("sample", flag.ExitOnError)
		out := fs.String("out", "/tmp/fs-load/cgroup.csv", "CSV de saída")
		interval := fs.Duration("interval", time.Second, "intervalo de amostragem")
		root := fs.String("cgroup", "/sys/fs/cgroup/system.slice", "pasta dos cgroups das units")
		_ = fs.Parse(os.Args[2:])
		if err := sample(*out, *interval, *root); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "modo desconhecido:", os.Args[1])
		os.Exit(2)
	}
}

func clock() {
	sc := bufio.NewScanner(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	for sc.Scan() {
		_, _ = fmt.Fprintln(w, time.Now().UnixNano())
		_ = w.Flush()
	}
}

func readFile(p string) string {
	b, err := os.ReadFile(p) //nolint:gosec // caminhos fixos do cgroup e do /proc
	if err != nil {
		return ""
	}
	return string(b)
}

// sample grava uma linha por unit e por intervalo: t_ns,unit,cpu_usec,mem_current,anon,file; a linha da unit
// "host" leva busy/total/steal do /proc/stat em jiffies nas colunas cpu_usec/mem_current/anon.
func sample(out string, interval time.Duration, root string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	f, err := os.Create(out) //nolint:gosec // caminho do operador
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // fechado no fim
	w := bufio.NewWriter(f)
	_, _ = fmt.Fprintln(w, "t_ns,unit,cpu_usec,mem_current,anon,file")
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		now := time.Now().UnixNano()
		for _, u := range units {
			dir := filepath.Join(root, "finger-sniffer-"+u+".service")
			cpu := loadstat.ParseKV(readFile(filepath.Join(dir, "cpu.stat")))["usage_usec"]
			cur, _ := strconv.ParseInt(strings.TrimSpace(readFile(filepath.Join(dir, "memory.current"))), 10, 64)
			ms := loadstat.ParseKV(readFile(filepath.Join(dir, "memory.stat")))
			_, _ = fmt.Fprintf(w, "%d,%s,%d,%d,%d,%d\n", now, u, cpu, cur, ms["anon"], ms["file"])
		}
		if busy, total, steal, err := loadstat.ProcStatCPU(readFile("/proc/stat")); err == nil {
			_, _ = fmt.Fprintf(w, "%d,host,%d,%d,%d,0\n", now, busy, total, steal)
		}
		_ = w.Flush()
		select {
		case <-ctx.Done():
			return w.Flush()
		case <-tick.C:
		}
	}
}
