//go:build load

// Comando loadmon: lado servidor (finger-01) do teste de carga (task 068). Dois modos:
//
//	loadmon sample -out /tmp/fs-load/cgroup.csv [-interval 1s]
//	    a cada intervalo, CPU (usage_usec) e memória (memory.current e, do memory.stat, anon, file, sock,
//	    kernel, slab e percpu; task 215), o nr_throttled do cpu.stat (ADR 0039) e, desde o banco em tmpfs
//	    (ADR 0045, task 247), o shmem do memory.stat, o memory.max e os contadores max e oom_kill do
//	    memory.events do cgroup de cada unit finger-sniffer-*, da fatia (linha "slice") e a CPU agregada do host
//	    (/proc/stat, com o número de núcleos), até SIGTERM/SIGINT;
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
		// fatia finger-sniffer.slice dentro de finger.slice (o systemd aninha pelo hífen; ADR 0039 item 1)
		root := fs.String("cgroup", "/sys/fs/cgroup/finger.slice/finger-sniffer.slice", "pasta dos cgroups das units")
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

// csvHeader é o cabeçalho do cgroup.csv (15 colunas desde a task 247; os brutos antigos têm 6, 10 ou 11).
const csvHeader = "t_ns,unit,cpu_usec,mem_current,anon,file,sock,kernel,slab,percpu,nr_throttled,shmem,memory_max,events_max,oom_kill"

// memoryMaxBytes lê o memory.max do cgroup: "max" (sem limite) ou ausente dá 0.
func memoryMaxBytes(text string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// cgroupLine monta a linha do cgroup.csv do cgroup em dir, com o nome name, no instante now.
func cgroupLine(now int64, name, dir string) string {
	cs := loadstat.ParseKV(readFile(filepath.Join(dir, "cpu.stat")))
	cur, _ := strconv.ParseInt(strings.TrimSpace(readFile(filepath.Join(dir, "memory.current"))), 10, 64)
	ms := loadstat.ParseKV(readFile(filepath.Join(dir, "memory.stat")))
	ev := loadstat.ParseKV(readFile(filepath.Join(dir, "memory.events")))
	return fmt.Sprintf("%d,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d", now, name, cs["usage_usec"], cur, ms["anon"], ms["file"],
		ms["sock"], ms["kernel"], ms["slab"], ms["percpu"], cs["nr_throttled"], ms["shmem"],
		memoryMaxBytes(readFile(filepath.Join(dir, "memory.max"))), ev["max"], ev["oom_kill"])
}

// sample grava, por intervalo, uma linha por unit, uma da fatia ("slice", o próprio root) e uma do host, no
// formato de csvHeader; a linha "host" leva busy/total/steal do /proc/stat em jiffies nas colunas
// cpu_usec/mem_current/anon e o número de núcleos na coluna file.
func sample(out string, interval time.Duration, root string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	f, err := os.Create(out) //nolint:gosec // caminho do operador
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // fechado no fim
	w := bufio.NewWriter(f)
	_, _ = fmt.Fprintln(w, csvHeader)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		now := time.Now().UnixNano()
		for _, u := range units {
			_, _ = fmt.Fprintln(w, cgroupLine(now, u, filepath.Join(root, "finger-sniffer-"+u+".service")))
		}
		_, _ = fmt.Fprintln(w, cgroupLine(now, "slice", root))
		ps := readFile("/proc/stat")
		if busy, total, steal, err := loadstat.ProcStatCPU(ps); err == nil {
			_, _ = fmt.Fprintf(w, "%d,host,%d,%d,%d,%d,0,0,0,0,0,0,0,0,0\n", now, busy, total, steal, loadstat.ProcStatNCPU(ps))
		}
		_ = w.Flush()
		select {
		case <-ctx.Done():
			return w.Flush()
		case <-tick.C:
		}
	}
}
