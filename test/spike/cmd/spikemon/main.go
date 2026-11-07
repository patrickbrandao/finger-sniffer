//go:build spike && linux

// Comando spikemon: CPU (% de 1 vCPU) e RSS por processo, a partir de /proc, a cada intervalo (task 006).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const clkTck = 100.0 // USER_HZ no Linux x86_64

type sample struct {
	ticks float64
	rss   int64
}

func main() {
	names := flag.String("procs", "spikecap,nats-server,spikestore,spikeweb", "nomes (comm) dos processos")
	every := flag.Duration("every", 5*time.Second, "intervalo")
	flag.Parse()
	want := strings.Split(*names, ",")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	prev, prevTotal, prevIdle := read(want), 0.0, 0.0
	prevTotal, prevIdle = cpuTotals()
	type agg struct {
		sumCPU, maxCPU float64
		maxRSS         int64
		n              int
	}
	sum := map[string]*agg{}
	var sysSum, sysMax float64
	var sysN int
	t := time.NewTicker(*every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			out := map[string]any{"summary": true, "system_cpu_avg": sysSum / float64(max(sysN, 1)), "system_cpu_max": sysMax}
			for k, a := range sum {
				out[k] = map[string]any{"cpu_avg": a.sumCPU / float64(max(a.n, 1)), "cpu_max": a.maxCPU, "rss_max_mib": float64(a.maxRSS) / (1 << 20)}
			}
			b, _ := json.Marshal(out)
			fmt.Println(string(b))
			return
		case <-t.C:
		}
		cur := read(want)
		total, idle := cpuTotals()
		dt := every.Seconds()
		line := map[string]any{"ts": time.Now().UTC().Format(time.RFC3339)}
		if total > prevTotal {
			sys := 100 * (1 - (idle-prevIdle)/(total-prevTotal))
			line["system_cpu"] = sys
			sysSum += sys
			sysMax = max(sysMax, sys)
			sysN++
		}
		for name, s := range cur {
			cpu := 0.0
			if p, ok := prev[name]; ok {
				cpu = 100 * (s.ticks - p.ticks) / clkTck / dt
			}
			line[name] = map[string]any{"cpu": cpu, "rss_mib": float64(s.rss) / (1 << 20)}
			a := sum[name]
			if a == nil {
				a = &agg{}
				sum[name] = a
			}
			a.sumCPU += cpu
			a.maxCPU = max(a.maxCPU, cpu)
			a.maxRSS = max(a.maxRSS, s.rss)
			a.n++
		}
		b, _ := json.Marshal(line)
		fmt.Println(string(b))
		prev, prevTotal, prevIdle = cur, total, idle
	}
}

// read soma utime+stime e RSS dos processos cujo comm está em want.
func read(want []string) map[string]sample {
	out := map[string]sample{}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		comm, err := os.ReadFile(d + "/comm") //nolint:gosec // caminho em /proc
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		match := false
		for _, w := range want {
			if name == w {
				match = true
			}
		}
		if !match {
			continue
		}
		stat, err := os.ReadFile(d + "/stat") //nolint:gosec // caminho em /proc
		if err != nil {
			continue
		}
		f := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+2:]))
		if len(f) < 22 {
			continue
		}
		ut, _ := strconv.ParseFloat(f[11], 64)
		st, _ := strconv.ParseFloat(f[12], 64)
		rssPages, _ := strconv.ParseInt(f[21], 10, 64)
		s := out[name]
		s.ticks += ut + st
		s.rss += rssPages * int64(os.Getpagesize())
		out[name] = s
	}
	return out
}

// cpuTotals devolve (total, idle+iowait) de /proc/stat.
func cpuTotals() (float64, float64) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	var total, idle float64
	for i, v := range f[1:] {
		x, _ := strconv.ParseFloat(v, 64)
		total += x
		if i == 3 || i == 4 {
			idle += x
		}
	}
	return total, idle
}
