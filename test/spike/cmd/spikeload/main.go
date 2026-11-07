//go:build spike

// Comando spikeload: gerador de carga do spike (task 006). Abre `rate` conexões novas por segundo; cada
// conexão faz `reqs` requisições keep-alive espaçadas de `interval` e fecha. Concorrência ≈ rate × reqs × interval.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	target := flag.String("target", "http://vps602.tmsoft.com.br:8080", "URL base")
	rate := flag.Int("rate", 50, "conexões novas por segundo")
	reqs := flag.Int("reqs", 4, "requisições por conexão")
	interval := flag.Duration("interval", time.Second, "intervalo entre requisições")
	bigRatio := flag.Float64("big-ratio", 0.1, "fração das conexões que baixam /big")
	duration := flag.Duration("duration", 10*time.Minute, "duração")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()

	var active, maxActive, opened, okReqs, errReqs atomic.Int64
	var mu sync.Mutex
	var lat []float64
	var wg sync.WaitGroup

	run := func() {
		defer wg.Done()
		n := active.Add(1)
		for {
			m := maxActive.Load()
			if n <= m || maxActive.CompareAndSwap(m, n) {
				break
			}
		}
		defer active.Add(-1)
		opened.Add(1)
		tr := &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			MaxConnsPerHost:     1,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     30 * time.Second,
		}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
		big := rand.Float64() < *bigRatio //nolint:gosec // sorteio da carga, não criptografia
		for i := 0; i < *reqs; i++ {
			path := "/small"
			if big && i == 0 {
				path = "/big"
			}
			t0 := time.Now()
			resp, err := client.Get(*target + path)
			if err == nil {
				_, err = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			if err != nil {
				errReqs.Add(1)
			} else {
				okReqs.Add(1)
				mu.Lock()
				lat = append(lat, float64(time.Since(t0).Microseconds())/1000)
				mu.Unlock()
			}
			if i < *reqs-1 {
				time.Sleep(*interval)
			}
		}
	}

	tick := time.NewTicker(time.Second / time.Duration(*rate))
	defer tick.Stop()
	report := time.NewTicker(5 * time.Second)
	defer report.Stop()
	start := time.Now()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-tick.C:
			wg.Add(1)
			go run()
		case <-report.C:
			out, _ := json.Marshal(map[string]any{
				"t": time.Since(start).Seconds(), "active": active.Load(), "opened": opened.Load(),
				"ok": okReqs.Load(), "errors": errReqs.Load(),
			})
			fmt.Println(string(out))
		}
	}
	wg.Wait()
	sort.Float64s(lat)
	p := func(q float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return lat[min(len(lat)-1, int(q*float64(len(lat))))]
	}
	out, _ := json.Marshal(map[string]any{
		"summary": true, "seconds": time.Since(start).Seconds(), "opened": opened.Load(), "max_active": maxActive.Load(),
		"ok": okReqs.Load(), "errors": errReqs.Load(), "req_ms_p50": p(0.5), "req_ms_p95": p(0.95), "req_ms_p99": p(0.99),
	})
	fmt.Println(string(out))
}
