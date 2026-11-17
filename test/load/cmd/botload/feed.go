//go:build load

package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// feedEvent é o LiveEvent do store (só os campos usados).
type feedEvent struct {
	Kind    string    `json:"kind"`
	TS      time.Time `json:"ts"`
	Dropped int       `json:"dropped"`
	Data    struct {
		Proto string `json:"proto"`
	} `json:"data"`
}

// feedSample converte um evento do feed global do store numa amostra: atraso ts → chegada; flag 1 no
// connection.updated do raw (ts = accept da sessão, excluído como no loadgen).
func feedSample(d []byte, now time.Time) (sample, bool) {
	var ev feedEvent
	if json.Unmarshal(d, &ev) != nil || ev.Kind == "" {
		return sample{}, false
	}
	if ev.Kind == "stream.dropped" {
		return sample{t: now.UnixNano(), kind: "store_feed_dropped", flag: ev.Dropped}, true
	}
	if ev.TS.IsZero() {
		return sample{}, false
	}
	flag := 0
	if ev.Kind == "connection.updated" && strings.HasPrefix(ev.Data.Proto, "raw") {
		flag = 1
	}
	return sample{t: ev.TS.UnixNano(), kind: "store_feed", latUS: now.Sub(ev.TS).Microseconds(), status: 200, flag: flag}, true
}

// feedCmd lê o feed global do store (/api/v1/stream, sem filtros) de dentro do finger-01 e mede o atraso de cada
// evento: separa o caminho do espelho do enlace do gerador no Mac (ADR 0046, "falhas do lado do cliente").
func feedCmd(args []string) error {
	fs := flag.NewFlagSet("feed", flag.ContinueOnError)
	store := fs.String("store", "http://170.247.40.86:9001/api/v1", "base da API do store")
	duration := fs.Duration("duration", 30*time.Minute, "duração")
	out := fs.String("out", "/out", "pasta dos resultados")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		return err
	}
	rec, err := newRecorder(filepath.Join(*out, "feed_samples.csv"))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()
	log.Printf("feed: %s/stream por %v (início %s)", *store, *duration, ts(time.Now()))
	var n, drops atomic.Int64
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Printf("feed 10s: eventos %d, stream.dropped %d", n.Load(), drops.Load())
			}
		}
	}()
	readSSE(ctx, sseClient(), *store+"/stream", "", func(d []byte) {
		if s, ok := feedSample(d, time.Now()); ok {
			if s.kind == "store_feed_dropped" {
				drops.Add(1)
			} else {
				n.Add(1)
			}
			rec.add(s)
		}
	}, log.Printf)
	lost := rec.close()
	log.Printf("feed fim: eventos %d, stream.dropped %d, amostras perdidas %d", n.Load(), drops.Load(), lost)
	return nil
}
