//go:build spike

// Comando spikeweb: servidor HTTP alvo do spike (task 006). /small = 1 KiB, /big = 256 KiB.
package main

import (
	"bytes"
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", ":8080", "endereço")
	flag.Parse()
	small := bytes.Repeat([]byte("s"), 1024)
	big := bytes.Repeat([]byte("b"), 256<<10)
	mux := http.NewServeMux()
	mux.HandleFunc("/small", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(small) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(big) })
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
