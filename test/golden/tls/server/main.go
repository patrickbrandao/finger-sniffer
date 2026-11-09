//go:build golden

// Servidor TLS + h2 temporário usado por test/golden/tls/collect.sh (task 036). Roda na vps602 numa porta
// capturada livre, grava as chaves de sessão (formato NSS SSLKEYLOGFILE) para o tshark e o ja4 decifrarem o
// pcap, e anuncia h2 e http/1.1 por ALPN. Não faz parte de nenhum serviço: é compilado só com a tag golden.
//
// Uso: fs-golden-tls-srv -addr :7702 -cert c.pem -key k.pem -keylog caso.keys
package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", ":7702", "endereço de escuta")
	cert := flag.String("cert", "cert.pem", "certificado PEM")
	key := flag.String("key", "key.pem", "chave PEM")
	keylog := flag.String("keylog", "", "arquivo de chaves TLS (SSLKEYLOGFILE)")
	flag.Parse()

	kp, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{kp}, NextProtos: []string{"h2", "http/1.1"}}
	if *keylog != "" {
		f, err := os.OpenFile(*keylog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		cfg.KeyLogWriter = f
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			// favicon e afins: resposta curta para o navegador não insistir
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := "<!doctype html><title>golden</title><p>golden HTTP/1</p>"
		if r.ProtoMajor == 2 {
			page = "<!doctype html><title>golden</title><p>golden HTTP/2</p>"
		}
		_, _ = io.WriteString(w, page)
	})
	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		TLSConfig:         cfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	// ServeTLS com TLSConfig próprio: o net/http configura o h2 sozinho porque NextProtos tem "h2"
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
