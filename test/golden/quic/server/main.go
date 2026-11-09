//go:build golden

// Servidor HTTP/3 (quic-go) temporário usado por test/golden/quic/collect.sh (task 050). Roda na vps602 numa
// porta capturada livre, em UDP (h3) e em TCP (h2 e http/1.1 com Alt-Svc, para o Firefox descobrir o h3), e grava
// as chaves de sessão (formato NSS SSLKEYLOGFILE) para o tshark decifrar os pacotes Handshake e 1-RTT. O Initial
// não precisa das chaves: ele é decifrado com as chaves derivadas do DCID. Não faz parte de nenhum serviço: é
// compilado só com a tag golden.
//
// Uso: fs-golden-quic-srv -addr 172.233.24.85:7703 -cert c.pem -key k.pem -keylog caso.keys
package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	addr := flag.String("addr", ":7703", "endereço de escuta (UDP e TCP)")
	cert := flag.String("cert", "cert.pem", "certificado PEM")
	key := flag.String("key", "key.pem", "chave PEM")
	keylog := flag.String("keylog", "", "arquivo de chaves TLS (SSLKEYLOGFILE)")
	flag.Parse()

	kp, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{kp}}
	if *keylog != "" {
		f, err := os.OpenFile(*keylog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		cfg.KeyLogWriter = f
	}

	h3 := &http3.Server{
		Addr:      *addr,
		TLSConfig: http3.ConfigureTLSConfig(cfg.Clone()),
		// sem 0-RTT e sem Retry, como o servidor h3 do web (spec 011 RF-06)
		QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor < 3 {
			// h1/h2: anuncia o h3 na mesma porta
			_ = h3.SetQUICHeaders(w.Header())
		}
		if r.URL.Path != "/" {
			// favicon e afins: resposta curta para o navegador não insistir
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// a imagem gera uma segunda requisição, que o Firefox já pode mandar pelo h3 anunciado
		_, _ = io.WriteString(w, "<!doctype html><title>golden</title><p>golden "+r.Proto+"</p><img src=\"/i.png\">")
	})
	h3.Handler = mux

	tcpCfg := cfg.Clone()
	tcpCfg.NextProtos = []string{"h2", "http/1.1"}
	srv := &http.Server{Addr: *addr, Handler: mux, TLSConfig: tcpCfg, ReadHeaderTimeout: 10 * time.Second}
	go func() { log.Fatal(srv.ListenAndServeTLS("", "")) }()
	log.Fatal(h3.ListenAndServe())
}
