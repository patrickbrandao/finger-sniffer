//go:build golden

// Cliente Go com quic-go/http3 usado por test/golden/quic/collect.sh (task 050). Configuração padrão da pilha:
// só a raiz de confiança muda. Força IPv4, porque o IP de origem anonimizado nos pcaps é o IPv4 do Mac.
// Uso: go run -tags golden ./goclient [-ca cert.pem] <url>
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	ca := flag.String("ca", "", "certificado PEM aceito como raiz")
	flag.Parse()

	var pool *x509.CertPool
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pool = x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
	}

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			ua, err := net.ResolveUDPAddr("udp4", addr)
			if err != nil {
				return nil, err
			}
			pc, err := net.ListenUDP("udp4", nil)
			if err != nil {
				return nil, err
			}
			return quic.DialEarly(ctx, pc, ua, tlsCfg, cfg)
		},
	}
	defer func() { _ = tr.Close() }()

	c := &http.Client{Timeout: 20 * time.Second, Transport: tr}
	resp, err := c.Get(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	fmt.Println(resp.Proto, resp.StatusCode, n)
}
