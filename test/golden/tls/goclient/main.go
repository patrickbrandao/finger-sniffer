//go:build golden

// Cliente Go (net/http + crypto/tls) usado por test/golden/tls/collect.sh (task 036).
// Uso: go run -tags golden ./goclient [-ca cert.pem] [-proto h2|h1] [-out arquivo] <url>
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
)

func main() {
	ca := flag.String("ca", "", "certificado PEM aceito como raiz")
	proto := flag.String("proto", "h2", "h2 ou h1")
	out := flag.String("out", "", "grava o corpo da resposta neste arquivo (vazio: descarta)")
	flag.Parse()

	// sem -ca: raízes do sistema (consulta ao tls.peet.ws)
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

	// a pilha padrão do net/http: só a raiz muda; o protocolo é escolhido pelo Transport.Protocols
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	// só IPv4: o IP de origem anonimizado nos pcaps é o IPv4 do Mac
	d := &net.Dialer{Timeout: 10 * time.Second}
	tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp4", addr)
	}
	p := new(http.Protocols)
	if *proto == "h1" {
		p.SetHTTP1(true)
	} else {
		p.SetHTTP2(true)
	}
	tr.Protocols = p

	c := &http.Client{Timeout: 20 * time.Second, Transport: tr}
	resp, err := c.Get(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	w := io.Discard
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	n, _ := io.Copy(w, resp.Body)
	_ = resp.Body.Close()
	fmt.Println(resp.Proto, resp.Status, n)
}
