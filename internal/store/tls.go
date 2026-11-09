package store

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// certJSON é um item de host.certificates do health.
type certJSON struct {
	Names      []string `json:"names"`
	Issuer     string   `json:"issuer"`
	NotAfter   string   `json:"not_after"`
	SelfSigned bool     `json:"self_signed"`
}

// certificatesJSON converte o estado dos certificados para o health (tempos no formato dos eventos).
func certificatesJSON(list []certs.CertInfo) []certJSON {
	out := make([]certJSON, 0, len(list))
	for _, c := range list {
		names := c.Names
		if names == nil {
			names = []string{}
		}
		out = append(out, certJSON{Names: names, Issuer: c.Issuer, NotAfter: event.FormatTime(c.NotAfter), SelfSigned: c.SelfSigned})
	}
	return out
}

// httpsTLSConfig é a configuração TLS da API na 9000: a mesma do espelho (pkg/certs), com escolha por SNI e
// recarga a quente, e ALPN h2/http1.1.
func httpsTLSConfig(cs *certs.Store) *tls.Config {
	c := cs.TLSConfig()
	c.NextProtos = []string{"h2", "http/1.1"}
	return c
}

// serveHTTPS atende a API em HTTPS (spec 004 RF-07) até ctx terminar. /metrics fica só na 9001.
func (s *Store) serveHTTPS(ctx context.Context, api *API) (*http.Server, <-chan error, error) {
	srv := &http.Server{
		Handler: api.HTTPSHandler(), TLSConfig: httpsTLSConfig(s.certs),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	addrs, err := s.cfg.apiAddrs(s.cfg.HTTPSAddr)
	if err != nil {
		return nil, nil, err
	}
	ls, err := listenAll(addrs)
	if err != nil {
		return nil, nil, err
	}
	// Certificados vêm do GetCertificate; os argumentos ficam vazios.
	errc := serveAll(ls, func(l net.Listener) error { return srv.ServeTLS(l, "", "") })
	s.svc.Log.Info("api listening (https)", "addr", addrsString(ls))
	return srv, errc, nil
}
