package web

import (
	"net/url"
	"strings"

	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
)

// altSvcOn decide o anúncio do h3 numa resposta h1/h2 (spec 005 RF-04, spec 011 RF-05): só em conexão
// TLS, com o listener UDP 443 de pé e sem alt_svc=0 na query (vale para qualquer rota, htdocs inclusive).
func (s *Server) altSvcOn(tlsOn bool, rawQuery string) bool {
	return tlsOn && !noAltSvc(rawQuery) && s.h3Active()
}

// noAltSvc informa se a query pede alt_svc=0 (o último valor vale, como nos controles).
func noAltSvc(rawQuery string) bool {
	off := false
	for part := range strings.SplitSeq(rawQuery, "&") {
		k, v, _ := strings.Cut(part, "=")
		if k, err := url.QueryUnescape(k); err != nil || k != "alt_svc" {
			continue
		}
		v, _ = url.QueryUnescape(v)
		off = v == "0"
	}
	return off
}

// addAltSvc acrescenta o Alt-Svc ao cabeçalho HTTP/1 quando o anúncio vale.
func (c *conn) addAltSvc(head *h1.Response, rawQuery string) {
	c.mu.Lock()
	tlsOn := c.tlsOn
	c.mu.Unlock()
	if head != nil && c.srv.altSvcOn(tlsOn, rawQuery) {
		head.Fields = append(head.Fields, h1.HeaderField{Name: "Alt-Svc", Value: altSvcH3})
	}
}
