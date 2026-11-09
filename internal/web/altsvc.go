package web

import (
	"net/url"
	"slices"
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

// addAltSvc põe o Alt-Svc no cabeçalho HTTP/1 quando o anúncio vale: depois dos campos padrão e antes
// dos de h= (spec 005 RF-04); sem h=, no fim. O Date entra depois, como primeiro campo (ADR 0021).
func (c *conn) addAltSvc(r *response, rawQuery string) {
	c.mu.Lock()
	tlsOn := c.tlsOn
	c.mu.Unlock()
	if r.head == nil || !c.srv.altSvcOn(tlsOn, rawQuery) {
		return
	}
	alt := h1.HeaderField{Name: "Alt-Svc", Value: altSvcH3}
	at := r.userAt
	if at <= 0 || at > len(r.head.Fields) {
		r.head.Fields = append(r.head.Fields, alt)
		return
	}
	r.head.Fields = slices.Insert(r.head.Fields, at, alt)
}
