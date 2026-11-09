package certs

import (
	"bytes"
	"time"
)

// Motivos do heartbeat (spec 015 RF-05).
const (
	ReasonSelfSigned = "cert_self_signed"
	ReasonExpiring   = "cert_expiring"
)

// ExpiringWithin é a antecedência a partir da qual o certificado conta como expirando (spec 015 RF-05).
const ExpiringWithin = 14 * 24 * time.Hour

// CertInfo é um item de host.certificates do health (openapi).
type CertInfo struct {
	Names      []string  `json:"names"`
	Issuer     string    `json:"issuer"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
}

// State devolve o estado do certificado A (dns01) e do B (http01), nessa ordem. Quando os dois usam o mesmo
// autoassinado, ele aparece uma vez só.
func (s *Store) State() []CertInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []CertInfo
	var prev []byte
	for _, slot := range slots {
		e := s.entries[slot]
		if e == nil || e.cert == nil || e.cert.Leaf == nil {
			continue
		}
		raw := e.cert.Leaf.Raw
		if prev != nil && bytes.Equal(prev, raw) {
			continue
		}
		prev = raw
		leaf := e.cert.Leaf
		issuer := leaf.Issuer.CommonName
		if issuer == "" {
			issuer = leaf.Issuer.String()
		}
		out = append(out, CertInfo{
			Names:      append([]string(nil), leaf.DNSNames...),
			Issuer:     issuer,
			NotAfter:   leaf.NotAfter.UTC(),
			SelfSigned: e.selfSigned,
		})
	}
	return out
}

// Reasons devolve os motivos de degradação do heartbeat: cert_self_signed se algum certificado em uso é o
// autoassinado e cert_expiring se algum expira em menos de 14 dias. Vazio = ok.
func (s *Store) Reasons(now time.Time) []string {
	var selfSigned, expiring bool
	for _, c := range s.State() {
		if c.SelfSigned {
			selfSigned = true
		}
		if c.NotAfter.Sub(now) < ExpiringWithin {
			expiring = true
		}
	}
	var out []string
	if selfSigned {
		out = append(out, ReasonSelfSigned)
	}
	if expiring {
		out = append(out, ReasonExpiring)
	}
	return out
}
