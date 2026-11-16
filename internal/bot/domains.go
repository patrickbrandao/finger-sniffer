package bot

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// NormalizeDomains confere e normaliza os domínios de uma chave (ADR 0051 item 3): `example.com` ou
// `*.example.com`, em minúsculas, sem ponto final, sem repetição.
func NormalizeDomains(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" {
			continue
		}
		host := strings.TrimPrefix(d, "*.")
		if !validHostname(host) {
			return nil, fmt.Errorf("bot: invalid domain %q", d)
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("bot: at least one domain is required")
	}
	return out, nil
}

// validHostname aceita rótulos DNS com letras, dígitos e hífen, com ao menos um ponto.
func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// NormalizeSite tira porta, ponto final e maiúsculas de um Host/SNI.
func NormalizeSite(s string) string {
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	return strings.TrimSuffix(strings.ToLower(s), ".")
}

// MatchDomain diz se o site casa com algum domínio: `example.com` casa só com ele; `*.example.com` casa com
// qualquer subdomínio (um ou mais rótulos), não com o próprio `example.com`.
func MatchDomain(domains []string, site string) bool {
	site = NormalizeSite(site)
	if site == "" {
		return false
	}
	for _, d := range domains {
		if suffix, ok := strings.CutPrefix(d, "*"); ok {
			if strings.HasSuffix(site, suffix) && len(site) > len(suffix) {
				return true
			}
			continue
		}
		if site == d {
			return true
		}
	}
	return false
}
