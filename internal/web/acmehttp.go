package web

import (
	"crypto/tls"
	"slices"
	"strings"

	"github.com/caddyserver/certmagic"
)

// challengeTypeHTTP01 é o tipo do desafio HTTP-01 (RFC 8555 §8.3).
const challengeTypeHTTP01 = "http-01"

// HTTPChallenge é o adaptador entre a rota /.well-known/acme-challenge/<token> do nosso servidor HTTP/1 e o
// solver HTTP-01 do certmagic (spec 015 RF-03). O certmagic guarda em memória o desafio ativo de cada nome
// enquanto a validação corre; aqui procuramos, entre os nomes do certificado B, o desafio HTTP-01 com esse
// token e devolvemos a key authorization. Token desconhecido, de outro tipo ou com caractere fora do base64url
// = 404 (RFC 8555 §8.3 manda validar a sintaxe antes de responder).
func (m *ACMEManager) HTTPChallenge(token string) ([]byte, bool) {
	if m == nil || !validToken(token) {
		return nil, false
	}
	for _, name := range m.cfg.NamesHTTP01 {
		chal, ok := certmagic.GetACMEChallenge(name)
		if !ok || chal.Type != challengeTypeHTTP01 || chal.Token != token {
			continue
		}
		if !strings.EqualFold(chal.Identifier.Value, name) || chal.KeyAuthorization == "" {
			continue
		}
		m.log.Info("acme http-01 served", "name", name)
		return []byte(chal.KeyAuthorization), true
	}
	return nil, false
}

// challengeTypeTLSALPN01 é o tipo do desafio TLS-ALPN-01 (RFC 8737) e acmeTLS1 o ALPN dele.
const (
	challengeTypeTLSALPN01 = "tls-alpn-01"
	acmeTLS1               = "acme-tls/1"
)

// isACMETLSHello diz se o ClientHello é o de uma validação TLS-ALPN-01: SNI e ALPN com só "acme-tls/1"
// (RFC 8737 §3: o servidor ACME oferece um único protocolo).
func isACMETLSHello(h *tls.ClientHelloInfo) bool {
	return h != nil && h.ServerName != "" && len(h.SupportedProtos) == 1 && h.SupportedProtos[0] == acmeTLS1
}

// TLSALPNChallenge devolve o certificado de desafio do TLS-ALPN-01 do certificado B (spec 015 RF-03, ADR 0038)
// quando o ClientHello é de validação, o nome é do B e há um desafio TLS-ALPN-01 ativo neste processo para ele.
// O web atende em qualquer porta TLS; o certmagic monta o certificado (extensão acmeIdentifier) a partir do
// desafio que ele mesmo guardou.
func (m *ACMEManager) TLSALPNChallenge(h *tls.ClientHelloInfo) (*tls.Certificate, bool) {
	if m == nil || !isACMETLSHello(h) {
		return nil, false
	}
	name := normalizeHost(h.ServerName)
	if !slices.Contains(m.cfg.NamesHTTP01, name) {
		return nil, false
	}
	chal, ok := certmagic.GetACMEChallenge(name)
	if !ok || chal.Type != challengeTypeTLSALPN01 {
		return nil, false
	}
	cert, err := m.cmCfg.GetCertificate(h)
	if err != nil || cert == nil {
		m.log.Warn("acme tls-alpn-01 certificate", "name", name, "err", err)
		return nil, false
	}
	m.log.Info("acme tls-alpn-01 served", "name", name)
	return cert, true
}

func normalizeHost(n string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
}

// validToken diz se o token só tem caracteres base64url (RFC 8555 §8.1) e um tamanho razoável.
func validToken(tok string) bool {
	if tok == "" || len(tok) > 256 {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
