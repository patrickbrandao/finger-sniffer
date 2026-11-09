package web

import (
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
