package h1

import (
	"errors"
	"net"
	"strings"
)

// Tipos de sinal que não vêm de um campo pelo nome (RF-07).
const (
	SignalAbsoluteFormDirect = "absolute-form-direct"
	SignalHostSNIMismatch    = "host-sni-mismatch"
)

// ProxyRule casa um campo pelo nome, sem caixa. Com Prefix, casa todo campo que começa com Name.
type ProxyRule struct {
	Name   string
	Prefix bool
}

// DefaultProxyRules é a lista padrão de campos que indicam proxy no caminho (spec 009 RF-07).
var DefaultProxyRules = MustParseProxyRules("Via,Forwarded,X-Forwarded-For,X-Forwarded-Host," +
	"X-Forwarded-Proto,X-Forwarded-Port,X-Forwarded-Server,X-Real-IP,Client-IP,True-Client-IP,X-Client-IP," +
	"X-Cache*,X-Squid*,Proxy-Connection,Proxy-Authorization,Surrogate-Capability,Cache-Control,Pragma," +
	"X-BlueCoat-Via,X-Proxy-*,X-xproxy-*,Max-Forwards")

// ErrBadProxyRule indica item vazio na lista de regras.
var ErrBadProxyRule = errors.New("h1: empty proxy rule")

// ParseProxyRules lê uma lista separada por vírgulas ("Via,X-Cache*,..."); "*" no fim marca prefixo.
func ParseProxyRules(list string) ([]ProxyRule, error) {
	var rules []ProxyRule
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		prefix := strings.HasSuffix(item, "*")
		item = strings.TrimSuffix(item, "*")
		if item == "" {
			return nil, ErrBadProxyRule
		}
		rules = append(rules, ProxyRule{Name: item, Prefix: prefix})
	}
	return rules, nil
}

// MustParseProxyRules é ParseProxyRules que entra em pânico em erro (para listas fixas no código).
func MustParseProxyRules(list string) []ProxyRule {
	rules, err := ParseProxyRules(list)
	if err != nil {
		panic(err)
	}
	return rules
}

func (p ProxyRule) match(name string) bool {
	if p.Prefix {
		return len(name) >= len(p.Name) && strings.EqualFold(name[:len(p.Name)], p.Name)
	}
	return strings.EqualFold(name, p.Name)
}

// ProxyContext é o que o servidor sabe da conexão para avaliar os sinais.
type ProxyContext struct {
	// Rules é a lista de campos; nil usa DefaultProxyRules.
	Rules []ProxyRule
	// Direct indica conexão direta ao servidor de origem (não pela porta de proxy): nela absolute-form
	// só aparece se um proxy reescreveu a requisição.
	Direct bool
	// SNI é o server_name do ClientHello ("" em texto claro ou sem SNI).
	SNI string
}

// maxSignalDetail limita o valor copiado para o detalhe de cada sinal.
const maxSignalDetail = 256

// DetectProxySignals devolve os sinais de proxy da requisição (RF-07), na ordem dos campos. O valor de
// Proxy-Authorization não é copiado (só o esquema): a credencial vazada fica apenas nos bytes crus.
func DetectProxySignals(req *Request, ctx ProxyContext) []ProxySignal {
	rules := ctx.Rules
	if rules == nil {
		rules = DefaultProxyRules
	}
	out := []ProxySignal{}
	for _, f := range req.Fields {
		for _, rule := range rules {
			if !rule.match(f[0]) {
				continue
			}
			name := f[0]
			kind := strings.ToLower(name)
			detail := strings.Trim(f[2], " \t")
			if kind == "proxy-authorization" {
				scheme, _, _ := strings.Cut(detail, " ")
				detail = "credential leaked; scheme=" + scheme
			}
			if len(detail) > maxSignalDetail {
				detail = detail[:maxSignalDetail]
			}
			out = append(out, ProxySignal{Kind: kind, Field: &name, Detail: &detail})
			break
		}
	}
	if ctx.Direct && req.RequestLine.Form == FormAbsolute {
		d := req.RequestLine.Target
		if len(d) > maxSignalDetail {
			d = d[:maxSignalDetail]
		}
		out = append(out, ProxySignal{Kind: SignalAbsoluteFormDirect, Detail: &d})
	}
	if ctx.SNI != "" {
		if host, ok := req.Get("Host"); ok && !strings.EqualFold(hostOnly(host), hostOnly(ctx.SNI)) {
			name := "Host"
			d := "host=" + host + " sni=" + ctx.SNI
			if len(d) > maxSignalDetail {
				d = d[:maxSignalDetail]
			}
			out = append(out, ProxySignal{Kind: SignalHostSNIMismatch, Field: &name, Detail: &d})
		}
	}
	return out
}

// hostOnly tira a porta, os colchetes do IPv6 e o ponto final de um host.
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return strings.TrimSuffix(h, ".")
}
