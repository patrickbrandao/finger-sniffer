// Package rules é o motor de regras do veredito (spec 018 RF-05 e RF-06, ADR 0049): função pura sobre uma entrada
// já montada, sem servidor, banco nem rede. As consultas às listas entram como interfaces (Sources).
//
// Dados pessoais (ADR 0049 item 5, ADR 0052): a entrada só tem os campos que a spec 018 lista; não há corpo, query,
// caminho, valor de cookie nem de Authorization, e nenhum `detail` de sinal leva IP ou o User-Agent inteiro.
package rules

import "net/netip"

// RulesVersion é a versão das regras (ADR 0049 item 6: mudança de regra muda a versão e regrava os goldens).
const RulesVersion = "v1.0"

// Input é o que as regras leem. Cada parte é opcional (nil quando a visão não tinha aquela camada).
type Input struct {
	// IP de origem, só para as listas de IP e a verificação de robô; nunca vai para o `detail`.
	IP       netip.Addr
	TCP      *TCP
	TLS      *TLS
	H2       *H2
	HTTP     *HTTP
	Behavior *Behavior
	// View diz o que havia para decidir (montada por quem chama; `human` exige TLS e HTTP).
	View View
}

// TCP é a visão do store (spec 013).
type TCP struct {
	// P0fOS é o `os` do p0f (ex. "Linux 3.11 and newer", "Mac OS X", "Windows 7 or 8"); "" ou "???" sem palpite.
	P0fOS string
	// TTLInitial é o TTL inicial estimado (0 = desconhecido).
	TTLInitial int
	JA4T       string
	// MSSReduction é `tcp.mss_reduction` (nil = desconhecido).
	MSSReduction *int
	// MTUImplied é `tcp.mtu_implied` (nil = desconhecido).
	MTUImplied *int
}

// TLS é o ClientHello visto (fork ou espelho).
type TLS struct {
	JA4  string
	JA4R string
	// ALPN oferecido no ClientHello, na ordem.
	ALPN []string
}

// H2 é o prefixo h2 visto.
type H2 struct {
	Akamai string
}

// HTTP é o resumo da requisição (ADR 0056 item 3), sem caminho, query, corpo nem valores de campo sensíveis.
type HTTP struct {
	UserAgent string
	// Version é a versão HTTP ("1.0", "1.1", "2", "3").
	Version string
	// JA4H completo ou só as partes a e b; a regra usa as partes a e b.
	JA4H string
	// FieldOrder são os nomes de campo na ordem recebida. A v1 compara a ordem pela parte b do JA4H (hash dessa
	// ordem), que é o que a base própria guarda.
	FieldOrder        []string
	HasAcceptLanguage bool
}

// Behavior são as estatísticas por IP + site (spec 018 RF-09; agregados da ADR 0052).
type Behavior struct {
	// RequestsPerMin é a taxa de requisições do IP no site no último minuto.
	RequestsPerMin int
	// RequestsHour e ConnsHour contam requisições e conexões na última hora.
	RequestsHour int
	ConnsHour    int
	// Intervalos entre requisições: n, soma e soma dos quadrados (segundos).
	IntervalN     int
	IntervalSum   float64
	IntervalSqSum float64
	// PathsHour são os caminhos distintos na hora (contados por hash) e StaticsHour quantos deles são estáticos.
	PathsHour   int
	StaticsHour int
}

// View é o que havia para decidir (schema View do openapi do bot).
type View struct {
	TCP        bool `json:"tcp"`
	TLS        bool `json:"tls"`
	HTTP       bool `json:"http"`
	H2         bool `json:"h2"`
	H3         bool `json:"h3"`
	Behavior   bool `json:"behavior"`
	ParseError bool `json:"parse_error,omitempty"`
}
