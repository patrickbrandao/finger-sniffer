package rules

import "net/netip"

// FPKind é o tipo de impressão da base própria.
type FPKind string

// Tipos de impressão da base própria (campos de `known_clients.json`, spec 018).
const (
	KindJA4    FPKind = "ja4"
	KindAkamai FPKind = "akamai"
	// KindJA4HAB são as partes a e b do JA4H (`ja4h_ab`, sem cookies).
	KindJA4HAB FPKind = "ja4h_ab"
	KindJA4T   FPKind = "ja4t"
)

// KnownClients é a base própria (`internal/bot/lists/known_clients.json`, ADR 0050 item 1). Implementação na
// task 278; o adaptador para estas interfaces é da task 282.
type KnownClients interface {
	// Families devolve as famílias de cliente (campo `client`) com ao menos uma medida com este valor.
	Families(kind FPKind, value string) []string
	// Measured diz se a família tem ao menos uma medida com valor não nulo desse tipo (sem medida, a regra não
	// conclui nada sobre a família).
	Measured(family string, kind FPKind) bool
	// Coherent devolve as famílias com uma mesma medida cujos ja4, akamai e ja4t são os dados; valor "" não é
	// comparado.
	Coherent(ja4, akamai, ja4t string) []string
}

// JA4DBLabel é o rótulo da ja4db para um JA4.
type JA4DBLabel struct {
	// Name é a aplicação ou biblioteca rotulada (ex. "python-requests").
	Name string
	// Kind é JA4DBBrowser, JA4DBLibrary, JA4DBTool ou JA4DBOther.
	Kind string
}

// Tipos de rótulo da ja4db.
const (
	JA4DBBrowser = "browser"
	JA4DBLibrary = "library"
	JA4DBTool    = "tool"
	JA4DBOther   = "other"
)

// JA4DB é a consulta à ja4db (ADR 0050 item 2). Desligada (ADR 0056 item 1) é nil em Sources: sem rótulo, sem
// `ja4db_match`.
type JA4DB interface {
	Label(ja4 string) (JA4DBLabel, bool)
}

// IPLists são as listas de IP (ADR 0050 item 3).
type IPLists interface {
	// Cloud devolve o provedor (ex. "aws") quando o IP está numa faixa de nuvem ou datacenter.
	Cloud(ip netip.Addr) (provider string, ok bool)
	// Crawler devolve o operador do robô (OperatorGoogle...) quando o IP está numa lista de robô.
	Crawler(ip netip.Addr) (operator string, ok bool)
}

// Verification é o resultado da verificação de robô por DNS reverso/direto.
type Verification int

// Resultados da verificação (ADR 0050 item 4).
const (
	VerifyUnknown Verification = iota
	VerifyPassed
	VerifyFailed
)

// String devolve o nome do resultado.
func (v Verification) String() string {
	switch v {
	case VerifyPassed:
		return "passed"
	case VerifyFailed:
		return "failed"
	}
	return "unknown"
}

// CrawlerVerifier devolve o resultado já pronto (em cache) da verificação do IP para o operador. A regra nunca faz
// DNS: quem implementa devolve VerifyUnknown e verifica em segundo plano.
type CrawlerVerifier interface {
	Verified(ip netip.Addr, operator string) Verification
}

// Sources são as consultas usadas pelas regras; qualquer uma pode ser nil (sem aquela informação).
type Sources struct {
	Known    KnownClients
	JA4DB    JA4DB
	IPs      IPLists
	Verifier CrawlerVerifier
}
