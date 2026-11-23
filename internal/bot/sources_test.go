package bot

import (
	"slices"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/lists"
	"github.com/patrickbrandao/finger-sniffer/internal/bot/rules"
)

// A tabela de UA, robotOperator e o catálogo concordam (task 365): todo operador da tabela tem pelo menos uma lista
// good_bot no catálogo; o robô de operador provado só pela lista (OpenAI, DuckDuckGo) tem a lista do próprio
// marcador; toda lista good_bot tem operador em robotOperator. Sem isso, o robô real cai fora de toda lista do
// operador e sai `ua_claims_crawler`.
func TestCrawlerTableMatchesCatalog(t *testing.T) {
	var robots []string
	ops := map[string]bool{}
	for _, s := range lists.Catalog {
		if s.Kind != lists.KindGoodBot {
			continue
		}
		op := robotOperator[s.Robot]
		if op == "" {
			t.Errorf("lista %s: robô %q sem operador em robotOperator", s.Name, s.Robot)
		}
		robots = append(robots, s.Robot)
		ops[op] = true
	}
	for robot := range robotOperator {
		if !slices.Contains(robots, robot) {
			t.Errorf("robotOperator[%s] sem lista no catálogo", robot)
		}
	}
	for name, op := range rules.CrawlerOperators() {
		if op == "" {
			continue
		}
		if !ops[op] {
			t.Errorf("%s: operador %s sem lista no catálogo", name, op)
		}
		if rules.VerifiedByList(op) && !slices.Contains(robots, name) {
			t.Errorf("%s: operador %s é provado só pela lista, mas o catálogo não tem a lista de %s", name, op, name)
		}
	}
}

// TestKnownSourceStable: a base própria indexa o stable (derivado do ja4_r) e a parte b dos JA4 TCP, e o casamento
// pelo stable devolve a mesma família do JA4 completo (ADR 0072 item 1.4).
func TestKnownSourceStable(t *testing.T) {
	k, err := lists.LoadKnownClients()
	if err != nil {
		t.Fatal(err)
	}
	s := newKnownSource(k)
	for _, m := range k.Measured {
		if !slices.Contains(s.Families(rules.KindJA4Stable, m.JA4Stable), m.Client) || !s.Measured(m.Client, rules.KindJA4Stable) {
			t.Errorf("%s/%s: stable %q sem a família", m.Client, m.Proto, m.JA4Stable)
		}
		akamai, ja4t := "", ""
		if m.Akamai != nil {
			akamai = *m.Akamai
		}
		if m.JA4T != nil {
			ja4t = *m.JA4T
		}
		if !slices.Contains(s.Coherent(rules.KindJA4Stable, m.JA4Stable, akamai, ja4t), m.Client) ||
			!slices.Contains(s.Coherent(rules.KindJA4, m.JA4, akamai, ja4t), m.Client) {
			t.Errorf("%s/%s: Coherent pelo stable ou pelo JA4", m.Client, m.Proto)
		}
	}
	// parte b só de JA4 TCP: as cifras do Chrome e do Firefox medidos são as mesmas; o QUIC não entra
	if got := s.Families(rules.KindJA4Ciphers, "8daaf6152771"); !slices.Contains(got, "chrome") || !slices.Contains(got, "firefox") {
		t.Errorf("cifras do chrome: %v", got)
	}
	if got := s.Families(rules.KindJA4Ciphers, "55b375c5d22e"); len(got) != 0 {
		t.Errorf("parte b do QUIC indexada: %v", got)
	}
	if got := s.Coherent(rules.KindJA4Ciphers, "8daaf6152771", "", ""); got != nil {
		t.Errorf("Coherent por cifras: %v", got)
	}
}
