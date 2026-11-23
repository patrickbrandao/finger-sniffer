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
