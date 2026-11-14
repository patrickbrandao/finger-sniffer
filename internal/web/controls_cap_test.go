package web

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// invalidKeysQuery monta uma query com n chaves distintas de percent-encoding inválido ("k000001%&...").
func invalidKeysQuery(n int) string {
	var b strings.Builder
	for i := range n {
		if i > 0 {
			b.WriteByte('&')
		}
		fmt.Fprintf(&b, "k%06d%%", i)
	}
	return b.String()
}

// TestParseControlsInvalidCap: chaves inválidas distintas e valores inválidos repetidos não fazem invalid
// nem o corpo do 400 crescerem com a query (task 130).
func TestParseControlsInvalidCap(t *testing.T) {
	for name, q := range map[string]string{
		"distinct keys":   invalidKeysQuery(200_000),
		"repeated status": strings.Repeat("status=x&", 200_000),
	} {
		c := ParseControls(q, testLimits)
		if c.Valid() {
			t.Fatalf("%s: valid", name)
		}
		if len(c.Record.Invalid) > recordMaxInvalid || len(c.errs) > recordMaxInvalid {
			t.Fatalf("%s: invalid %d errs %d", name, len(c.Record.Invalid), len(c.errs))
		}
		if n := len(c.InvalidText()); n > recordMaxInvalid*(2*recordMaxValueLen+64) {
			t.Fatalf("%s: text %d bytes", name, n)
		}
	}
	// Nome e valor enormes também são cortados na linha do 400.
	c := ParseControls(strings.Repeat("a", 5000)+"%="+strings.Repeat("b", 5000), testLimits)
	if c.Valid() || len(c.Record.Invalid[0]) != recordMaxValueLen || len(c.InvalidText()) > 2*recordMaxValueLen+64 {
		t.Fatalf("clip: %d %d", len(c.Record.Invalid[0]), len(c.InvalidText()))
	}
}

// TestInvalidKeysRequest: GET /r com ~300 KiB de chaves inválidas → 400 pequeno e o evento publicado
// dentro do teto (task 130).
//
// A ociosidade do servidor sobe de 3 s para 30 s: ela não é o que se testa aqui e, com -race e a suíte inteira
// disputando a CPU no CI, ler 300 KiB pelo tap (eventos stream.bytes), analisar ~34 mil chaves e publicar o
// evento chegou a passar de 3 s (task 214). O custo linear da análise continua coberto pelo
// TestParseControlsInvalidCap (200 mil chaves) e pelo BenchmarkParseControlsInvalidKeys.
func TestInvalidKeysRequest(t *testing.T) {
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.IdleDefault, c.IdleMax = 30*time.Second, 60*time.Second }})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	q := invalidKeysQuery(300 << 10 / 9)
	cl.send(get("/r?"+q, "x"))
	resp, body := cl.response("GET")
	if resp.StatusCode != 400 || len(body) > 8<<10 {
		t.Fatalf("status %d body %d bytes", resp.StatusCode, len(body))
	}
	e := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0]
	ctl, _ := e.Payload["controls"].(map[string]any)
	inv, _ := ctl["invalid"].([]any)
	if e.Size > event.MaxEventBytes || len(inv) == 0 || len(inv) > recordMaxInvalid {
		t.Fatalf("event %d bytes, invalid %d", e.Size, len(inv))
	}
}

// BenchmarkParseControlsInvalidKeys: o custo cresce linearmente com o número de chaves inválidas.
func BenchmarkParseControlsInvalidKeys(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		q := invalidKeysQuery(n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.SetBytes(int64(len(q)))
			for b.Loop() {
				ParseControls(q, testLimits)
			}
		})
	}
}
