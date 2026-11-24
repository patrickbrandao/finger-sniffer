package raw

import (
	"bytes"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// waitFor espera cond ficar verdadeira em até 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timeout: %s", what)
}

// TestSessionPanicRecovered: um pânico no meio da sessão fecha só ela, conta em raw_panics_total, devolve as
// reservas e o servidor segue atendendo (spec 006 RF-07b, ADR 0070 item 6).
func TestSessionPanicRecovered(t *testing.T) {
	testHook = func(data []byte) {
		if bytes.Contains(data, []byte("BOOM")) {
			panic("teste")
		}
	}
	t.Cleanup(func() { testHook = nil })
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo"}}, withTLS(t))

	// Sessão TLS: a reserva do ClientHello acontece antes e precisa ter voltado.
	c := dialTLS(t, env.addr[0], "", nil)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("BOOM\n")); err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(c)
	waitFor(t, "raw_panics_total = 1", func() bool { return env.srv.metrics.Get(MetricPanics) == 1 })
	waitFor(t, "orçamento devolvido", func() bool { return env.srv.budget.inUse() == 0 })

	c2 := dial(t, env.addr[0])
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c2.Write([]byte("ok\n")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, c2, 3); got != "ok\n" {
		t.Fatalf("eco depois do pânico = %q", got)
	}
}

// TestClientHelloWithoutBudget: sem orçamento para a captura do ClientHello, a sessão fecha antes do handshake
// e conta em raw_input_budget_denied_total (spec 006 RF-07b).
func TestClientHelloWithoutBudget(t *testing.T) {
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo"}}, func(c *Config) {
		withTLS(t)(c)
		c.inputBudget = helloReserve - 1
	})
	raw := dial(t, env.addr[0])
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.Handshake(); err == nil {
		t.Fatal("handshake completou sem orçamento")
	}
	waitFor(t, "recusa contada", func() bool { return env.srv.metrics.Get(MetricInputBudgetDenied) == 1 })
	if got := env.srv.budget.inUse(); got != 0 {
		t.Fatalf("orçamento em uso = %d", got)
	}
}

// TestTimedListsCutWithoutBudget: sem orçamento, reads_in para nas entradas fixas com reads_in_truncated, sem
// contar recusa (dado só de análise, ADR 0070 item 2).
func TestTimedListsCutWithoutBudget(t *testing.T) {
	b := newInputBudget(0, service.NewMetrics())
	s := &session{hold: &hold{b: b}}
	var l []TimedLength
	cut := false
	for range fixedTimed + 10 {
		l = s.appendTimed(l, &cut, 1, 1)
	}
	if len(l) != fixedTimed || !cut {
		t.Fatalf("len = %d cut = %v", len(l), cut)
	}
	if got := b.metrics.Get(MetricInputBudgetDenied); got != 0 {
		t.Fatalf("%s = %v", MetricInputBudgetDenied, got)
	}
}
