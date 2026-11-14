package web

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// TestInputBudget: reserva sem bloquear, recusa contada, teto local do hold e devolução idempotente.
func TestInputBudget(t *testing.T) {
	m := service.NewMetrics()
	b := newInputBudget(100, m)
	if !b.reserve(60) || b.reserve(41) || !b.reserve(40) || b.inUse() != 100 {
		t.Fatalf("in use %d", b.inUse())
	}
	b.release(100)
	if m.Get(MetricInputBudgetUsed) != 0 || m.Get(MetricInputBudgetDenied) != 1 {
		t.Fatalf("metrics %v", m.Snapshot())
	}

	h := b.newHold(50)
	if !h.reserve(30) || h.reserve(21) || b.inUse() != 30 {
		t.Fatalf("hold local cap: %d %d", h.inUse(), b.inUse())
	}
	// Recusa do global não deixa reserva no hold.
	other := b.newHold(0)
	if !other.reserve(70) || h.reserve(1) || h.inUse() != 30 {
		t.Fatalf("global cap: %d", h.inUse())
	}
	h.release(10)
	if h.inUse() != 20 || b.inUse() != 90 {
		t.Fatalf("partial release: %d %d", h.inUse(), b.inUse())
	}
	h.release(1000) // nunca devolve mais do que retém
	h.releaseAll()
	other.releaseAll()
	other.releaseAll()
	if b.inUse() != 0 || m.Get(MetricInputBudgetUsed) != 0 {
		t.Fatalf("leftover %d", b.inUse())
	}

	// Concorrência: muitos donos reservando e devolvendo terminam em zero sem passar do teto.
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			h := b.newHold(0)
			for range 1000 {
				if h.reserve(7) && b.inUse() > 100 {
					t.Error("over limit")
				}
			}
			h.releaseAll()
		})
	}
	wg.Wait()
	if b.inUse() != 0 {
		t.Fatalf("concurrent leftover %d", b.inUse())
	}
}

// TestLoadConfigInputBudget: FS_WEB_INPUT_BUDGET com padrão de 40 MiB e faixa 8–64 MiB (ADR 0033).
func TestLoadConfigInputBudget(t *testing.T) {
	t.Setenv("FS_LISTEN_IPV4", "127.0.0.1")
	t.Setenv("FS_LISTEN_IPV6", "")
	base, err := service.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FS_WEB_INPUT_BUDGET", "")
	if c, err := LoadConfig(base); err != nil || c.InputBudget != 41943040 {
		t.Fatalf("default: %v %d", err, c.InputBudget)
	}
	for v, ok := range map[string]bool{"8388608": true, "67108864": true, "8388607": false, "67108865": false, "0": false} {
		t.Setenv("FS_WEB_INPUT_BUDGET", v)
		c, err := LoadConfig(base)
		if (err == nil) != ok || (ok && fmt.Sprint(c.InputBudget) != v) {
			t.Fatalf("FS_WEB_INPUT_BUDGET=%s: %v %d", v, err, c.InputBudget)
		}
	}
}

// TestHTTP1InputBudget (task 155): com orçamento pequeno, conexões com cabeçalhos grandes pendentes →
// a excedente recebe 431 com head_too_large, as outras seguem, e o contador volta a zero ao fim de todas.
func TestHTTP1InputBudget(t *testing.T) {
	const budget = 1 << 20
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.InputBudget = budget }})
	partial := "GET /p/" + testProbe + "/ HTTP/1.1\r\nHost: x\r\nX-Big: " + strings.Repeat("a", 600<<10)

	c1 := dial(t, h.addr80)
	cl1 := newClient(t, c1)
	cl1.send(partial)
	waitFor(t, 2*time.Second, func() bool { return h.srv.budget.inUse() >= 500<<10 },
		func() string { return fmt.Sprint("in use ", h.srv.budget.inUse()) })

	// A segunda não cabe: 431, registrada com head_too_large, sem derrubar a primeira.
	c2 := dial(t, h.addr80)
	cl2 := newClient(t, c2)
	cl2.send(partial)
	if resp, _ := cl2.response("GET"); resp.StatusCode != 431 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	p := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c2), 1)[0].Payload
	if p["head_too_large"] != true || num(t, p["status"]) != 431 {
		t.Fatalf("payload %v %v", p["head_too_large"], p["status"])
	}
	if h.srv.metrics.Get(MetricInputBudgetDenied) < 1 || h.srv.budget.inUse() > budget {
		t.Fatalf("denied %v in use %d", h.srv.metrics.Get(MetricInputBudgetDenied), h.srv.budget.inUse())
	}

	// A primeira termina normalmente e devolve a reserva.
	cl1.send("\r\n\r\n")
	if resp, _ := cl1.response("GET"); resp.StatusCode != 200 {
		t.Fatalf("first status %d", resp.StatusCode)
	}
	waitFor(t, 2*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return fmt.Sprint("after response ", h.srv.budget.inUse()) })

	// Cabeçalho parcial abandonado (cliente fecha) também devolve.
	c3 := dial(t, h.addr80)
	newClient(t, c3).send(partial)
	waitFor(t, 2*time.Second, func() bool { return h.srv.budget.inUse() >= 500<<10 },
		func() string { return fmt.Sprint("c3 in use ", h.srv.budget.inUse()) })
	_ = c3.Close()
	_ = c2.Close()
	waitFor(t, 2*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return fmt.Sprint("after close ", h.srv.budget.inUse()) })
	if h.srv.metrics.Get(MetricInputBudgetUsed) != 0 {
		t.Fatalf("gauge %v", h.srv.metrics.Get(MetricInputBudgetUsed))
	}
}
