package web

import (
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestControlsRepeatCap (task 322, ADR 0070 item 3): h= e status= 1xx repetidos param no teto, sem 400, e o
// nome entra em controls.clamped.
func TestControlsRepeatCap(t *testing.T) {
	q := strings.Repeat("h=a:&", 200_000) + strings.Repeat("status=100&", 200_000)
	c := ParseControls(q, ControlLimits{})
	if len(c.Fields) != maxFieldControls || len(c.Interim) != maxInterimControls {
		t.Fatalf("fields %d interim %d", len(c.Fields), len(c.Interim))
	}
	if !c.Valid() {
		t.Fatalf("clamp turned into 400: %s", c.InvalidText())
	}
	if !slices.Contains(c.Record.Clamped, "h") || !slices.Contains(c.Record.Clamped, "status") {
		t.Fatalf("clamped %v", c.Record.Clamped)
	}
}

// TestControlsRepeatRetained (task 322): conexões que mandam ~850 KB de h=a: e não leem a resposta retêm
// menos de 2× o que reservam no orçamento (3× com -race, retainFactor).
func TestControlsRepeatRetained(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	req := "GET /p/" + testProbe + "/r?size=50000000&" + strings.Repeat("h=a:&", 170_000) +
		" HTTP/1.1\r\nHost: x\r\n\r\n"
	const n = 10
	base := heapInUse()
	conns := make([]net.Conn, 0, n)
	for range n {
		c := dial(t, h.addr80)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(4096)
		}
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	// espera as requisições chegarem ao escritor (o orçamento estabiliza)
	time.Sleep(500 * time.Millisecond)
	reserved := h.srv.budget.inUse()
	retained := heapInUse() - base
	t.Logf("reservado %d, retido %d", reserved, retained)
	if reserved <= 0 || retained > retainFactor*reserved {
		t.Fatalf("retido %d > %d× reservado %d", retained, retainFactor, reserved)
	}
	for _, c := range conns {
		_ = c.Close()
	}
}
