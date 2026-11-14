package web

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestH2PendingBodyIdle (task 142): stream h2 com content-length cujo corpo nunca chega → a conexão fecha
// depois de idle (nunca antes) e a vaga volta; upload lento porém ativo não é cortado.
func TestH2PendingBodyIdle(t *testing.T) {
	const idle = 500 * time.Millisecond
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.IdleDefault = idle }})
	post := h2Get("/p/"+testProbe+"/", [2]string{"content-length", "10"})
	post[0][1] = "POST"

	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings()
	r.rawHeaders(1, false, post...)
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var err error
	for err == nil {
		_, err = r.fr.ReadFrame()
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("connection not closed by the server: %v", err)
	}
	if d := time.Since(start); d < idle-50*time.Millisecond || d > 3*time.Second {
		t.Fatalf("closed after %v (idle %v)", d, idle)
	}
	waitFor(t, 2*time.Second, func() bool { return h.srv.metrics.Get(MetricConnsActive) == 0 && len(h.srv.sem) == 0 },
		func() string {
			return fmt.Sprint("active ", h.srv.metrics.Get(MetricConnsActive), " sem ", len(h.srv.sem))
		})

	// Upload lento (um byte a cada 200 ms, mais longo que idle no total): atendido.
	c2 := dial(t, h.addr80)
	r2 := newH2Raw(t, c2, true)
	_ = r2.fr.WriteSettings()
	r2.rawHeaders(1, false, post...)
	for i := range 10 {
		time.Sleep(idle / 5 * 2)
		if err := r2.fr.WriteData(1, i == 9, []byte{'x'}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	hf := r2.until(func(f http2.Frame) bool { m, ok := f.(*http2.MetaHeadersFrame); return ok && m.StreamID == 1 }).(*http2.MetaHeadersFrame)
	if hf.PseudoValue("status") != "200" {
		t.Fatalf("slow upload status %s", hf.PseudoValue("status"))
	}
}
