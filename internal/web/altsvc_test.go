package web

import (
	"strings"
	"testing"
	"time"
)

// TestAltSvcPosition: em TLS com h3 de pé, o Alt-Svc sai depois dos campos padrão e antes dos de h=, na
// ordem dos bytes (spec 005 RF-04); o Date continua o primeiro campo (ADR 0021) e hsize segue exato.
func TestAltSvcPosition(t *testing.T) {
	h := newHarness(t, harnessOpts{cfg: func(c *Config) {
		c.UDPPorts = []int{443}
		c.Limits = ControlLimits{SizeMax: 4096, DelayMax: 2 * time.Second, HSizeMax: 2048}
	}})
	startH3(t, h)
	do := func(path string) *client {
		t.Helper()
		cl := newClient(t, dialTLS(t, h.addr443, testSNI))
		cl.send(get(path, "x"))
		return cl
	}
	alt := "Alt-Svc: " + altSvcH3 + "\r\n"
	std := "HTTP/1.1 200 OK\r\n" + dateLine + "Content-Type: application/octet-stream\r\nCache-Control: no-store\r\n"

	t.Run("fields", func(t *testing.T) {
		do("/r?size=0&h=X-A:1&h=x-b:%20two").
			expect(std + alt + "X-A: 1\r\nx-b:  two\r\nContent-Length: 0\r\n\r\n")
	})
	t.Run("conn", func(t *testing.T) {
		// Connection é campo padrão: o Alt-Svc vem depois dele.
		do("/r?size=0&conn=close&h=X-A:1").
			expect(std + "Connection: close\r\n" + alt + "X-A: 1\r\nContent-Length: 0\r\n\r\n")
	})
	t.Run("no-fields", func(t *testing.T) {
		do("/r?size=0").expect(std + alt + "Content-Length: 0\r\n\r\n")
	})
	t.Run("hsize", func(t *testing.T) {
		base := std + alt + "X-A: 1\r\nContent-Length: 0\r\n"
		pad := "X-Fs-Pad: " + strings.Repeat("a", 400-len(base)-len("X-Fs-Pad: \r\n")-len("\r\n")) + "\r\n"
		want := base + pad + "\r\n"
		if len(want) != 400 {
			t.Fatalf("want len %d", len(want))
		}
		do("/r?size=0&h=X-A:1&hsize=400").expect(want)
	})
}
