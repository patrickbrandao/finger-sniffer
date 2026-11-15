package web

import (
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestAltSvcPosition: em TLS com h3 de pé, o Alt-Svc sai depois dos campos padrão e antes dos de h=, na
// ordem dos bytes (spec 005 RF-04); o Date continua o primeiro campo (ADR 0021) e hsize segue exato.
func TestAltSvcPosition(t *testing.T) {
	h := newHarness(t, harnessOpts{cfg: func(c *Config) {
		c.UDPPorts = []int{8443}
		c.Limits = ControlLimits{SizeMax: 4096, DelayMax: 2 * time.Second, HSizeMax: 2048}
	}})
	pc := startH3(t, h)
	do := func(path string) *client {
		t.Helper()
		cl := newClient(t, dialTLS(t, h.addr443, testSNI))
		cl.send(get(path, "x"))
		return cl
	}
	alt := "Alt-Svc: " + altSvcH3(pc.LocalAddr().(*net.UDPAddr).Port) + "\r\n"
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

// TestAltSvcPortChoice: U é a primeira porta de FS_WEB_UDP_PORTS com listener de pé, em IPv4 ou IPv6
// (h3=":8443" no finger-01); com portas pedidas e nenhuma de pé, sem anúncio e h3_listener_down; com
// FS_WEB_UDP_PORTS vazio, sem anúncio e sem degraded (spec 005 RF-04, ADR 0038).
func TestAltSvcPortChoice(t *testing.T) {
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.UDPPorts = []int{8443, 9443} }})
	down := func() bool {
		_, reasons := h.srv.Status()
		return slices.Contains(reasons, ReasonH3Down)
	}
	if v := h.srv.altSvc(true, ""); v != "" || !down() {
		t.Fatalf("nenhum de pé: %q down=%v", v, down())
	}
	h.srv.setUDP("[::1]:9443", true)
	if v := h.srv.altSvc(true, ""); v != `h3=":9443"; ma=60` || down() {
		t.Fatalf("só 9443: %q down=%v", v, down())
	}
	h.srv.setUDP("127.0.0.1:8443", true)
	if v := h.srv.altSvc(true, ""); v != `h3=":8443"; ma=60` {
		t.Fatalf("8443 e 9443: %q", v)
	}
	if v := h.srv.altSvc(false, ""); v != "" {
		t.Fatalf("sem TLS: %q", v)
	}
	if v := h.srv.altSvc(true, "alt_svc=0"); v != "" {
		t.Fatalf("alt_svc=0: %q", v)
	}
	// listener de uma porta fora da lista não conta
	h.srv.setUDP("127.0.0.1:8443", false)
	h.srv.setUDP("[::1]:9443", false)
	h.srv.setUDP("127.0.0.1:4433", true)
	if v := h.srv.altSvc(true, ""); v != "" || !down() {
		t.Fatalf("porta fora da lista: %q down=%v", v, down())
	}

	off := newHarness(t, harnessOpts{cfg: func(c *Config) { c.UDPPorts = nil }})
	if v := off.srv.altSvc(true, ""); v != "" {
		t.Fatalf("FS_WEB_UDP_PORTS vazio: %q", v)
	}
	if st, reasons := off.srv.Status(); slices.Contains(reasons, ReasonH3Down) {
		t.Fatalf("FS_WEB_UDP_PORTS vazio degradou: %s %v", st, reasons)
	}
}
