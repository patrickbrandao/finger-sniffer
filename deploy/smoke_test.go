package deploy

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// fakeMirror imita, em 127.0.0.1, as portas que o deploy/smoke.sh consulta.
type fakeMirror struct {
	mu       sync.Mutex
	statuses map[string]string
	reasons  map[string][]string

	plain, tls *httptest.Server
	dnsSrv     *dns.Server
	dnsPort    int
	echo       net.Listener
	banner     net.Listener
}

func (f *fakeMirror) setStatus(svc, status string, reasons ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses[svc] = status
	f.reasons[svc] = reasons
}

// health devolve o JSON no formato do store (status antes de reasons e metrics), indentado como o real.
func (f *fakeMirror) health(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	type svc struct {
		Status  string         `json:"status"`
		Version string         `json:"version"`
		Reasons []string       `json:"reasons,omitempty"`
		Metrics map[string]int `json:"metrics,omitempty"`
	}
	services := map[string]svc{}
	for name, st := range f.statuses {
		services[name] = svc{Status: st, Version: "test", Reasons: f.reasons[name], Metrics: map[string]int{"x_total": 1}}
	}
	b, _ := json.MarshalIndent(map[string]any{"ok": true, "services": services}, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func newFakeMirror(t *testing.T) *fakeMirror {
	t.Helper()
	f := &fakeMirror{statuses: map[string]string{}, reasons: map[string][]string{}}
	for _, s := range []string{"capture", "web", "raw", "dns", "store"} {
		f.statuses[s] = "ok"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", f.health)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hello")) })
	f.plain = httptest.NewServer(mux)
	f.tls = httptest.NewUnstartedServer(mux)
	// o handshake recusado pelo curl no teste de TLS estrito é esperado: sem log
	f.tls.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.tls.StartTLS()
	t.Cleanup(f.plain.Close)
	t.Cleanup(f.tls.Close)

	// DNS: A 127.0.0.1 dentro da zona, REFUSED fora dela
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.dnsPort = pc.LocalAddr().(*net.UDPAddr).Port
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		q := r.Question[0]
		if !dns.IsSubDomain("zone.test.", q.Name) {
			m.SetRcode(r, dns.RcodeRefused)
		} else {
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
				A:   net.IPv4(127, 0, 0, 1),
			})
		}
		_ = w.WriteMsg(m)
	})
	started := make(chan struct{})
	f.dnsSrv = &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = f.dnsSrv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = f.dnsSrv.Shutdown() })

	f.echo = listen(t, func(c net.Conn) {
		line, err := bufio.NewReader(c).ReadString('\n')
		if err == nil {
			_, _ = c.Write([]byte(line))
		}
	})
	f.banner = listen(t, func(c net.Conn) { _, _ = c.Write([]byte("220 fake ESMTP ready\r\n")) })
	return f
}

// listen aceita conexões TCP em 127.0.0.1 e chama h em cada uma (fechando depois).
func listen(t *testing.T, h func(net.Conn)) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				h(c)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func port(t *testing.T, addr string) string {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// runSmoke executa deploy/smoke.sh contra o espelho falso; devolve a saída e o código de saída.
func runSmoke(t *testing.T, f *fakeMirror, svc string, extra ...string) (string, int) {
	t.Helper()
	for _, tool := range []string{"bash", "curl", "dig"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s ausente", tool)
		}
	}
	cmd := exec.Command("bash", "smoke.sh")
	cmd.Env = append(os.Environ(),
		"SVC="+svc,
		"FS_ENV_FILE=/nonexistent",
		"SMOKE_HOST=127.0.0.1",
		"SMOKE_NAME=example.com", // nome coberto pelo certificado do httptest
		"SMOKE_ZONE=zone.test",
		"SMOKE_DNS_EXPECT=127.0.0.1",
		"SMOKE_API_HTTP_PORT="+port(t, f.plain.Listener.Addr().String()),
		"SMOKE_API_HTTPS_PORT="+port(t, f.tls.Listener.Addr().String()),
		"SMOKE_HTTP_PORT="+port(t, f.plain.Listener.Addr().String()),
		"SMOKE_HTTPS_PORT="+port(t, f.tls.Listener.Addr().String()),
		"SMOKE_DNS_PORT="+strconv.Itoa(f.dnsPort),
		"SMOKE_ECHO_PORT="+port(t, f.echo.Addr().String()),
		"SMOKE_BANNER_PORT="+port(t, f.banner.Addr().String()),
		"SMOKE_HEALTH_WAIT=2",
		"SMOKE_TIMEOUT=2",
	)
	cmd.Env = append(cmd.Env, extra...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return string(out), ee.ExitCode()
		}
		t.Fatalf("smoke.sh: %v\n%s", err, out)
	}
	return string(out), 0
}

func TestSmokeListSelectsStepsBySVC(t *testing.T) {
	cases := map[string]string{
		"":        "health web dns raw store",
		"web":     "health web",
		"dns":     "health dns",
		"raw":     "health raw",
		"store":   "health store",
		"capture": "health",
		"nats":    "health",
	}
	for svc, want := range cases {
		cmd := exec.Command("bash", "smoke.sh")
		cmd.Env = append(os.Environ(), "SVC="+svc, "SMOKE_HOST=127.0.0.1", "SMOKE_LIST=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("SVC=%q: %v\n%s", svc, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("SVC=%q: passos %q, quer %q", svc, got, want)
		}
	}
}

func TestSmokeRejectsInvalidSVC(t *testing.T) {
	cmd := exec.Command("bash", "smoke.sh")
	cmd.Env = append(os.Environ(), "SVC=bogus", "SMOKE_HOST=127.0.0.1")
	if err := cmd.Run(); err == nil {
		t.Fatal("SVC inválido deveria falhar")
	}
}

func TestSmokeAllPassWithSelfSignedWarning(t *testing.T) {
	f := newFakeMirror(t)
	f.setStatus("web", "degraded", "cert_self_signed")
	f.setStatus("store", "degraded", "cert_self_signed")
	out, rc := runSmoke(t, f, "")
	if rc != 0 {
		t.Fatalf("rc=%d\n%s", rc, out)
	}
	for _, want := range []string{"[smoke] ok", "dns example.com", "REFUSED", "raw banner", "AVISO"} {
		if !strings.Contains(out, want) {
			t.Errorf("saída sem %q\n%s", want, out)
		}
	}
}

func TestSmokeStrictTLSWhenNotSelfSigned(t *testing.T) {
	// health sem cert_self_signed: o certificado do httptest (CA desconhecida) tem de reprovar
	f := newFakeMirror(t)
	out, rc := runSmoke(t, f, "web")
	if rc == 0 || !strings.Contains(out, "web GET https") || !strings.Contains(out, "FALHOU") {
		t.Fatalf("esperava falha do TLS estrito, rc=%d\n%s", rc, out)
	}
}

func TestSmokeFailsWhenRawIsDown(t *testing.T) {
	f := newFakeMirror(t)
	f.setStatus("web", "degraded", "cert_self_signed")
	f.setStatus("store", "degraded", "cert_self_signed")
	_ = f.echo.Close()
	out, rc := runSmoke(t, f, "")
	if rc == 0 || !strings.Contains(out, "raw eco") || !strings.Contains(out, "[smoke] FALHOU") {
		t.Fatalf("esperava falha com o raw parado, rc=%d\n%s", rc, out)
	}
	// os outros passos rodam mesmo depois da falha
	if !strings.Contains(out, "store GET https") {
		t.Errorf("passos seguintes não rodaram\n%s", out)
	}

	// SVC=dns não olha o raw
	out, rc = runSmoke(t, f, "dns")
	if rc != 0 || strings.Contains(out, "raw eco") {
		t.Fatalf("SVC=dns deveria passar sem o raw, rc=%d\n%s", rc, out)
	}
}

func TestSmokeFailsWhenServiceUnhealthy(t *testing.T) {
	f := newFakeMirror(t)
	f.setStatus("raw", "down")
	out, rc := runSmoke(t, f, "capture")
	if rc == 0 || !strings.Contains(out, "raw=down") {
		t.Fatalf("esperava falha do health, rc=%d\n%s", rc, out)
	}
}
