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
	"path/filepath"
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
	metrics  map[string]map[string]int
	altSvc   string            // Alt-Svc das respostas ("" = nenhum)
	versions map[string]string // versão por serviço ("" = "test")
	botCode  int               // código de GET /bot/v1/health (0 = 200)

	plain, tls *httptest.Server
	dnsSrv     *dns.Server
	dnsPort    int
	echo       net.Listener
	banner     net.Listener
}

func (f *fakeMirror) setMetric(svc, name string, v int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.metrics[svc] == nil {
		f.metrics[svc] = map[string]int{"x_total": 1}
	}
	f.metrics[svc][name] = v
}

func (f *fakeMirror) setAltSvc(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.altSvc = v
}

func (f *fakeMirror) setVersion(svc, v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versions[svc] = v
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
	match := true
	for name, st := range f.statuses {
		m := f.metrics[name]
		if m == nil {
			m = map[string]int{"x_total": 1}
		}
		v := f.versions[name]
		if v == "" {
			v = "test"
		}
		match = match && v == "test"
		reasons := f.reasons[name]
		// como o store (internal/store/health.go): versão diferente da do store degrada com motivo
		if v != "test" {
			reasons = append(append([]string(nil), reasons...), "version "+v+" differs from store test")
			if st == "ok" {
				st = "degraded"
			}
		}
		services[name] = svc{Status: st, Version: v, Reasons: reasons, Metrics: m}
	}
	b, _ := json.MarshalIndent(map[string]any{
		"ok": true, "version": "test", "versions_match": match, "services": services,
	}, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func newFakeMirror(t *testing.T) *fakeMirror {
	t.Helper()
	f := &fakeMirror{statuses: map[string]string{}, reasons: map[string][]string{}, metrics: map[string]map[string]int{}, versions: map[string]string{}}
	for _, s := range []string{"capture", "web", "raw", "dns", "store", "bot"} {
		f.statuses[s] = "ok"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", f.health)
	mux.HandleFunc("/bot/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		code := f.botCode
		f.mu.Unlock()
		if code == 0 {
			code = http.StatusOK
		}
		w.WriteHeader(code)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		alt := f.altSvc
		f.mu.Unlock()
		if alt != "" {
			w.Header().Set("Alt-Svc", alt)
		}
		_, _ = w.Write([]byte("hello"))
	})
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
		// UDP do h3 no mesmo número do TLS (como 8443 no finger-01) e o "traefik" falso é o próprio TLS
		"SMOKE_H3_PORT="+port(t, f.tls.Listener.Addr().String()),
		"SMOKE_TRAEFIK_PORT="+port(t, f.tls.Listener.Addr().String()),
		"SMOKE_DNS_PORT="+strconv.Itoa(f.dnsPort),
		"SMOKE_ECHO_PORT="+port(t, f.echo.Addr().String()),
		"SMOKE_BANNER_PORT="+port(t, f.banner.Addr().String()),
		// bot: 9002 no TLS falso e 9003 no HTTP falso, sem a bridge (a recusa por origem é coberta no finger-01)
		"SMOKE_BOT_PUBLIC_PORT="+port(t, f.tls.Listener.Addr().String()),
		"SMOKE_BOT_INTERNAL_PORT="+port(t, f.plain.Listener.Addr().String()),
		"SMOKE_BOT_LOOPBACK=127.0.0.1",
		"SMOKE_BOT_BRIDGE=",
		"SMOKE_HEALTH_WAIT=2",
		"SMOKE_TIMEOUT=2",
		// o espelho falso não fala h3; o GET por h3 é coberto só contra o servidor (finger-01)
		"SMOKE_H3_GET=0",
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
		"":        "health web h3 traefik dns raw store bot",
		"bot":     "health bot",
		"web":     "health web h3 traefik",
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

// selfSignedMirror: espelho falso com web e store autoassinados (o curl usa -k contra o httptest).
func selfSignedMirror(t *testing.T) *fakeMirror {
	t.Helper()
	f := newFakeMirror(t)
	f.setStatus("web", "degraded", "cert_self_signed")
	f.setStatus("store", "degraded", "cert_self_signed")
	return f
}

// listenUDPOnTLSPort abre um socket UDP no mesmo número de porta do TLS falso, como o listener QUIC da 443.
func listenUDPOnTLSPort(t *testing.T, f *fakeMirror) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:"+port(t, f.tls.Listener.Addr().String()))
	if err != nil {
		t.Skipf("porta UDP ocupada: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
}

func TestSmokeH3SkippedWithoutHeartbeat(t *testing.T) {
	// antes da task 057: o web não anuncia h3 e o passo só avisa
	f := selfSignedMirror(t)
	out, rc := runSmoke(t, f, "web")
	if rc != 0 || !strings.Contains(out, "h3_listening") || !strings.Contains(out, "pulado") {
		t.Fatalf("esperava aviso de h3 pulado, rc=%d\n%s", rc, out)
	}
}

func TestSmokeH3PassesWithAltSvcAndListener(t *testing.T) {
	f := selfSignedMirror(t)
	f.setMetric("web", "h3_listening", 1)
	alt := `h3=":` + port(t, f.tls.Listener.Addr().String()) + `"; ma=60`
	f.setAltSvc(alt)
	listenUDPOnTLSPort(t, f)
	out, rc := runSmoke(t, f, "web")
	if rc != 0 {
		t.Fatalf("rc=%d\n%s", rc, out)
	}
	for _, want := range []string{"h3 Alt-Svc", alt, "h3 listener udp", "SMOKE_H3_GET=0"} {
		if !strings.Contains(out, want) {
			t.Errorf("saída sem %q\n%s", want, out)
		}
	}
	if _, err := exec.LookPath("ss"); err == nil && !strings.Contains(out, "ss -Hlun") {
		t.Errorf("com ss no host, o listener UDP deveria ser conferido\n%s", out)
	}
}

func TestSmokeH3FailsWithoutAltSvc(t *testing.T) {
	f := selfSignedMirror(t)
	f.setMetric("web", "h3_listening", 1)
	listenUDPOnTLSPort(t, f)
	out, rc := runSmoke(t, f, "web")
	if rc == 0 || !strings.Contains(out, "sem Alt-Svc h3") {
		t.Fatalf("esperava falha sem Alt-Svc, rc=%d\n%s", rc, out)
	}
}

func TestSmokeH3FailsWithoutUDPListener(t *testing.T) {
	if _, err := exec.LookPath("ss"); err != nil {
		t.Skip("ss ausente (só Linux)")
	}
	f := selfSignedMirror(t)
	f.setMetric("web", "h3_listening", 1)
	f.setAltSvc(`h3=":` + port(t, f.tls.Listener.Addr().String()) + `"; ma=60`)
	out, rc := runSmoke(t, f, "web")
	if rc == 0 || !strings.Contains(out, "nenhum socket UDP") {
		t.Fatalf("esperava falha sem listener UDP, rc=%d\n%s", rc, out)
	}
}

func TestSmokeH3FailsWhenListenerDown(t *testing.T) {
	f := selfSignedMirror(t)
	f.setStatus("web", "degraded", "cert_self_signed", "h3_listener_down")
	out, rc := runSmoke(t, f, "web")
	if rc == 0 || !strings.Contains(out, "h3_listener_down") {
		t.Fatalf("esperava falha com h3_listener_down, rc=%d\n%s", rc, out)
	}
}

func TestSmokeFailsOnVersionMismatchInFullDeploy(t *testing.T) {
	// task 078: deploy completo com versões desencontradas reprova, mostrando a versão de cada serviço
	f := selfSignedMirror(t)
	f.setVersion("raw", "old1234")
	out, rc := runSmoke(t, f, "")
	if rc == 0 || !strings.Contains(out, "VERSÕES DESENCONTRADAS") || !strings.Contains(out, "raw=old1234") {
		t.Fatalf("esperava falha por versions_match=false, rc=%d\n%s", rc, out)
	}
}

func TestSmokeWarnsOnVersionMismatchWithSVC(t *testing.T) {
	// com SVC=<svc>, desencontro é esperado (um serviço de outro commit): só avisa
	f := selfSignedMirror(t)
	f.setVersion("raw", "old1234")
	out, rc := runSmoke(t, f, "capture")
	if rc != 0 || !strings.Contains(out, "AVISO VERSÕES DESENCONTRADAS") {
		t.Fatalf("esperava aviso sem falha, rc=%d\n%s", rc, out)
	}
}

func TestSmokePassesWhenVersionsMatch(t *testing.T) {
	f := selfSignedMirror(t)
	out, rc := runSmoke(t, f, "capture")
	if rc != 0 || !strings.Contains(out, "health versions_match") || strings.Contains(out, "DESENCONTRADAS") {
		t.Fatalf("rc=%d\n%s", rc, out)
	}
}

// task 173 (spec 016 RF-10): degraded sai como AVISO com serviço e motivos; só cert_self_signed é tolerado.
func TestSmokeDegradedSelfSignedPassesWithWarning(t *testing.T) {
	f := selfSignedMirror(t)
	out, rc := runSmoke(t, f, "")
	if rc != 0 {
		t.Fatalf("rc=%d\n%s", rc, out)
	}
	for _, want := range []string{"health web", "health store", "AVISO degraded: cert_self_signed"} {
		if !strings.Contains(out, want) {
			t.Errorf("saída sem %q\n%s", want, out)
		}
	}
}

func TestSmokeDegradedByOtherReasonFails(t *testing.T) {
	for _, svc := range []string{"", "capture"} {
		f := selfSignedMirror(t)
		f.setStatus("store", "degraded", "cert_self_signed", "ntp not synchronized")
		out, rc := runSmoke(t, f, svc)
		if rc != 1 {
			t.Fatalf("SVC=%q: esperava rc=1, veio %d\n%s", svc, rc, out)
		}
		for _, want := range []string{
			"AVISO degraded: cert_self_signed; ntp not synchronized",
			"degraded por motivo não tolerado: ntp not synchronized", "[smoke] FALHOU",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("SVC=%q: saída sem %q\n%s", svc, want, out)
			}
		}
		if strings.Contains(out, "não tolerado: cert_self_signed") {
			t.Errorf("SVC=%q: cert_self_signed reprovado\n%s", svc, out)
		}
	}
}

func TestSmokeDegradedWithoutReasonFails(t *testing.T) {
	f := selfSignedMirror(t)
	f.setStatus("dns", "degraded")
	out, rc := runSmoke(t, f, "dns")
	if rc != 1 || !strings.Contains(out, "não tolerado: (sem motivo)") {
		t.Fatalf("rc=%d\n%s", rc, out)
	}
}

func TestSmokeVersionReasonToleratedOnlyWithSVC(t *testing.T) {
	f := selfSignedMirror(t)
	f.setVersion("raw", "old1234")
	out, rc := runSmoke(t, f, "web")
	if rc != 0 || !strings.Contains(out, "AVISO degraded: version old1234 differs from store test") {
		t.Fatalf("SVC=web: rc=%d\n%s", rc, out)
	}
	out, rc = runSmoke(t, f, "")
	if rc != 1 || !strings.Contains(out, "não tolerado: version old1234 differs from store test") {
		t.Fatalf("sem SVC: rc=%d\n%s", rc, out)
	}
}

// ADR 0038: Alt-Svc com outra porta (o h3=":443" antigo, que no finger-01 é do traefik) reprova.
func TestSmokeH3FailsWithAltSvcOnOtherPort(t *testing.T) {
	f := selfSignedMirror(t)
	f.setMetric("web", "h3_listening", 1)
	f.setAltSvc(`h3=":443"; ma=60`)
	listenUDPOnTLSPort(t, f)
	out, rc := runSmoke(t, f, "web")
	want := `esperado h3=":` + port(t, f.tls.Listener.Addr().String()) + `"`
	if rc == 0 || !strings.Contains(out, want) {
		t.Fatalf("esperava falha por Alt-Svc em outra porta, rc=%d\n%s", rc, out)
	}
}

// smokeConfig devolve a linha de SMOKE_CONFIG=1 com o env dado.
func smokeConfig(t *testing.T, env ...string) string {
	t.Helper()
	cmd := exec.Command("bash", "smoke.sh")
	cmd.Env = append(os.Environ(), "SMOKE_CONFIG=1")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// Padrões do finger-01 (ADR 0038, task 224): web em 8080/8443, h3 em UDP 8443, nome do certificado B, zona
// finger-west-01 e o traefik na 443 obrigatório (task 232).
func TestSmokeDefaultsFinger01(t *testing.T) {
	got := smokeConfig(t, "FS_ENV_FILE=/nonexistent", "SMOKE_HOST=170.247.40.86")
	want := "host=170.247.40.86 name=finger-01.badblock.net.br zone=finger-west-01.badblock.net.br " +
		"http=8080 https=8443 h3=8443 traefik=finger-01.badblock.net.br:443 required=1"
	if got != want {
		t.Errorf("padrões:\n got %s\nwant %s", got, want)
	}

	// do env instalado: IP, primeiro nome do certificado B, zona e primeira porta UDP
	env := filepath.Join(t.TempDir(), "fs.env")
	if err := os.WriteFile(env, []byte("FS_LISTEN_IPV4=192.0.2.1\nFS_DNS_ZONE=z.example\n"+
		"FS_CERT_NAMES_HTTP01=b.example,c.example\nFS_WEB_UDP_PORTS=9443,8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got = smokeConfig(t, "FS_ENV_FILE="+env)
	want = "host=192.0.2.1 name=b.example zone=z.example http=8080 https=8443 h3=9443 traefik=b.example:443 required=1"
	if got != want {
		t.Errorf("do env:\n got %s\nwant %s", got, want)
	}
}

func TestSmokeTraefikPassesThroughToWeb(t *testing.T) {
	f := selfSignedMirror(t)
	out, rc := runSmoke(t, f, "web")
	if rc != 0 || !strings.Contains(out, "traefik GET https") || !strings.Contains(out, "HTTP 200") {
		t.Fatalf("rc=%d\n%s", rc, out)
	}
}

// Sem a rota do traefik: reprova por padrão (task 232); SMOKE_TRAEFIK_REQUIRED=0 rebaixa a AVISO.
func TestSmokeTraefikRequiredByDefault(t *testing.T) {
	f := selfSignedMirror(t)
	closed := listen(t, func(net.Conn) {})
	p := port(t, closed.Addr().String())
	_ = closed.Close()
	out, rc := runSmoke(t, f, "web", "SMOKE_TRAEFIK_PORT="+p)
	if rc == 0 || !strings.Contains(out, "traefik GET https") || !strings.Contains(out, "FALHOU") {
		t.Fatalf("esperava falha sem a rota do traefik, rc=%d\n%s", rc, out)
	}
	out, rc = runSmoke(t, f, "web", "SMOKE_TRAEFIK_PORT="+p, "SMOKE_TRAEFIK_REQUIRED=0")
	if rc != 0 || !strings.Contains(out, "AVISO") || !strings.Contains(out, "SMOKE_TRAEFIK_REQUIRED=0") {
		t.Fatalf("esperava AVISO sem falha com SMOKE_TRAEFIK_REQUIRED=0, rc=%d\n%s", rc, out)
	}
}

// Bot (spec 016 RF-14): 9002 e 9003 respondendo passam; o health sem o bot reprova; sem a bridge, aviso.
func TestSmokeBotPasses(t *testing.T) {
	f := newFakeMirror(t)
	f.setStatus("store", "degraded", "cert_self_signed")
	out, rc := runSmoke(t, f, "bot")
	if rc != 0 {
		t.Fatalf("rc=%d\n%s", rc, out)
	}
	for _, want := range []string{"bot GET https :", "bot :", "loopback", "sem FS_BOT_INTERNAL_LISTEN: pulado", "bot=ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("saída sem %q\n%s", want, out)
		}
	}
}

func TestSmokeBotFailsWhenHealthNot200(t *testing.T) {
	f := newFakeMirror(t)
	f.setStatus("store", "degraded", "cert_self_signed")
	f.mu.Lock()
	f.botCode = http.StatusServiceUnavailable
	f.mu.Unlock()
	if out, rc := runSmoke(t, f, "bot"); rc == 0 || !strings.Contains(out, "FALHOU") {
		t.Fatalf("esperava falha, rc=%d\n%s", rc, out)
	}
}

func TestSmokeFailsWhenBotDown(t *testing.T) {
	f := newFakeMirror(t)
	f.setStatus("store", "degraded", "cert_self_signed")
	f.setStatus("bot", "down")
	if out, rc := runSmoke(t, f, "bot"); rc == 0 || !strings.Contains(out, "bot=down") {
		t.Fatalf("esperava falha com bot=down, rc=%d\n%s", rc, out)
	}
}

// Com a bridge, a origem fora dela tem de levar 403: um bot que aceita qualquer origem reprova.
func TestSmokeBotBridgeMustRejectOtherOrigin(t *testing.T) {
	f := newFakeMirror(t)
	f.setStatus("store", "degraded", "cert_self_signed")
	out, rc := runSmoke(t, f, "bot", "SMOKE_BOT_BRIDGE=127.0.0.1")
	if rc == 0 || !strings.Contains(out, "esperado 403") {
		t.Fatalf("esperava falha da recusa por origem, rc=%d\n%s", rc, out)
	}
}
