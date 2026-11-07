package store

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

var update = flag.Bool("update", false, "regrava o exemplo do health (testdata)")

const exampleFile = "../../cmd/finger-sniffer-store/testdata/health-example.json"

var t0 = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func heartbeat(t *testing.T, svc, ver, status string, reasons ...string) []byte {
	t.Helper()
	env, err := event.New(svc, ver, t0, nil, event.Heartbeat{
		Status: status, Reasons: reasons, Commit: "abc1234", StartedAt: event.FormatTime(t0.Add(-time.Hour)),
		Metrics: map[string]float64{"published_events_total": 42, "dropped_events_total": 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env)
	return b
}

func TestTracker(t *testing.T) {
	tr := NewTracker(event.Services, 15*time.Second)
	for _, s := range []string{"capture", "web", "raw", "store"} {
		if err := tr.Observe(heartbeat(t, s, "1.0.0", event.StatusOK), t0); err != nil {
			t.Fatal(err)
		}
	}
	_ = tr.Observe(heartbeat(t, "dns", "1.0.0", event.StatusDegraded, "zone"), t0.Add(-20*time.Second))

	got, allUp, match := tr.Services(t0, "1.0.0")
	if allUp || !match {
		t.Fatalf("allUp=%v match=%v", allUp, match)
	}
	if got["web"].Status != event.StatusOK || got["web"].Metrics["published_events_total"] != 42 || *got["web"].LastHeartbeat != event.FormatTime(t0) {
		t.Fatalf("web: %+v", got["web"])
	}
	if d := got["dns"]; d.Status != event.StatusDown || len(d.Reasons) != 2 {
		t.Fatalf("dns must be down after 15s: %+v", d)
	}

	// Serviço inesperado aparece; versão diferente desliga versions_match.
	_ = tr.Observe(heartbeat(t, "extra", "2.0.0", event.StatusOK), t0)
	_ = tr.Observe(heartbeat(t, "dns", "1.0.0", event.StatusOK), t0)
	got, allUp, match = tr.Services(t0, "1.0.0")
	if !allUp || match || got["extra"].Status != event.StatusOK {
		t.Fatalf("allUp=%v match=%v extra=%+v", allUp, match, got["extra"])
	}

	if err := tr.Observe([]byte("{"), t0); err == nil {
		t.Fatal("expected decode error")
	}
	bad, _ := json.Marshal(event.Envelope{SchemaVersion: 1, Service: "web", ServiceVersion: "v", Ts: "t", Payload: json.RawMessage(`[]`)})
	if err := tr.Observe(bad, t0); err == nil {
		t.Fatal("expected payload error")
	}
}

func TestTrackerNeverSeen(t *testing.T) {
	got, allUp, _ := NewTracker([]string{"web"}, time.Second).Services(t0, "v")
	if allUp || got["web"].Status != event.StatusDown || got["web"].LastHeartbeat != nil {
		t.Fatalf("%+v", got)
	}
}

// hostFixture cria arquivos de host falsos.
func hostFixture(t *testing.T, aggregating bool) HostPaths {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	agg := "false"
	if aggregating {
		agg = "true"
	}
	p := HostPaths{
		NetStatus: write("net-status.json", `{"iface":"eth0","mtu":1500,"kernel":"6.12.115+deb13.1-amd64",
			"offloads":{"generic-receive-offload":"off","rx-gro-hw":"off","tcp-segmentation-offload":"off"},
			"aggregating_offload":`+agg+`,"nft_ruleset_lines":0,"conntrack_loaded":false}`),
		SysctlFile:  write("90.conf", "# comentário\nnet.ipv4.tcp_syncookies = 1\n\nnet.core.somaxconn = 4096\nnet.ipv4.ip_local_port_range = 32768 60999\nnet.inexistente = 1\nlixo\n"),
		ProcSys:     filepath.Join(dir, "sys"),
		ProcNetstat: write("netstat", "TcpExt: SyncookiesSent SyncookiesRecv\nTcpExt: 3 0\nIpExt: InNoRoutes\nIpExt: 0\n"),
		TimesyncOK:  write("synchronized", ""),
	}
	write("sys/net/ipv4/tcp_syncookies", "1\n")
	write("sys/net/core/somaxconn", "4096\n")
	write("sys/net/ipv4/ip_local_port_range", "32768\t60999\n")
	return p
}

func TestReadHost(t *testing.T) {
	h, reasons := ReadHost(hostFixture(t, false))
	if len(reasons) != 0 {
		t.Fatalf("reasons %v", reasons)
	}
	if h.Kernel == "" || h.MTU != 1500 || h.Offloads["rx-gro-hw"] != "off" || !h.NTPSynchronized || h.SyncookiesSent != 3 {
		t.Fatalf("%+v", h)
	}
	if h.Sysctls["net.core.somaxconn"] != "4096" || h.Sysctls["net.ipv4.ip_local_port_range"] != "32768 60999" || len(h.Sysctls) != 3 {
		t.Fatalf("sysctls %v", h.Sysctls)
	}
}

func TestReadHostProblems(t *testing.T) {
	p := hostFixture(t, true)
	_, reasons := ReadHost(p)
	if len(reasons) != 1 || reasons[0] != "aggregating offload on" {
		t.Fatalf("%v", reasons)
	}
	if err := os.WriteFile(p.NetStatus, []byte(`{"conntrack_loaded":true,"nft_ruleset_lines":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(p.TimesyncOK)
	if _, reasons = ReadHost(p); len(reasons) != 3 {
		t.Fatalf("%v", reasons)
	}
	_ = os.WriteFile(p.NetStatus, []byte(`{`), 0o600)
	if _, reasons = ReadHost(p); reasons[0] != "net status invalid" {
		t.Fatalf("%v", reasons)
	}
	empty := HostPaths{NetStatus: "/nope", SysctlFile: "/nope", ProcNetstat: "/nope", TimesyncOK: "/nope"}
	h, reasons := ReadHost(empty)
	if len(reasons) != 2 || h.Sysctls != nil || h.SyncookiesSent != 0 {
		t.Fatalf("%+v %v", h, reasons)
	}
}

// exampleStore monta um store determinístico para o health de exemplo.
func exampleStore(t *testing.T) *Store {
	t.Helper()
	db, path := testDB(t)
	s := &Store{
		cfg: Config{DBPath: path, Retention: "10m", MaxBytes: 2 << 30, DownAfter: 15 * time.Second, Host: hostFixture(t, false)},
		db:  db, tracker: NewTracker(event.Services, 15*time.Second),
	}
	for _, svc := range event.Services {
		_ = s.tracker.Observe(heartbeat(t, svc, version.Version, event.StatusOK), t0)
	}
	return s
}

// TestHealthExample garante que o handler produz exatamente o exemplo do contrato
// (cmd/finger-sniffer-store/testdata/health-example.json), que o Redocly valida contra o schema Health
// no verify (regra no-invalid-media-type-examples). Assim a resposta real valida contra o openapi.yaml.
func TestHealthExample(t *testing.T) {
	s := exampleStore(t)
	h := s.HealthAt(context.Background(), t0)
	// Campos que dependem do ambiente ficam fixos no exemplo.
	h.Version, h.Host.Store.DBBytes = "0.1.0", 1048576
	for k, v := range h.Services {
		v.Version = "0.1.0"
		h.Services[k] = v
	}
	got, _ := json.MarshalIndent(map[string]any{"summary": "Todos os serviços no ar", "value": h}, "", "  ")
	got = append(got, '\n')
	if *update {
		if err := os.WriteFile(exampleFile, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(exampleFile)
	if err != nil {
		t.Fatalf("%v (rode com -update para criar)", err)
	}
	if string(got) != string(want) {
		t.Fatalf("health diverge do exemplo do contrato; rode go test ./internal/store -run TestHealthExample -update\n%s", got)
	}
}

func TestAPI(t *testing.T) {
	s := exampleStore(t)
	api := &API{OpenAPI: []byte("openapi: 3.1.0\n"), Health: s.HealthAt, Now: func() time.Time { return t0 }}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	get := func(path string) (int, http.Header, string) {
		t.Helper()
		resp, err := http.Get(srv.URL + path) //nolint:noctx // teste
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}

	code, hdr, body := get("/api/v1/health")
	var h Health
	if code != 200 || hdr.Get("Access-Control-Allow-Origin") != "*" || json.Unmarshal([]byte(body), &h) != nil || !h.OK {
		t.Fatalf("health %d %v %s", code, hdr, body)
	}
	if code, hdr, body = get("/api/v1/openapi.yaml"); code != 200 || hdr.Get("Content-Type") != "application/yaml" || !strings.HasPrefix(body, "openapi") {
		t.Fatalf("openapi %d %s", code, body)
	}
	code, _, body = get("/metrics")
	for _, want := range []string{`fs_service_up{service="web"} 1`, `fs_published_events_total{service="dns"} 42`, "fs_host_syncookies_sent 3", "fs_store_connections 0"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
	if code, _, _ = get("/nope"); code != 404 {
		t.Fatalf("404 expected, got %d", code)
	}
	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/api/v1/health", nil) //nolint:noctx // teste
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight %v %v", resp, err)
	}
	_ = resp.Body.Close()
}

func TestSanitize(t *testing.T) {
	if sanitize("a.b-c_D9") != "a_b_c_D9" {
		t.Fatal(sanitize("a.b-c_D9"))
	}
}

func TestOpenDBErrors(t *testing.T) {
	if _, err := OpenDB(context.Background(), "/dev/null/x/y.sqlite"); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadConfig(t *testing.T) {
	t.Setenv("FS_STORE_DB", "/tmp/x.sqlite")
	t.Setenv("FS_API_HTTP_PORT", "19001")
	t.Setenv("FS_STORE_MAX_BYTES", "100")
	t.Setenv("FS_HEALTH_DOWN_AFTER", "3s")
	c, err := LoadConfig()
	if err != nil || c.DBPath != "/tmp/x.sqlite" || c.HTTPAddr != ":19001" || c.MaxBytes != 100 || c.DownAfter != 3*time.Second {
		t.Fatalf("%+v %v", c, err)
	}
	t.Setenv("FS_STORE_MAX_BYTES", "x")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error")
	}
	t.Setenv("FS_STORE_MAX_BYTES", "")
	t.Setenv("FS_HEALTH_DOWN_AFTER", "x")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error")
	}
}
