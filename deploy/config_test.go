package deploy

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sysctlValues lê "chave = valor" do arquivo de sysctl do projeto.
func sysctlValues(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open("sysctl/90-finger-sniffer.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	vals := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("linha inválida: %q", line)
		}
		vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return vals
}

func TestSysctlMatchesSpec016(t *testing.T) {
	want := map[string]string{
		"net.ipv4.tcp_syncookies":         "1",
		"net.core.somaxconn":              "4096",
		"net.ipv4.tcp_max_syn_backlog":    "4096",
		"net.ipv4.tcp_timestamps":         "1",
		"net.ipv4.tcp_ecn":                "2",
		"net.ipv4.tcp_sack":               "1",
		"net.ipv4.tcp_window_scaling":     "1",
		"net.ipv4.tcp_congestion_control": "htcp",
		"net.core.default_qdisc":          "fq_codel",
		"net.ipv4.tcp_fastopen":           "3",
		// buffer UDP do quic-go (ADR 0019)
		"net.core.rmem_max": "7340032",
		"net.core.wmem_max": "7340032",
	}
	got := sysctlValues(t)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, quer %q", k, got[k], v)
		}
	}
	if got["net.ipv4.ip_local_port_range"] == "" {
		t.Error("ip_local_port_range ausente")
	}
}

// unitDirectives devolve as diretivas da unit (a mesma chave pode repetir).
func unitDirectives(t *testing.T, name string) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("systemd", name))
	if err != nil {
		t.Fatal(err)
	}
	d := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			d[k] = append(d[k], v)
		}
	}
	return d
}

func TestWebUnitQUIC(t *testing.T) {
	d := unitDirectives(t, "finger-sniffer-web.service")
	env := " " + strings.Join(d["Environment"], " ") + " "
	for _, kv := range []string{"QUIC_GO_DISABLE_GSO=true", "QUIC_GO_DISABLE_ECN=true", "GOMEMLIMIT=80MiB"} {
		if !strings.Contains(env, " "+kv+" ") {
			t.Errorf("Environment sem %s: %v", kv, d["Environment"])
		}
	}
	if got := strings.Join(d["MemoryMax"], ","); got != "96M" {
		t.Errorf("MemoryMax = %q, quer 96M", got)
	}
	// bind UDP 443: capacidade de porta baixa e famílias IP liberadas
	if got := strings.Join(d["AmbientCapabilities"], ","); got != "CAP_NET_BIND_SERVICE" {
		t.Errorf("AmbientCapabilities = %q", got)
	}
	fams := strings.Fields(strings.Join(d["RestrictAddressFamilies"], " "))
	for _, f := range []string{"AF_INET", "AF_INET6"} {
		found := false
		for _, g := range fams {
			found = found || g == f
		}
		if !found {
			t.Errorf("RestrictAddressFamilies sem %s: %v", f, fams)
		}
	}
	for _, k := range []string{"IPAddressDeny", "SystemCallFilter"} {
		if len(d[k]) > 0 {
			t.Errorf("%s pode bloquear o QUIC; revisar: %v", k, d[k])
		}
	}
}

func TestEnvExampleLiveAndUDP(t *testing.T) {
	vals, count := envMap(t, "../.env.example")
	want := map[string]string{
		"FS_LIVE_BUFFER":      "1024",
		"FS_LIVE_MAX_CLIENTS": "64",
		"FS_WEB_UDP_PORTS":    "443",
	}
	for k, v := range want {
		if vals[k] != v {
			t.Errorf("%s = %q, quer %q", k, vals[k], v)
		}
	}
	for k, n := range count {
		if n > 1 {
			t.Errorf("%s repetida %d vezes", k, n)
		}
	}
	// o BPF do capture exclui só gerência e API: 80/443 (TCP e UDP) seguem capturados
	for _, p := range strings.Split(vals["FS_CAPTURE_EXCLUDE_PORTS"], ",") {
		if p == "443" || p == "80" {
			t.Errorf("FS_CAPTURE_EXCLUDE_PORTS exclui %s", p)
		}
	}
}
