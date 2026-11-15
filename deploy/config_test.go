package deploy

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// O comentário do stream FS_EVENTS no nats.conf acompanha event.StreamSubjects (ADR 0017, task 183): lista
// todos os subjects do stream e não volta a descrevê-lo como fs.v1.>.
func TestNATSConfStreamCommentMatchesStreamSubjects(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "eventbus", "nats", "nats.conf"))
	if err != nil {
		t.Fatal(err)
	}
	conf := string(b)
	for _, s := range event.StreamSubjects {
		if !strings.Contains(conf, s) {
			t.Errorf("nats.conf não cita o subject %q do stream", s)
		}
	}
	for _, line := range strings.Split(conf, "\n") {
		if strings.Contains(line, "fs.v1.>") && !strings.Contains(line, "Nunca fs.v1.>") {
			t.Errorf("nats.conf descreve o stream como fs.v1.>: %q", line)
		}
	}
}

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
	for _, kv := range []string{"QUIC_GO_DISABLE_GSO=true", "QUIC_GO_DISABLE_ECN=true", "GOMEMLIMIT=64MiB"} {
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

// .env.example com os valores do finger-01 (ADRs 0038 e 0039, task 224).
func TestEnvExampleFinger01(t *testing.T) {
	vals, count := envMap(t, "../.env.example")
	want := map[string]string{
		"FS_LIVE_BUFFER":      "1024",
		"FS_LIVE_MAX_CLIENTS": "64",
		// endereços, NIC e zona do finger-01 (ADR 0038 itens 1 e 2)
		"FS_LISTEN_IPV4":           "170.247.40.86",
		"FS_LISTEN_IPV6":           "2804:231c:e500:cafe::86",
		"FS_CAPTURE_IFACE":         "ens192",
		"FS_CAPTURE_EXCLUDE_PORTS": "48022,48161,9000,9001",
		"FS_DNS_ZONE":              "finger-west-01.badblock.net.br",
		// web fora de 80/443, que são do traefik (ADR 0038 item 3)
		"FS_WEB_TCP_PORTS": "8080,8443",
		"FS_WEB_UDP_PORTS": "8443",
		// certificados A e B (ADR 0038 item 5); ACME ligado só no servidor (task 231)
		"FS_CERT_NAMES_DNS01":  "finger-west-01.badblock.net.br,*.finger-west-01.badblock.net.br",
		"FS_CERT_NAMES_HTTP01": "finger-01.badblock.net.br,finger-01.tmsoft.com.br",
		"FS_ACME_ENABLE":       "0",
		// modo degradado e teto do banco (ADR 0039 item 5)
		"FS_MAX_CONNS":           "1000",
		"FS_MAX_NEW_CONNS_PER_S": "250",
		"FS_STORE_MAX_BYTES":     "8589934592",
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
	// o BPF do capture exclui só gerência e API: 80/443 do traefik e as portas do web seguem capturadas
	for _, p := range strings.Split(vals["FS_CAPTURE_EXCLUDE_PORTS"], ",") {
		switch p {
		case "80", "443", "8080", "8443":
			t.Errorf("FS_CAPTURE_EXCLUDE_PORTS exclui %s", p)
		}
	}
}
