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
		"net.ipv4.tcp_syncookies": "1",
		// iguais aos do host no finger-01, que este arquivo não pode reduzir (ADR 0038 item 7)
		"net.core.somaxconn":              "65535",
		"net.ipv4.tcp_max_syn_backlog":    "65535",
		"net.ipv4.tcp_timestamps":         "1",
		"net.ipv4.tcp_ecn":                "2",
		"net.ipv4.tcp_sack":               "1",
		"net.ipv4.tcp_window_scaling":     "1",
		"net.ipv4.tcp_congestion_control": "htcp",
		"net.core.default_qdisc":          "fq_codel",
		"net.ipv4.tcp_fastopen":           "3",
		// teto do host, acima dos ~7 MiB do quic-go (ADRs 0019 e 0038)
		"net.core.rmem_max": "134217728",
		"net.core.wmem_max": "134217728",
		// 8080/8443/9000/9001 fora da faixa efêmera
		"net.ipv4.ip_local_port_range": "32768 60999",
	}
	got := sysctlValues(t)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, quer %q", k, got[k], v)
		}
	}
	// só as chaves do espelho: os sysctls do host que ele não fixa ficam de fora (ADR 0038 item 7)
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("chave %s fora da lista da spec 016", k)
		}
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

// unitLimits é a tabela da ADR 0039 item 2 (store pela ADR 0045 item 3): MemoryMax, GOMEMLIMIT e CPUQuota por unit.
var unitLimits = map[string][3]string{
	"store":   {"6G", "1536MiB", "400%"},
	"nats":    {"1G", "896MiB", "200%"},
	"web":     {"768M", "512MiB", "400%"},
	"capture": {"512M", "384MiB", "200%"},
	"raw":     {"256M", "192MiB", "100%"},
	"dns":     {"256M", "192MiB", "100%"},
}

// envOf junta as linhas Environment= da unit, com espaço nas pontas para casar "chave=valor" inteiro.
func envOf(d map[string][]string) string { return " " + strings.Join(d["Environment"], " ") + " " }

// ADR 0039 (task 225): fatia, limites, swap, arquivos e THP de cada unit.
func TestUnitLimitsADR0039(t *testing.T) {
	for svc, lim := range unitLimits {
		d := unitDirectives(t, "finger-sniffer-"+svc+".service")
		one := func(k, want string) {
			if got := strings.Join(d[k], ","); got != want {
				t.Errorf("%s: %s = %q, quer %q", svc, k, got, want)
			}
		}
		one("Slice", "finger-sniffer.slice")
		one("MemoryMax", lim[0])
		one("CPUQuota", lim[2])
		one("MemorySwapMax", "0")
		one("LimitNOFILE", "65536")
		env := envOf(d)
		for _, kv := range []string{"GOMEMLIMIT=" + lim[1], "GODEBUG=disablethp=1"} {
			if !strings.Contains(env, " "+kv+" ") {
				t.Errorf("%s: Environment sem %s: %v", svc, kv, d["Environment"])
			}
		}
		if n := strings.Count(env, "GOMEMLIMIT="); n != 1 {
			t.Errorf("%s: GOMEMLIMIT aparece %d vezes", svc, n)
		}
	}
	// a unit de rede também fica na fatia (as 7 units)
	if got := strings.Join(unitDirectives(t, "finger-sniffer-net.service")["Slice"], ","); got != "finger-sniffer.slice" {
		t.Errorf("net: Slice = %q", got)
	}
}

// A fatia comum segura a soma: 10G e 800% (ADR 0039 item 1, ADR 0045 item 3), acima da soma dos MemoryMax.
func TestSliceUnit(t *testing.T) {
	d := unitDirectives(t, "finger-sniffer.slice")
	for k, want := range map[string]string{"MemoryMax": "10G", "CPUQuota": "800%", "MemorySwapMax": "0"} {
		if got := strings.Join(d[k], ","); got != want {
			t.Errorf("slice: %s = %q, quer %q", k, got, want)
		}
	}
	mib := map[string]int{"6G": 6144, "1G": 1024, "768M": 768, "512M": 512, "256M": 256}
	sum := 0
	for _, lim := range unitLimits {
		sum += mib[lim[0]]
	}
	if sum != 8960 {
		t.Errorf("soma dos MemoryMax = %d MiB, quer 8960 (8,8 GiB < 10G)", sum)
	}
}

// Capacidades: web sem CAP_NET_BIND_SERVICE (portas > 1024, ADR 0038 item 3); raw e dns com ela; capture com
// CAP_NET_RAW; store e nats sem nenhuma.
func TestUnitCapabilities(t *testing.T) {
	want := map[string]string{
		"web": "", "raw": "CAP_NET_BIND_SERVICE", "dns": "CAP_NET_BIND_SERVICE", "capture": "CAP_NET_RAW",
		"store": "", "nats": "",
	}
	for svc, caps := range want {
		d := unitDirectives(t, "finger-sniffer-"+svc+".service")
		for _, k := range []string{"CapabilityBoundingSet", "AmbientCapabilities"} {
			if got := strings.Join(d[k], ","); got != caps {
				t.Errorf("%s: %s = %q, quer %q", svc, k, got, caps)
			}
		}
	}
}

func TestWebUnitQUIC(t *testing.T) {
	d := unitDirectives(t, "finger-sniffer-web.service")
	env := envOf(d)
	for _, kv := range []string{"QUIC_GO_DISABLE_GSO=true", "QUIC_GO_DISABLE_ECN=true"} {
		if !strings.Contains(env, " "+kv+" ") {
			t.Errorf("Environment sem %s: %v", kv, d["Environment"])
		}
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

// nats.conf: max_memory_store de 256MB, folga sobre o stream de 128 MiB (ADR 0039 item 3).
func TestNATSConfMemoryStore(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "eventbus", "nats", "nats.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\n  max_memory_store: 256MB\n") {
		t.Errorf("nats.conf sem max_memory_store: 256MB\n%s", b)
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
		// certificados A e B (ADR 0038 item 5); ACME ligado só no servidor (task 231); o B só com
		// finger-01.badblock.net.br, o único nome no passthrough do traefik (decisão do humano, task 232)
		"FS_CERT_NAMES_DNS01":  "finger-west-01.badblock.net.br,*.finger-west-01.badblock.net.br",
		"FS_CERT_NAMES_HTTP01": "finger-01.badblock.net.br",
		"FS_ACME_ENABLE":       "0",
		// modo degradado (ADR 0039 item 5) e teto do banco (3 GiB, ADR 0045 item 3)
		"FS_MAX_CONNS":           "1000",
		"FS_MAX_NEW_CONNS_PER_S": "250",
		"FS_STORE_MAX_BYTES":     "3221225472",
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
