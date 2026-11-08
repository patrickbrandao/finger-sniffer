//go:build e2e

// Package e2e roda os testes ponta a ponta contra a vps602 com a main implantada (spec 017, PLAN.md F2).
// Uso: make verify-full ARGS="--e2e"  ou  go test -count=1 -tags e2e ./test/e2e/
// O teste de retenção (10 min) só roda com FS_E2E_LONG=1.
package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

var (
	vpsSSH  = env("VPS_SSH", "root@vps602.tmsoft.com.br")
	vpsPort = env("VPS_PORT", "48022")
	vps4    = env("FS_E2E_VPS4", "172.233.24.85")
	api     = env("FS_E2E_API", "http://vps602.tmsoft.com.br:9001/api/v1")
)

const (
	listenPort = 7701 // capturada e livre na vps602 (web/raw ainda são stubs)
	closedPort = 7799 // capturada e sem listener: o kernel responde RST
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// remote roda um comando na vps602.
func remote(t *testing.T, cmd string) string {
	t.Helper()
	out, err := exec.Command("ssh", "-4", "-p", vpsPort, "-o", "BatchMode=yes", vpsSSH, cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh %q: %v\n%s", cmd, err, out)
	}
	return strings.TrimSpace(string(out))
}

// macIPv4 é o IPv4 público desta máquina como a vps602 vê (o ssh por IPv4 mostra a origem).
func macIPv4(t *testing.T) string {
	t.Helper()
	ip := remote(t, `echo ${SSH_CLIENT%% *}`)
	if net.ParseIP(ip).To4() == nil {
		t.Fatalf("IPv4 de origem inválido: %q", ip)
	}
	return ip
}

// startListener sobe um http.server temporário na vps602 e o remove no fim do teste.
func startListener(t *testing.T) {
	t.Helper()
	remote(t, fmt.Sprintf("mkdir -p /tmp/fs-e2e && echo e2e > /tmp/fs-e2e/index.html && cd /tmp/fs-e2e && "+
		"setsid -f bash -c 'exec -a fs-e2e-srv python3 -m http.server %d --bind %s' >/dev/null 2>&1 </dev/null", listenPort, vps4))
	t.Cleanup(func() {
		remote(t, "pkill -f '[f]s-e2e-srv'; rm -rf /tmp/fs-e2e; true")
		if n := remote(t, fmt.Sprintf("ss -ltnH 'sport = :%d' | wc -l", listenPort)); n != "0" {
			t.Errorf("listener temporário ainda ativo na %d", listenPort)
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", vps4, listenPort), time.Second); err == nil {
			_ = c.Close()
			time.Sleep(2 * time.Second) // deixa essa conexão de teste fechar antes de marcar o início
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("listener temporário não subiu")
}

// get faz GET na API, guarda o corpo para a validação de contrato e decodifica em out.
func get(t *testing.T, path string, out any) []byte {
	t.Helper()
	resp, err := http.Get(api + path) //nolint:gosec // URL do teste
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
	}
	return b
}

type endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type connection struct {
	ConnID string   `json:"conn_id"`
	Src    endpoint `json:"src"`
	Dst    endpoint `json:"dst"`
	Ended  *string  `json:"ended"`
	Close  struct {
		By  string `json:"by"`
		How string `json:"how"`
	} `json:"close"`
	Totals struct {
		In  struct{ Segments int } `json:"in"`
		Out struct{ Segments int } `json:"out"`
	} `json:"totals"`
	IP *struct {
		TTL        int `json:"ttl"`
		TTLInitial int `json:"ttl_initial"`
	} `json:"ip"`
	TCP *struct {
		Syn *struct {
			Options [][]any `json:"options"`
			ISN     int64   `json:"isn"`
		} `json:"syn"`
		JA4T           *string  `json:"ja4t"`
		P0F            *string  `json:"p0f"`
		RTTHandshakeMs *float64 `json:"rtt_handshake_ms"`
	} `json:"tcp"`
}

type packet struct {
	Src      *endpoint `json:"src"`
	Dst      *endpoint `json:"dst"`
	TCPFlags *string   `json:"tcp_flags"`
}

// contract guarda uma resposta por exemplo do openapi.yaml (mesmos nomes de arquivo de testdata/).
var contract = map[string][]byte{}

func since(t0 time.Time) string { return url.QueryEscape(t0.UTC().Format(time.RFC3339Nano)) }

// waitConns espera as conexões terminadas de src para a porta, no mínimo n.
func waitConns(t *testing.T, src string, port int, t0 time.Time, n int) []connection {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var ended []connection
	var raw []byte
	for time.Now().Before(deadline) {
		var list []connection
		raw = get(t, fmt.Sprintf("/connections?src_ip=%s&dst_port=%d&since=%s", src, port, since(t0)), &list)
		ended = ended[:0]
		for _, c := range list {
			if c.Ended != nil {
				ended = append(ended, c)
			}
		}
		if len(ended) >= n {
			contract["connections-list-example.json"] = raw
			return ended
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("só %d de %d conexões terminadas de %s para %d", len(ended), n, src, port)
	return nil
}

var ja4tRe = regexp.MustCompile(`^\d+_(\d+(-\d+)*|00)_\d{2,}_\d+$`)

// TestF2ExitCriterion: nc e curl a uma porta capturada aparecem em /connections com SYN, JA4T, p0f, RTT e
// pcap válido no tshark; SYN para porta fechada vira pacote avulso; as portas de gerência e da API não
// aparecem; e todas as respostas validam contra o openapi.yaml (critério de saída da F2).
func TestF2ExitCriterion(t *testing.T) {
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		t.Fatal("tshark não encontrado no PATH (necessário para abrir o pcap)")
	}
	mac := macIPv4(t)
	startListener(t)
	t0 := time.Now()

	// curl e nc a partir desta máquina
	target := fmt.Sprintf("%s:%d", vps4, listenPort)
	if out, err := exec.Command("curl", "-4", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://"+target+"/").Output(); err != nil || string(out) != "200" {
		t.Fatalf("curl: %v %s", err, out)
	}
	nc := exec.Command("nc", "-4", "-w", "3", vps4, fmt.Sprint(listenPort))
	nc.Stdin = strings.NewReader("hello e2e\r\n\r\n")
	if out, err := nc.CombinedOutput(); err != nil && !strings.Contains(string(out), "400") {
		t.Fatalf("nc: %v %s", err, out)
	}
	// SYN para porta fechada (capturada): o kernel recusa com RST
	if c, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", vps4, closedPort), 3*time.Second); err == nil {
		_ = c.Close()
		t.Fatalf("porta %d deveria estar fechada", closedPort)
	}
	// tráfego na API (9001) e no ssh (48022) durante a janela do teste
	get(t, "/health", nil)
	remote(t, "true")

	conns := waitConns(t, mac, listenPort, t0, 2)
	dir := t.TempDir()
	for _, c := range conns {
		var r connection
		raw := get(t, "/connections/"+c.ConnID, &r)
		contract["connection-example.json"] = raw
		t.Logf("%s %s:%d → %d: ja4t=%s p0f=%s rtt=%.3f ms close=%s/%s", r.ConnID, r.Src.IP, r.Src.Port, r.Dst.Port,
			deref(r.TCP.JA4T), deref(r.TCP.P0F), derefF(r.TCP.RTTHandshakeMs), r.Close.By, r.Close.How)
		switch {
		case r.TCP == nil || r.TCP.Syn == nil || len(r.TCP.Syn.Options) == 0:
			t.Errorf("%s: SYN sem opções", r.ConnID)
		case r.TCP.JA4T == nil || !ja4tRe.MatchString(*r.TCP.JA4T):
			t.Errorf("%s: JA4T inválido: %v", r.ConnID, deref(r.TCP.JA4T))
		case r.TCP.P0F == nil || !strings.HasPrefix(*r.TCP.P0F, "4:"):
			t.Errorf("%s: p0f inválido: %v", r.ConnID, deref(r.TCP.P0F))
		case r.TCP.RTTHandshakeMs == nil || *r.TCP.RTTHandshakeMs <= 0:
			t.Errorf("%s: sem RTT do handshake", r.ConnID)
		case r.Close.How != "fin" && r.Close.How != "rst":
			t.Errorf("%s: close = %+v", r.ConnID, r.Close)
		case r.IP == nil || r.IP.TTL == 0 || r.IP.TTLInitial < r.IP.TTL:
			t.Errorf("%s: ip = %+v", r.ConnID, r.IP)
		}
		// pcap válido no tshark, com todos os pacotes da conexão
		resp, err := http.Get(api + "/connections/" + c.ConnID + "/pcap") //nolint:gosec // URL do teste
		if err != nil {
			t.Fatal(err)
		}
		pcap, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		f := filepath.Join(dir, c.ConnID+".pcap")
		if err := os.WriteFile(f, pcap, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(tshark, "-r", f, "-T", "fields", "-e", "frame.number").Output() //nolint:gosec // caminho do teste
		if err != nil {
			t.Errorf("%s: tshark não abriu o pcap: %v", c.ConnID, err)
			continue
		}
		frames := len(strings.Fields(string(out)))
		if want := r.Totals.In.Segments + r.Totals.Out.Segments; frames != want {
			t.Errorf("%s: pcap com %d frames, registro com %d segmentos", c.ConnID, frames, want)
		}
	}

	// SYN para a porta fechada aparece em /packets
	var pkts []packet
	contract["packets-example.json"] = get(t, fmt.Sprintf("/packets?src_ip=%s&since=%s&limit=1000", mac, since(t0)), &pkts)
	found := false
	for _, p := range pkts {
		if p.Dst != nil && p.Dst.Port == closedPort && p.TCPFlags != nil && strings.Contains(*p.TCPFlags, "S") {
			found = true
		}
	}
	if !found {
		t.Errorf("SYN para a porta fechada %d não está em /packets", closedPort)
	}

	// portas excluídas (48022 ssh, 9001 API) não aparecem em nenhuma consulta
	for _, port := range []int{48022, 9001, 9000, 48161} {
		var list []connection
		get(t, fmt.Sprintf("/connections?dst_port=%d&since=%s", port, since(t0)), &list)
		if len(list) != 0 {
			t.Errorf("porta %d apareceu em /connections: %d conexões", port, len(list))
		}
	}
	var all []packet
	get(t, fmt.Sprintf("/packets?since=%s&limit=1000", since(t0)), &all)
	for _, p := range all {
		for _, e := range []*endpoint{p.Src, p.Dst} {
			if e != nil && (e.Port == 48022 || e.Port == 9001 || e.Port == 9000 || e.Port == 48161) {
				t.Errorf("pacote de porta excluída em /packets: %+v → %+v", p.Src, p.Dst)
			}
		}
	}

	contract["health-example.json"] = get(t, "/health", nil)
	contract["dns-list-example.json"] = get(t, fmt.Sprintf("/dns?since=%s", since(t0)), nil)
	validateContract(t)
}

// validateContract grava as respostas reais no lugar dos exemplos e roda o mesmo Redocly do verify: a
// regra no-invalid-media-type-examples (erro) valida cada resposta contra o schema da rota.
func validateContract(t *testing.T) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"cmd/finger-sniffer-store/openapi.yaml", "redocly.yaml"} {
		b, err := os.ReadFile(filepath.Join(root, f)) //nolint:gosec // arquivos do repositório
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// exemplos sem resposta real neste teste (probe) ficam os do repositório
	golden, _ := filepath.Glob(filepath.Join(root, "cmd/finger-sniffer-store/testdata/*.json"))
	for _, g := range golden {
		b, _ := os.ReadFile(g) //nolint:gosec // arquivos do repositório
		name := filepath.Base(g)
		if live, ok := contract[name]; ok {
			// os exemplos são Example Objects: a resposta real vai em "value"
			b, _ = json.Marshal(map[string]any{"summary": "resposta real do e2e", "value": json.RawMessage(live)})
		}
		if err := os.WriteFile(filepath.Join(dir, "testdata", name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("npx", "-y", "@redocly/cli@2.76.0", "lint", "openapi.yaml")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "REDOCLY_TELEMETRY=off", "REDOCLY_SUPPRESS_UPDATE_NOTICE=true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("respostas reais não validam contra o openapi.yaml:\n%s", out)
	}
	t.Logf("contrato: %d respostas reais validadas (%s)", len(contract), strings.Join(keys(contract), ", "))
}

// TestRetention: uma conexão some da API depois de FS_RETENTION (10 min) e continua lá antes disso.
func TestRetention(t *testing.T) {
	if os.Getenv("FS_E2E_LONG") != "1" {
		t.Skip("teste longo (~12 min): defina FS_E2E_LONG=1")
	}
	var h struct {
		Host struct {
			Store struct {
				Retention string `json:"retention"`
			} `json:"store"`
		} `json:"host"`
	}
	get(t, "/health", &h)
	ret, err := time.ParseDuration(h.Host.Store.Retention)
	if err != nil {
		t.Fatalf("retenção do health: %q", h.Host.Store.Retention)
	}
	mac := macIPv4(t)
	startListener(t)
	t0 := time.Now()
	if out, err := exec.Command("curl", "-4", "-s", "-o", "/dev/null", fmt.Sprintf("http://%s:%d/", vps4, listenPort)).CombinedOutput(); err != nil {
		t.Fatalf("curl: %v %s", err, out)
	}
	c := waitConns(t, mac, listenPort, t0, 1)[0]
	ended, err := time.Parse(time.RFC3339Nano, *c.Ended)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("conexão %s terminou em %s; retenção %s", c.ConnID, ended.Format(time.RFC3339), ret)
	for {
		resp, err := http.Get(api + "/connections/" + c.ConnID) //nolint:gosec // URL do teste
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		age := time.Since(ended)
		switch {
		case resp.StatusCode == http.StatusNotFound && age < ret-15*time.Second:
			t.Fatalf("conexão sumiu cedo: %s depois do fim (retenção %s)", age.Round(time.Second), ret)
		case resp.StatusCode == http.StatusNotFound:
			t.Logf("conexão sumiu %s depois do fim (retenção %s)", age.Round(time.Second), ret)
			return
		case age > ret+2*time.Minute:
			t.Fatalf("conexão ainda na API %s depois do fim (retenção %s)", age.Round(time.Second), ret)
		}
		time.Sleep(15 * time.Second)
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func derefF(f *float64) float64 {
	if f == nil {
		return -1
	}
	return *f
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
