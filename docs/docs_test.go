// Package docs confere a documentação derivada (este arquivo não é documentação: só testa os links).
package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// linkRe acha links Markdown [texto](alvo); imagens e links externos são filtrados depois.
var linkRe = regexp.MustCompile(`\]\(([^)\s]+)\)`)

// headingRe acha títulos ATX para montar as âncoras no estilo do GitHub.
var headingRe = regexp.MustCompile(`(?m)^#{1,6} (.+)$`)

// slug imita o GitHub: minúsculas, sem pontuação (exceto - e _), espaços viram "-".
func slug(h string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(h)) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_':
			b.WriteRune(r)
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r > 127:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// stripFences remove os blocos de código (um "# comentário" dentro deles não é título).
func stripFences(s string) string {
	return regexp.MustCompile("(?s)```.*?```").ReplaceAllString(s, "")
}

// stripCode remove também os trechos de código, onde "](" não é link.
func stripCode(s string) string {
	return regexp.MustCompile("`[^`\n]*`").ReplaceAllString(stripFences(s), "")
}

func anchors(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	out := map[string]bool{}
	for _, m := range headingRe.FindAllStringSubmatch(stripFences(string(data)), -1) {
		out[slug(m[1])] = true
	}
	return out
}

// TestRelativeLinks: todo link relativo dos .md de docs/ aponta para um arquivo existente e, com âncora, para um
// título existente.
func TestRelativeLinks(t *testing.T) {
	files, err := filepath.Glob("*.md")
	if err != nil || len(files) == 0 {
		t.Fatalf("nenhum .md em docs/: %v", err)
	}
	sub, _ := filepath.Glob("*/*.md")
	files = append(files, sub...)
	// O README de raiz também é do papel docs (spec 002) e aponta para docs/, specs e contratos.
	files = append(files, filepath.Join("..", "README.md"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range linkRe.FindAllStringSubmatch(stripCode(string(data)), -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			file, anchor, _ := strings.Cut(target, "#")
			dest := f
			if file != "" {
				dest = filepath.Join(filepath.Dir(f), file)
				if _, err := os.Stat(dest); err != nil {
					t.Errorf("%s: link quebrado %q", f, target)
					continue
				}
			}
			if anchor != "" && strings.HasSuffix(dest, ".md") && !anchors(t, dest)[anchor] {
				t.Errorf("%s: âncora inexistente %q", f, target)
			}
		}
	}
}

// TestIndexListsGuides: o README lista todos os guias da pasta.
func TestIndexListsGuides(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("*.md")
	for _, f := range files {
		if f != "README.md" && !strings.Contains(string(readme), "]("+f+")") {
			t.Errorf("README.md não lista %s", f)
		}
	}
}

// TestIndexListsDevDocs: o índice de dev/ lista todos os documentos da pasta.
func TestIndexListsDevDocs(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("dev", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join("dev", "*.md"))
	for _, f := range files {
		name := filepath.Base(f)
		if name != "README.md" && !strings.Contains(string(readme), "]("+name+")") {
			t.Errorf("dev/README.md não lista %s", name)
		}
	}
}

// TestRootReadme: o README de raiz traz o aviso de tráfego público e aponta para docs, specs, contratos e licença.
func TestRootReadme(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		"](docs/README.md)", "](docs/probes.md)", "](specs/INDEX.md)", "](cmd/finger-sniffer-store/openapi.yaml)",
		"](eventbus/nats/asyncapi.yaml)", "](LICENSE)", "](NOTICE)", "FoxIO License 1.1",
		"público", "10 minutos", "make verify-quick", "make deploy", "make tools",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("README.md sem %q", want)
		}
	}
}

// TestProbesMatrix: probes.md tem uma receita por caso da matriz da spec 017 (1–13), cada uma com o que procurar,
// os campos estáveis e as diferenças esperadas por proxy (ADR 0022), e documenta o Date e o date=0 (ADR 0021).
func TestProbesMatrix(t *testing.T) {
	data, err := os.ReadFile("probes.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	heads := regexp.MustCompile(`(?m)^### Caso (\d+):`).FindAllStringSubmatchIndex(s, -1)
	if len(heads) != 13 {
		t.Fatalf("probes.md tem %d casos, quero 13", len(heads))
	}
	for i, h := range heads {
		num := s[h[2]:h[3]]
		if want := strconv.Itoa(i + 1); num != want {
			t.Errorf("caso fora de ordem: %s, quero %s", num, want)
		}
		end := len(s)
		if i+1 < len(heads) {
			end = heads[i+1][0]
		}
		body := s[h[0]:end]
		for _, want := range []string{"```console", "**Procurar**", "**Estáveis**", "**Diferenças esperadas**"} {
			if !strings.Contains(body, want) {
				t.Errorf("caso %s sem %q", num, want)
			}
		}
	}
	for _, want := range []string{
		"`date=0`", "### `Date`", "proxy HTTP", "túnel CONNECT", "HTTPS-proxy",
		"`PROXY:PORTA`", "absolute-form", "`Proxy-Connection`",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("probes.md sem %q", want)
		}
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"Controles de resposta: `/p/<id>/r?...`": "controles-de-resposta-pidr",
		"HTTP/1, h2 e h3":                        "http1-h2-e-h3",
		"Probe: `GET /api/v1/probes/{id}`":       "probe-get-apiv1probesid",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, quero %q", in, got, want)
		}
	}
}

// TestHTTP3Fields: http3.md descreve os campos do HTTP3Info que os clientes e a página usam, inclusive os do contrato
// 0.3.2.
func TestHTTP3Fields(t *testing.T) {
	data, err := os.ReadFile("http3.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"`h3_settings`", "`h3_control_stream_seen`", "`transport_params`", "`date`"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("http3.md sem %s", want)
		}
	}
}

// TestAuditF5Docs: os guias refletem os contratos (0.3.3, hoje 0.4.x) e as decisões da auditoria F5 (ADR 0023, e a 0026 no lugar da 0024): erros
// da API, métricas do capture publicadas desde a partida e as diferenças esperadas que a auditoria explicou.
func TestAuditF5Docs(t *testing.T) {
	want := map[string][]string{
		"api.md": {
			"versão 0.4.x", "## Erros", "de caminho", "rota inexistente", "`OPTIONS`", "204", "500",
			"invalid conn_id", "`started`", "`ended`", "/api/v1/dns",
		},
		"metrics.md": {
			"`fs_capture_packets_in_total`", "`fs_capture_packets_out_total`", "`fs_capture_truncated_total`",
			"`fs_capture_offload_suspect_total`", "`fs_capture_filtered_userspace_total`",
			"`fs_dropped_events_total`", "`fs_store_late_packets_total`", "desde a partida",
		},
		"probes.md": {
			"GOAWAY PROTOCOL_ERROR", "`streams[]`", "`Upgrade: h2c`", "`PS`", "`websocket.close.by: client`",
			"`close.by: server`", "`conn=close`", "`close=after`", "`ts_clock_group`", "**por par",
			"`times` vem `null`", "ADR 0026", "confirmou o recebimento", "IPs públicos",
		},
		"http3.md": {"ADR", "0026-fechamento-rapido-e-ajustes-da-release.md", "p95 ≤ 500 ms", "p95 252 ms", "`wait`"},
		"dev/auditoria-f5.md": {
			"## Resolução das tarefas 086 e 087", "ADR", "0.3.3", "task 089", "task 090",
			"**substituída** pela", "0026-fechamento-rapido-e-ajustes-da-release.md", "task 072",
		},
	}
	for file, items := range want {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range items {
			if !strings.Contains(string(data), w) {
				t.Errorf("%s sem %q", file, w)
			}
		}
	}
}

// TestListenAndRecordReadyDocs: os guias dizem onde a API escuta (task 082, ADR 0023) e explicam o tempo até o
// registro com o rótulo reason e FS_TCP_CLOSE_GRACE (tasks 077 e 090), sem a folga antiga de 2 s do QUIC nem a
// meta provisória de 3 s da ADR 0024 (substituída pela 0026, task 109).
func TestListenAndRecordReadyDocs(t *testing.T) {
	want := map[string][]string{
		"api.md": {
			"`127.0.0.1`", "`FS_LISTEN_IPV4`", "`FS_LISTEN_IPV6`", "**nunca** em todos os endereços",
			"`FS_TCP_CLOSE_GRACE`", "`conntrack loaded`", "differs from store",
		},
		"../README.md": {"`127.0.0.1`", "`FS_LISTEN_IPV4`/`FS_LISTEN_IPV6`"},
		"metrics.md": {
			"## Tempo até o registro", "`fs_store_record_ready_seconds{reason}`", "`close`", "`quic_close`",
			"`idle`", "`FS_TCP_CLOSE_GRACE`", "**100 ms**", "de 0 a 500 ms", "task 077", "task 090",
			"lida em `close` e `quic_close`", "fora da meta",
		},
		"http3.md": {"task 090", "100 ms", "#tempo-até-o-registro"},
		"probes.md": {
			"`FS_TCP_CLOSE_GRACE` (100 ms)", "task 090", "p95 ≤ 500 ms (ADR 0026)",
			"`packet.stray` decidido por ociosidade", "instante em que o store decidiu", "ADR 0026 §5",
		},
	}
	// frases da folga antiga do QUIC que não podem voltar
	banned := map[string][]string{
		"http3.md":   {"~2 s depois", "Esse atraso de ~2 s", "ADR 0024", "0024-registro-quic", "p95 ≤ 3 s"},
		"probes.md":  {"cerca de 2 s depois", "uns 2 s depois", "ADR 0024", "de 3 s"},
		"metrics.md": {"ADR [0024]", "0024-registro-quic", "p95 ≤ 3 s"},
	}
	for file, items := range want {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range items {
			if !strings.Contains(string(data), w) {
				t.Errorf("%s sem %q", file, w)
			}
		}
		for _, b := range banned[file] {
			if strings.Contains(string(data), b) {
				t.Errorf("%s ainda diz %q", file, b)
			}
		}
	}
}

// TestConnectionCloseDocs: o guia não diz que o espelho fecha por causa do `Connection: close` da requisição
// (spec 005 RF-08, task 119); explica quem fecha, o pendurado até a ociosidade e como pedir o fechamento.
func TestConnectionCloseDocs(t *testing.T) {
	data, err := os.ReadFile("probes.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, w := range []string{
		"**`Connection: close` na requisição não faz o espelho fechar**", "espera o\nservidor fechar",
		"`idle_before_close_ms` ≈ 120000", "`/p/<id>/r?close=after`", "`idle=<s>`",
		"o `Connection: close` **não** faz o espelho fechar",
	} {
		if !strings.Contains(s, w) {
			t.Errorf("probes.md sem %q", w)
		}
	}
	for _, b := range []string{
		"o espelho fecha porque o cliente pediu `Connection: close`",
		"`frame=close`, `Connection: close` na requisição",
	} {
		if strings.Contains(s, b) {
			t.Errorf("probes.md ainda diz %q", b)
		}
	}
}

// TestContracts04Docs: api.md e probes.md descrevem os campos e parâmetros dos contratos 0.4.x (ADR 0029,
// task 124): settle/min_conns/wait_met e seus 400, os 4 instantes, ip.packets, TFO, alertas e keepalive.
func TestContracts04Docs(t *testing.T) {
	want := map[string][]string{
		"api.md": {
			"versão 0.4.x", "`settle`", "`min_conns`", "`wait_met`", "inclusive `wait=0s`",
			"settle and min_conns require wait", "`settle` fora de `0s`–`10s`", "`min_conns` fora de 1–1000",
			"`request_started_at`", "`request_ended_at`", "`response_started_at`", "`response_ended_at`",
			"Cada instante é **independente**", "RST_STREAM", "`ip.packets`", "`first_data`",
		},
		"probes.md": {
			"?wait=30s&settle=1s", "`wait_met: true`", "`&min_conns=N`", "--tcp-fastopen", "`tcp.syn.payload_b64`",
			"#### TCP Fast Open", "`0x15`", "**sem duplicar**", "`unknown_ca`", "**não mandam keepalive TCP**",
			"`ip.packets.{syn,ack,first_data}`", "os instantes `request_started_at`",
		},
	}
	for f, ws := range want {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		for _, w := range ws {
			if !strings.Contains(s, w) {
				t.Errorf("%s sem %q", f, w)
			}
		}
		if strings.Contains(s, "?wait=10s") && f == "probes.md" {
			t.Errorf("probes.md ainda coleta com ?wait=10s")
		}
	}
}

// TestMSSWindowDocs: probes.md ensina a ler o MSS, o MTU implícito e o teto pela janela só com campos do contrato
// (task 195): a conta sem timestamps, as referências 1460/1440, o aviso de clamping, a janela do SYN sem escala e
// a série da janela; sem citar consumidor específico (ADR 0028).
func TestMSSWindowDocs(t *testing.T) {
	data, err := os.ReadFile("probes.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, w := range []string{
		"#### MSS, MTU implícito e teto de throughput pela janela", `["mss", N]`, "`N + 40`", "`N + 60`",
		"Não some os 12 bytes", "1460 (IPv4) e 1440 (IPv6)", "PPPoE", "GRE ou 6in4", "IPsec", "MSS clamping",
		"`janela_max = window × 2^S`", "nunca é escalada", "`teto_Mbps = janela × 8 / rtt_handshake_ms / 1000`",
		"`tcp.window_series`", "o SYN visto é o do proxy", "túnel L3",
	} {
		if !strings.Contains(s, w) {
			t.Errorf("probes.md sem %q", w)
		}
	}
	if strings.Contains(strings.ToLower(s), "tcp-analyzer") {
		t.Errorf("probes.md cita consumidor específico (ADR 0028)")
	}
}
